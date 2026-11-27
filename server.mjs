import { spawn, execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import {
  buildClaudeEnv,
  buildStreamInput,
  extractJsonObject,
  findResult,
  mediaTypeForExt,
  isAuthorized,
  MAX_BYTES,
  sniffFileType,
} from './lib.mjs';

const run = promisify(execFile);

const PORT = Number(process.env.PORT ?? 3000);
const SECRET = process.env.AI_SERVICE_SECRET;
const CLAUDE_TIMEOUT_MS = Number(process.env.CLAUDE_TIMEOUT_SECONDS ?? 150) * 1000;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT ?? 3);
const MAX_PAGES = 8;

if (!SECRET || SECRET.length < 16) {
  console.error('AI_SERVICE_SECRET (min 16 chars) is required');
  process.exit(1);
}
if (!process.env.CLAUDE_CODE_OAUTH_TOKEN && !process.env.ANTHROPIC_API_KEY) {
  console.error('ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (from `claude setup-token`) is required');
  process.exit(1);
}

let active = 0;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BYTES) {
        reject(Object.assign(new Error('File too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** PDFs become one PNG per page so scanned documents (no text layer) can be read as images. */
async function prepareImages(dir, buffer, type) {
  if (type.kind === 'image') {
    const path = join(dir, `page-1.${type.ext}`);
    await writeFile(path, buffer);
    return [path];
  }

  const pdfPath = join(dir, 'input.pdf');
  await writeFile(pdfPath, buffer);
  await run('pdftoppm', ['-r', '120', '-l', String(MAX_PAGES), '-png', pdfPath, join(dir, 'page')], { timeout: 60_000 });
  const pages = (await readdir(dir)).filter((name) => /^page-\d+\.png$/.test(name)).sort();
  return pages.map((name) => join(dir, name));
}

/**
 * The model gets the page images inline and NO tools at all, so a malicious document has nothing to abuse.
 * It also runs in an empty working directory.
 */
async function runClaude(dir, imagePaths) {
  const images = await Promise.all(
    imagePaths.map(async (path) => ({
      mediaType: mediaTypeForExt(path.split('.').pop() ?? '') ?? 'image/png',
      data: await readFile(path),
    })),
  );

  return new Promise((resolve, reject) => {
    const args = [
      '-p',
      '--input-format', 'stream-json',
      '--output-format', 'stream-json',
      '--verbose',
      '--tools', '',
      '--strict-mcp-config',
      '--disable-slash-commands',
      '--no-session-persistence',
      '--setting-sources', '',
      '--effort', 'low',
    ];
    const child = spawn('claude', args, { cwd: dir, env: buildClaudeEnv(process.env), stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(Object.assign(new Error('Claude timed out'), { status: 504 }));
    }, CLAUDE_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      try {
        const result = findResult(stdout);
        if (code !== 0 || !result || result.is_error) {
          const detail = String(result?.result ?? stderr).slice(0, 300);
          const status = /limit|quota|rate/i.test(detail) ? 429 : /login|auth|token/i.test(detail) ? 502 : 500;
          reject(Object.assign(new Error(`Claude failed: ${detail}`), { status }));
          return;
        }
        resolve(extractJsonObject(String(result.result ?? '')));
      } catch (error) {
        reject(Object.assign(new Error(`Claude output unreadable: ${error.message}`), { status: 502 }));
      }
    });

    child.stdin.end(buildStreamInput(images));
  });
}

async function handleExtract(req, res) {
  const body = await readBody(req);
  const type = sniffFileType(body);
  if (!type) {
    return send(res, 415, { error: 'Unsupported file: send a PDF, PNG, JPEG or WEBP' });
  }

  const dir = await mkdtemp(join(tmpdir(), 'smeta-'));
  try {
    const images = await prepareImages(dir, body, type);
    if (images.length === 0) {
      return send(res, 422, { error: 'No pages could be read from the file' });
    }
    const started = Date.now();
    const smeta = await runClaude(dir, images);
    console.log(JSON.stringify({ event: 'extract', pages: images.length, ms: Date.now() - started }));
    return send(res, 200, { smeta, pages: images.length });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function send(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return send(res, 200, { ok: true });
    }
    if (req.method !== 'POST' || req.url !== '/extract') {
      return send(res, 404, { error: 'Not found' });
    }
    if (!isAuthorized(req.headers.authorization, SECRET)) {
      return send(res, 401, { error: 'Unauthorized' });
    }
    if (active >= MAX_CONCURRENT) {
      res.setHeader('Retry-After', '4');
      return send(res, 429, { error: 'Busy, retry shortly' });
    }

    active += 1;
    try {
      await handleExtract(req, res);
    } finally {
      active -= 1;
    }
  } catch (error) {
    console.error('request failed:', error.message);
    if (!res.headersSent) {
      send(res, error.status ?? 500, { error: error.message });
    }
  }
}).listen(PORT, () => console.log(`barpo-ai listening on ${PORT}`));
