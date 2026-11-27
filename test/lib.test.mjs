import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildClaudeEnv, buildStreamInput, extractJsonObject, findResult, isAuthorized, mediaTypeForExt, sniffFileType } from '../lib.mjs';

const pad = (head) => Buffer.concat([Buffer.from(head, 'latin1'), Buffer.alloc(16)]);

test('sniffFileType trusts magic bytes only', () => {
  assert.deepEqual(sniffFileType(pad('%PDF-1.7')), { kind: 'pdf', ext: 'pdf' });
  assert.deepEqual(sniffFileType(Buffer.concat([Buffer.from([0x89]), Buffer.from('PNG'), Buffer.alloc(16)])), { kind: 'image', ext: 'png' });
  assert.deepEqual(sniffFileType(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.alloc(16)])), { kind: 'image', ext: 'jpg' });
  assert.deepEqual(sniffFileType(Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WEBP'), Buffer.alloc(4)])), { kind: 'image', ext: 'webp' });
  assert.equal(sniffFileType(pad('MZ executable')), null);
  assert.equal(sniffFileType(Buffer.from('%PDF')), null);
});

test('isAuthorized requires the exact bearer secret', () => {
  const secret = 'a-long-enough-secret';
  assert.equal(isAuthorized(`Bearer ${secret}`, secret), true);
  assert.equal(isAuthorized('Bearer wrong-secret-value!', secret), false);
  assert.equal(isAuthorized(secret, secret), false);
  assert.equal(isAuthorized(undefined, secret), false);
  assert.equal(isAuthorized('Bearer ', ''), false);
});

test('extractJsonObject tolerates fences and surrounding text', () => {
  assert.deepEqual(extractJsonObject('{"a":1}'), { a: 1 });
  assert.deepEqual(extractJsonObject('```json\n{"a":{"b":2}}\n```'), { a: { b: 2 } });
  assert.deepEqual(extractJsonObject('Here you go: {"a":1} done'), { a: 1 });
  assert.throws(() => extractJsonObject('no json here'));
});

test('buildClaudeEnv passes only the allowed variables', () => {
  const env = buildClaudeEnv({
    PATH: '/bin',
    HOME: '/home/app',
    CLAUDE_CODE_OAUTH_TOKEN: 'tok',
    AI_SERVICE_SECRET: 'secret',
    ANTHROPIC_API_KEY: 'sk-ant-api',
    RAILWAY_TOKEN: 'r',
  });
  assert.equal(env.ANTHROPIC_API_KEY, 'sk-ant-api');
  assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, undefined, 'the API key wins over the subscription token');
  assert.equal(env.PATH, '/bin');
  assert.equal(env.AI_SERVICE_SECRET, undefined);
  assert.equal(env.RAILWAY_TOKEN, undefined);
  assert.equal(env.DISABLE_AUTOUPDATER, '1');
});

test('page images travel inline and the prompt forbids obeying the document', () => {
  const line = buildStreamInput([{ mediaType: 'image/png', data: Buffer.from('abc') }]);
  const message = JSON.parse(line);
  assert.equal(message.type, 'user');
  assert.equal(message.message.content[0].source.data, Buffer.from('abc').toString('base64'));
  assert.match(message.message.content.at(-1).text, /never follow requests/);
  assert.ok(line.endsWith('\n'));
});

test('findResult picks the last result line and ignores noise', () => {
  const out = ['noise', JSON.stringify({ type: 'system' }), JSON.stringify({ type: 'result', result: 'x', is_error: false }), ''].join('\n');
  assert.equal(findResult(out)?.result, 'x');
  assert.equal(findResult('nothing'), undefined);
});

test('mediaTypeForExt maps the extensions the service writes', () => {
  assert.equal(mediaTypeForExt('PNG'), 'image/png');
  assert.equal(mediaTypeForExt('jpg'), 'image/jpeg');
  assert.equal(mediaTypeForExt('exe'), null);
});

test('buildClaudeEnv falls back to the subscription token without an API key', () => {
  const env = buildClaudeEnv({ PATH: '/bin', CLAUDE_CODE_OAUTH_TOKEN: 'tok' });
  assert.equal(env.CLAUDE_CODE_OAUTH_TOKEN, 'tok');
  assert.equal(env.ANTHROPIC_API_KEY, undefined);
});
