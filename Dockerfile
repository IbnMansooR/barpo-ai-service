FROM node:22-bookworm-slim

ARG CLAUDE_VERSION=2.1.235

ENV NODE_ENV=production \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# poppler-utils: pdftoppm renders scanned PDF pages to PNG for the model to read.
RUN apt-get update \
    && apt-get install -y --no-install-recommends poppler-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code@${CLAUDE_VERSION} \
    && claude --version

# The CLI runs as an unprivileged user.
RUN useradd --create-home --shell /usr/sbin/nologin app
USER app
ENV HOME=/home/app

WORKDIR /app
COPY --chown=app:app lib.mjs server.mjs package.json ./

CMD ["node", "server.mjs"]
