# The Rulebook judge page (demo/judge/, served by demo/src/judge-server.ts). Read-only: no PayPal,
# NEAR, NEAR AI or agent credential is copied in or needed; "Run it" replays on in-process fakes.
# Build from the repo root: docker build -f demo/judge/Dockerfile .
FROM node:22.18.0-slim
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080
WORKDIR /app
RUN npm install -g pnpm@12.16.1
COPY . .
# The demo package and the workspace packages it imports; no dev dependencies (no Playwright).
RUN pnpm install --frozen-lockfile --prod --filter "@nearh/demo..."
USER node
EXPOSE 8080
CMD ["node", "demo/src/judge-server.ts"]
