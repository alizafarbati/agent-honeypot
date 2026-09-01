FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY surface/ surface/
COPY capture/ capture/
COPY evolution/ evolution/
COPY analysis/ analysis/
RUN npx tsc

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist/ ./dist/
COPY surface/mcpservers/hr-portal/ ./surface/mcpservers/hr-portal/
COPY capture/ ./capture/
COPY analysis/stylometry/ ./analysis/stylometry/
COPY evolution/rl/ ./evolution/rl/
COPY control/ ./control/
COPY security/ ./security/
COPY scripts/ ./scripts/
COPY bin/ ./bin/
COPY docs/ ./docs/
RUN mkdir -p data
EXPOSE 9079
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:9079/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "bin/agent-honeypot.mjs", "dash"]
