FROM node:26 AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npm install -g "pnpm@$(node -p "require('./package.json').packageManager.split('@')[1].split('+')[0]")"
RUN pnpm install --prod --frozen-lockfile
COPY . .

FROM node:26-slim AS runner
WORKDIR /app
COPY --from=build /app .
RUN set -xe \
    && chown -R node:node /app \
    && rm -rf /root /opt/* /tmp/* /var/cache/* /var/log/* /var/spool/* /var/lib/systemd

FROM scratch AS final
COPY --from=runner / /
WORKDIR /app
USER node
CMD ["node", "src/server.ts"]
