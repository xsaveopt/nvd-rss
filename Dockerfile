FROM node:26 AS build
WORKDIR /app
COPY . .
RUN set -xe \
    && npm install --omit=dev

FROM node:26-slim AS runner
WORKDIR /app
COPY --from=build /app .
RUN set -xe \
    && npm i -g npm \
    && chown -R node:node /app \
    && npm cache clean --force \
    && rm -rf /root /opt/* /tmp/* /var/cache/* /var/log/* /var/spool/* /var/lib/systemd

FROM scratch AS final
COPY --from=runner / /
WORKDIR /app
USER node
CMD ["npm", "run", "start"]
