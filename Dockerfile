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
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["node", "-e", "const p=(process.env.RSS_PATH||'/rss').replace(/\\/+$/,'')||'/';const i=p.lastIndexOf('/');const dir=i<=0?'':p.slice(0,i);const port=process.env.PORT||3000;fetch('http://127.0.0.1:'+port+dir+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "src/server.ts"]
