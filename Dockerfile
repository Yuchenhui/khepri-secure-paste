FROM node:22-alpine

LABEL org.opencontainers.image.source="https://github.com/Yuchenhui/khepri-secure-paste"
ENV NODE_ENV=production
WORKDIR /app
COPY core.js shortener.js http-util.js ./
COPY public/new.html public/view.html ./public/
USER node

HEALTHCHECK --interval=30s --timeout=4s --start-period=5s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || '8080') + '/health', {signal:AbortSignal.timeout(3000)}).then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

# Override with node shortener.js to run the short-link service.
CMD ["node", "core.js"]
