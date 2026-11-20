FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache --upgrade \
      'nodejs-current=26.13.1-r0' 'libcrypto3>=3.5.9-r1' 'libssl3>=3.5.9-r1' 'zlib>=1.4-r0' \
    && addgroup -S node && adduser -S -D -H -G node node

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
