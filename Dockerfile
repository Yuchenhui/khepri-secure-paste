FROM node:20-alpine
WORKDIR /app
COPY core.js shortener.js ./
COPY public/ ./public/
ENV NODE_ENV=production
# Two services share the image; override CMD to run either:
#   docker run ... khepri node core.js
#   docker run ... khepri node shortener.js
CMD ["node", "core.js"]
