FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node server.mjs package.json ./
COPY --chown=node:node public ./public
COPY --chown=node:node private ./private
USER node
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["node","server.mjs"]
