FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 3000

VOLUME ["/app/data"]
ENV DB_PATH=/app/data/passgen.db

CMD ["node", "server.js"]
