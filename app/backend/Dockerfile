FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

# Run as non-root user for security best practices
USER 10001

EXPOSE 5000

CMD ["node", "server.js"]
