FROM node:20-alpine

WORKDIR /usr/src/app

# Install curl for healthcheck
RUN apk add --no-cache curl

# Copy dependency manifests
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev || npm install --omit=dev

# Copy application code
COPY . .

# Expose server port
EXPOSE 3000

# Run healthcheck
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start server
CMD ["node", "src/server.js"]
