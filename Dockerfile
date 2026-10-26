FROM node:22-alpine

WORKDIR /app

# 1. Install production dependencies for backend microservices
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --omit=dev

COPY mocks/issuer/package*.json ./mocks/issuer/
RUN cd mocks/issuer && npm ci --omit=dev

COPY mocks/verifier/package*.json ./mocks/verifier/
RUN cd mocks/verifier && npm ci --omit=dev

# 2. Install dependencies and build the frontend React SPA
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci

# 3. Copy application source tree
COPY . .

# 4. Compile frontend production bundle
RUN cd frontend && npm run build

# 5. Runtime environment defaults
ENV NODE_ENV=production
ENV PORT=4000

EXPOSE 4000

# 6. Execute unified production orchestrator
CMD ["node", "scripts/start_production.js"]
