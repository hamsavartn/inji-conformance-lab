# 05. Usage & Installation Instructions

This directory contains complete step-by-step instructions for running, testing, and deploying the **MOSIP Inji Conformance Laboratory** across local, containerized, and cloud environments.

## Deliverables Included

1. **`README.md`**: Master repository documentation featuring:
   - System overview and live cloud deployment links
   - Fast installation commands (npm, docker)
   - Architecture diagrams and feature breakdown
2. **`JUDGE_TESTING_GUIDE.md`**: Dedicated judge evaluation manual:
   - Zero-friction cloud testing instructions
   - Single-command local Docker setup (`docker compose up --build`)
   - How to run the automated 8-lane Conformance Matrix
   - How to trigger Chaos Monkey failure vectors
3. **`docker-compose.yml`**: Production container orchestration file defining:
   - Microservice services: `bff-gateway`, `mock-certify`, `mock-verify`
   - Isolated Docker bridge network (`inji-net`)
   - Resource constraints (total memory footprint < 1.5 GB)
4. **`Dockerfile`**: Hardened multi-stage container build based on Node.js 22 LTS with unprivileged execution.
5. **`railway.json` & `RAILWAY_DEPLOYMENT_GUIDE.md`**: Cloud deployment configurations for Render and Railway.

## Quickstart Guide

### Option 1: Live Cloud Instance (No Installation Required)
Simply navigate to:
**`https://inji-conformance-lab.onrender.com`**

### Option 2: Docker Compose (Local 1-Command Setup)
```bash
docker compose up --build
```
Access the application at `http://localhost:3000`.

### Option 3: Local Node.js Development
```bash
npm install
npm run start:local
```
Access the application at `http://localhost:3000`.
