# 07. Packaged Zip Deliverables

This directory contains the official packaged submission archive for the **MOSIP Inji Conformance Laboratory** (Problem Statement 2: High Complexity).

## Deliverables Included

1. **`mosip_inji_conformance_lab.zip`**: Complete offline standalone deliverable package (3.29 MB) containing:
   - Full Source Code (BFF Gateway, React Frontend, OpenID4VCI & OpenID4VP Mocks, Inji Collab proxy)
   - Complete Test Suites (40/40 Passing Unit, E2E, and Security Regression Tests)
   - Production Dockerfile and docker-compose.yml
   - OpenAPI 3.0.3 YAML Specification
   - Pitch Deck (PowerPoint PPTX & PDF)
   - Architecture & Design Documents
   - Test Data & Chaos Tamper Fixtures
   - Conformance Verification Matrices

## Verification & Integrity

- **Archive Size**: ~3.29 MB
- **Cleanliness Guarantee**:
  - Excludes `node_modules`, `dist/`, build artifacts, and runtime SQLite files (`*.db-wal`).
  - Excludes internal evaluator prompts, speech scripts, and temporary editor caches.
  - Retains all directory structures, making it immediately runnable with `docker compose up --build`.

## Unpacking & Execution Instructions

```bash
# 1. Unzip the archive
unzip mosip_inji_conformance_lab.zip -d mosip_inji_conformance_lab
cd mosip_inji_conformance_lab

# 2. Run with Docker (Recommended)
docker compose up --build

# 3. Access in browser
http://localhost:3000
```

