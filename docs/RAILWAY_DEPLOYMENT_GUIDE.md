# MOSIP Inji Conformance Laboratory — Railway Cloud Deployment Manual

This guide explains how to deploy the entire **MOSIP Inji Conformance Laboratory** (all 4 microservices + Web UI) to [Railway.app](https://railway.app) in **under 2 minutes** so hackathon judges can immediately test the live application without installing or running anything locally.

---

## 1. Cloud Architecture Overview

Railway deploys the project as a **Unified Cloud Container** using the root [`Dockerfile`](file:///c:/Users/ASUS/Desktop/Hackathons/MOSIP/Dockerfile) and [`railway.json`](file:///c:/Users/ASUS/Desktop/Hackathons/MOSIP/railway.json):

```
                               PUBLIC INTERNET / JUDGES
                                          │
                         HTTPS: https://your-app.up.railway.app
                                          │
    ┌─────────────────────────────────────▼─────────────────────────────────────┐
    │                      RAILWAY CONTAINER ($PORT)                            │
    │                                                                           │
    │   ┌───────────────────────────────────────────────────────────────────┐   │
    │   │                  Hardened BFF Orchestrator Hub                    │   │
    │   │  • Serves React UI SPA bundle (/)                                │   │
    │   │  • Orchestration REST APIs (/api/v1/orchestrate/*)                │   │
    │   │  • Live WebSocket Telemetry (/telemetry via wss://)              │   │
    │   │  • SQLite Conformance Ledger                                     │   │
    │   └─────────────────────┬───────────────────────┬─────────────────────┘   │
    │                         │                       │                         │
    │                 http://localhost:8080   http://localhost:8081             │
    │                         │                       │                         │
    │   ┌─────────────────────▼─────┐   ┌─────────────▼─────────────────────┐   │
    │   │    Mock Inji Certify      │   │         Mock Inji Verify          │   │
    │   │  • OpenID4VCI Draft 13/14 │   │  • OpenID4VP Draft 21-23          │   │
    │   │  • DPoP, SD-JWT, mdoc     │   │  • DIF PE 2.0, direct_post        │   │
    │   └───────────────────────────┘   └───────────────────────────────────┘   │
    └───────────────────────────────────────────────────────────────────────────┘
```

### Why this design is rock-solid:
- **Single Public URL:** Judges only need one HTTPS link.
- **Zero CORS / Zero Mixed Content Errors:** The frontend and backend share the exact same origin (`window.location.origin`), avoiding browser security blocks.
- **Persistent WebSockets:** Telemetry connects natively over `wss://` to the same host.
- **Zero Configuration:** Railway automatically injects `$PORT`, and the container binds everything internally.

---

## 2. Step-by-Step Deployment (2 Minutes)

### Step 1: Ensure Latest Code is Pushed to GitHub
In your terminal:
```bash
git push origin master
```

### Step 2: Create Railway Project
1. Go to [railway.app](https://railway.app) and sign in (using your GitHub account).
2. Click **"+ New Project"**.
3. Select **"Deploy from GitHub repo"**.
4. Select your MOSIP hackathon repository (`MOSIP` or `inji-interop-playground`).

### Step 3: Generate Public Domain
1. Once Railway imports the project, click on the service card in the Railway dashboard.
2. Go to the **Settings** tab.
3. Under the **Networking** section, click **"Generate Domain"** (e.g. `mosip-inji-conformance.up.railway.app`).
4. Railway will build the Docker container and deploy all microservices.

### Step 4: Verify Live System
Open your generated Railway URL in your browser:
- You should see the **MOSIP Inji Conformance Laboratory** web dashboard.
- Click **"▶ EXECUTE HANDSHAKE"** to test a live OpenID4VCI + OpenID4VP credential issuance and verification flow.
- Click **"RUN ALL LANES"** to verify the 8-lane interop matrix.

---

## 3. How to Submit on Hackathon Portal

In your Unstop / MOSIP Decode submission form:
- **Project Link / Live Demo URL:** Enter your Railway URL (`https://your-app.up.railway.app`).
- **Submission Note:**
  > *"Live Interactive Playground: https://your-app.up.railway.app (Runs all 4 microservices live with real-time WebSockets and zero-dependency cloud hosting). Offline/Local execution also fully supported via `docker compose up --build`."*
