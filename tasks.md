# Work Breakdown Structure & Implementation Tasks
## Project: Inji Interoperability Playground
### Target Deadline: October 26, 2026, 11:59 PM IST (5 Days)

---

## Phase 0: Scaffolding, Docker Topology & Core Infrastructure (Day 1: Oct 21)
- [x] **TASK-001**: Initialize project repository structure (`/frontend`, `/backend`, `/mocks`, `/docs`, `/scripts`).
- [x] **TASK-002**: Create base `docker-compose.yml`, `openapi_spec.yaml`, `db/schema.sql`, `fixtures/`, and CI runner.
- [x] **TASK-003**: Configure TypeScript strict mode and local project skills (`.agents/skills/`).
- [x] **TASK-004**: Set up WebSocket event hub in Node.js BFF for real-time bidirectional telemetry.

---

## Phase 1: Core Protocol Engines & Mock Adapters (Day 2: Oct 22)
- [x] **TASK-101**: Implement **OpenID4VCI (Draft 13)** Issuer Mock:
  - `/.well-known/openid-credential-issuer` metadata discovery.
  - `/credential_offer` generator (pre-authorized code & auth code).
  - `/token` endpoint with DPoP support.
  - `/credential` endpoint with W3C VC and SD-JWT VC issuance.
- [x] **TASK-102**: Implement **OpenID4VP (Draft 21–23)** Verifier Mock:
  - Presentation request builder (`presentation_definition` with DIF PE 2.0).
  - `/direct_post` response endpoint with 5MB buffer.
  - Cryptographic verification engine for signatures, issuer DIDs, and expiration.
- [x] **TASK-103**: Build Automated Synthetic Wallet Agent:
  - Ephemeral P-256 key-pair generation (`secp256r1`).
  - RFC 9449 DPoP `ath` access token hash calculation and binding.
  - Proof of possession signing (`proof.jwt`) with singular Draft 13 wrapper.
  - SD-JWT holder disclosure filtering and key-binding assembly.
- [x] **TASK-104**: Implement Inji Collab Sandbox Proxy Adapter (connecting to live Inji Certify and Inji Verify instances).

---

## Phase 2: Frontend Matrix & Protocol Inspector (Day 3: Oct 23)
- [x] **TASK-201**: Implement **3-Column Matrix Selector**:
  - Issuer selector (Inji Certify / Mock VCI / External Walt.id).
  - Wallet selector (Inji Web / Inji Mobile QR Bridge / Automated Agent).
  - Verifier selector (Inji Verify / Mock VP / External Verifier).
  - Live ping/health status probes.
- [x] **TASK-202**: Build **Real-Time Protocol Inspector**:
  - Overview panel with high-level claims and lifecycle progress bar.
  - Raw compact token viewer with 1-click clipboard copy.
  - Decoded JWT inspector (header/payload/signature color coding).
  - SD-JWT selective disclosure tree with disclosure hash verification.
- [x] **TASK-203**: Wire WebSocket stream from BFF to Frontend with reactive state updates.

---

## Phase 3: Interactive Visualizations & Tamper Workbench (Day 4: Oct 24)
- [x] **TASK-301**: Implement **Dynamic Mermaid Sequence Diagram**:
  - Live SVG rendering using Mermaid.js.
  - Active protocol handshake hop tracking.
- [x] **TASK-302**: Build **Adversarial Tamper Workbench**:
  - UI toggles for 4 primary attack vectors:
    1. Signature bit-flip corruption (`replace_last_char_with_Z`).
    2. Expired credential timestamp injection (-600s).
    3. Key-binding nonce mutation (`INVALID_REPLAY`).
    4. Stripped SD-JWT disclosure payloads.
  - Negative assertion validator confirming Inji Verify returns expected HTTP 400 rejection codes.
- [x] **TASK-303**: Add Synthetic ISO 18013-5 mdoc / mDL parser demonstration.

---

## Phase 4: Interoperability Scorecard & Automated CI Harness (Day 5: Oct 25)
- [ ] **TASK-401**: Build **Historical Interoperability Dashboard**:
  - Store test run results in SQLite / JSON persistence.
  - Filter by credential format, module version, and pass/fail outcome.
  - One-click export to Markdown (`INTEROP_MATRIX.md`) and JSON.
- [ ] **TASK-402**: Implement Headless CLI Interoperability Runner (`npm run test:interop`):
  - Runs all matrix permutations headlessly.
  - Generates GitHub Actions summary table.
- [ ] **TASK-403**: Implement Issue Generator:
  - Formats discovered protocol discrepancies into ready-to-file GitHub issue markdown for `mosip/inji-*` repositories.

---

## Phase 5: Polish, Documentation, Video Demo & Submission (Day 6: Oct 26)
- [ ] **TASK-501**: Complete master `README.md` with 3-minute quickstart guide, architecture diagrams, and API docs.
- [ ] **TASK-502**: Prepare Test Data fixtures (`sample_credentials.json`, `test_dids.json`, `tamper_payloads.json`).
- [ ] **TASK-503**: Produce 5–7 Slide Pitch Presentation PDF covering Problem, Solution, Architecture, Matrix, and MOSIP Impact.
- [ ] **TASK-504**: Record 3–5 Minute Video Demo walking through live End-to-End Issue, Hold, Present, Verify, and Tamper flows.
- [ ] **TASK-505**: Final submission audit against MOSIP Decode Checklist and email dispatch to `decode@mosip.io`.
