# MOSIP Decode 2026 — Master Submission Checklist
## Problem Statement 2: Inji Conformance Laboratory & Interoperability Playground

---

## 📁 Submission Deliverables Dossier Hierarchy

All submission materials are duplicated into structured, dedicated topic folders under `submission_deliverables/` for clear evaluation, while all original root files remain intact:

```
submission_deliverables/
├── 01_pitch_presentation_or_slide_deck/
│   ├── PITCH_DECK.pptx                     # Editable 16:9 Presentation (PowerPoint)
│   ├── PITCH_DECK.pdf                      # Print-ready Pitch Deck (PDF)
│   └── README.md                           # Pitch deck overview & executive summary
│
├── 02_design_mockup_and_wireframe/
│   ├── ui_main_dashboard.jpg               # High-res screenshot of main workbench UI
│   ├── ui_interop_matrix.jpg               # High-res screenshot of 8-lane matrix UI
│   ├── design.md                           # UI/UX wireframes, styling & component architecture
│   └── README.md                           # Design specifications summary
│
├── 03_architecture_diagram/
│   ├── architecture.md                     # Microservices, network topology & sequence flows
│   └── README.md                           # Architectural overview & security model
│
├── 04_test_data_and_results/
│   ├── TEST_DATA.md                        # Test data dossier & schemas
│   ├── sample_credentials.json             # SD-JWT, W3C JSON-LD, ISO mdoc payloads
│   ├── tamper_vectors.json                 # Chaos monkey adversarial test vectors
│   ├── INTEROP_MATRIX.md                   # 8-Lane cross-ecosystem interop results
│   ├── verification-matrix.md              # RFC protocol conformance matrix
│   ├── AUDIT_REPORT.md                     # 40/40 Passing test verification report
│   └── README.md                           # Test execution summary
│
├── 05_usage_and_installation_instructions/
│   ├── README.md                           # Master project documentation
│   ├── JUDGE_TESTING_GUIDE.md              # Quickstart guide for judges & evaluators
│   ├── docker-compose.yml                  # 1-Command local orchestration
│   ├── Dockerfile                          # Hardened multi-stage container build
│   ├── railway.json                        # Cloud deployment configuration
│   ├── RAILWAY_DEPLOYMENT_GUIDE.md         # Deployment reference guide
│   └── README.md                           # Installation instructions summary
│
├── 06_api_documentation/
│   ├── openapi_spec.yaml                   # Complete OpenAPI 3.0.3 specification
│   └── README.md                           # API endpoint guide & schemas
│
└── 07_packaged_zip_deliverables/
    ├── mosip_inji_conformance_lab.zip      # Complete packaged submission archive (3.29 MB)
    └── README.md                           # Packaging manifest & unzip instructions
```

---

## 🎯 Master Deliverables Checklist

### 1. Presentation & Documentation
- [x] **Pitch Deck (PPTX)**: `PITCH_DECK.pptx` (10 widescreen 16:9 slides)
- [x] **Pitch Deck (PDF)**: `PITCH_DECK.pdf` (High-resolution, pre-rendered)
- [x] **README.md**: Complete project guide, architecture overview, live cloud demo links
- [x] **Judge Testing Guide**: `JUDGE_TESTING_GUIDE.md` (Step-by-step 1-click evaluation guide)
- [x] **OpenAPI 3.0.3 Specification**: `openapi_spec.yaml` (Documenting BFF, Issuer, Verifier)
- [x] **License**: `LICENSE` (Apache License 2.0)

### 2. Design & Architecture
- [x] **UI Mockup - Main Workbench**: `docs/screenshots/ui_main_dashboard.jpg`
- [x] **UI Mockup - Interop Matrix**: `docs/screenshots/ui_interop_matrix.jpg`
- [x] **Design Specifications**: `design.md` (Design system, wireframes, component hierarchy)
- [x] **Architecture Specification**: `architecture.md` (Microservices topology, zero-trust boundary, sequence diagrams)

### 3. Test Suites, Data & Conformance Matrices
- [x] **Cryptographic Test Data Dossier**: `fixtures/TEST_DATA.md`
- [x] **Sample Credential Vectors**: `fixtures/sample_credentials.json` (SD-JWT, W3C JSON-LD, ISO 18013-5 mdoc)
- [x] **Adversarial Tamper Vectors**: `fixtures/tamper_vectors.json` (5 Chaos Monkey attack vectors)
- [x] **Interop Results Matrix**: `INTEROP_MATRIX.md` (8-Lane cross-ecosystem matrix)
- [x] **Verification Matrix**: `docs/verification-matrix.md` (Requirement-to-test traceability)
- [x] **Security & Quality Audit**: `AUDIT_REPORT.md` (All 40/40 tests passing with 0 errors)

### 4. Cloud Deployment & Containerization
- [x] **Live 24/7 Cloud URL**: [`https://inji-conformance-lab.onrender.com`](https://inji-conformance-lab.onrender.com)
- [x] **Health Check Endpoint**: [`https://inji-conformance-lab.onrender.com/api/v1/health`](https://inji-conformance-lab.onrender.com/api/v1/health) (`status: UP`)
- [x] **Docker Compose Topology**: `docker-compose.yml` (`bff-gateway`, `mock-certify`, `mock-verify` on `inji-net`)
- [x] **Production Dockerfile**: `Dockerfile` (Node.js 22-slim, non-root user, optimized footprint)
- [x] **GitHub Actions CI**: `.github/workflows/interop-matrix.yml`

### 5. Packaging & Cleanliness
- [x] **Packaged Submission Zip**: `mosip_inji_conformance_lab.zip` (3.29 MB, strictly verified with all required assets)
- [x] **Zero Unnecessary Files**:
  - Excluded all agent scratch/prompts (`*AUDIT_PROMPT*.md`, `*AUDIT_MANDATE*.md`, `memory.md`, `tasks.md`).
  - Excluded local databases (`*.db`, `*.db-shm`, `*.db-wal`).
  - Excluded non-hackathon binary assets (`fouriertherm*.png`, `ieee_paper_preview.png`, `*.docx`).
  - Excluded private speech script (`docs/DEMO_VIDEO_SCRIPT.md`).

---

## 📹 Actions Required by You (The Submitter)

These remaining items are external to the codebase and must be completed by you:

1. **Record the 5-Minute Demo Video**:
   - Open `docs/DEMO_VIDEO_SCRIPT.md` (kept local on your laptop).
   - Open `https://inji-conformance-lab.onrender.com` in your browser.
   - Record your 1080p walkthrough following the second-by-second cues (00:00 to 05:00).
   - Export as `inji-conformance-lab-demo.mp4` (or similar).

2. **Upload Submission Deliverables to Google Drive**:
   - Create a new Google Drive folder (e.g. `MOSIP_Decode_2026_PS02_[TeamName]`).
   - Upload:
     - `mosip_inji_conformance_lab.zip` (found in `submission_deliverables/07_packaged_zip_deliverables/` or root)
     - `PITCH_DECK.pdf`
     - Demo Video (`.mp4`)
     - College / Student ID Card Scan
   - Set folder sharing to: **"Anyone with the link can view"**.

3. **Send Submission Email / Form**:
   - **Recipient**: `decode@mosip.io`
   - **Subject**: `MOSIP Decode 2026 Submission - PS02 Inji Conformance Laboratory - [Your Team Name]`
   - **Email Body**:
     - Team Name & Member Details
     - GitHub Repo Link: `https://github.com/hamsavartn/inji-conformance-lab`
     - Live Cloud Demo Link: `https://inji-conformance-lab.onrender.com`
     - Google Drive Folder Link (containing Video, Zip, Deck, ID Card)
