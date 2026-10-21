# MOSIP Decode 2026: Requirements and Constraints
## Problem Statement 02: Inji Interoperability Playground (Complexity: HIGH)

---

## 1. Executive Summary & Objective
Build a visual, developer-first **Interoperability Playground** web application and automated sandbox for Verifiable Credentials (VCs). The system must allow developers, integrators, and MOSIP evaluators to select any combination of:
1. **Issuer**: Inji Certify, Mock OpenID4VCI Issuer, External Issuer (e.g., Walt.id / Sphereon).
2. **Wallet / Holder**: Inji Web, Inji Mobile (via QR / Deep-link bridge), Mock OpenID4VCI/VP Wallet.
3. **Verifier / Relying Party**: Inji Verify, Mock OpenID4VP Relying Party, External Verifier.

The platform executes live `Issue -> Hold -> Present -> Verify` lifecycle flows, visually rendering raw protocol payloads in real time, validating cryptographic proofs, surfacing standards discrepancies, and producing an exportable interoperability report.

---

## 2. Hard Constraints & Hackathon Boundaries

| Constraint Domain | Boundary Specification | Reference / Source |
| :--- | :--- | :--- |
| **Submission Deadline** | **October 26, 2026, 11:59 PM IST** (5 Days from Oct 21) | MOSIP Decode Guidelines |
| **Complexity Level** | **HIGH** (carries top evaluation weighting under scoring rubrics) | Evaluation Criteria PDF |
| **Licensing** | Must use **OSI-Approved Open Source License** (Apache-2.0 or MIT) | https://opensource.org/licenses |
| **Code of Conduct** | Contributor Covenant adherence; no toxic conduct, strict privacy | MOSIP Code of Conduct |
| **Platform Topology** | **One-Command Docker Compose** deployment (`docker compose up`) runnable offline/locally | Deliverables Section |
| **Zero Proprietary Lock-in** | No proprietary paid APIs (e.g., paid cloud OCR or proprietary VC suites) | Allowed Resources rule |
| **Evaluation Weighting** | 40% Functionality, 40% Deliverable Quality, 10% UX/Design, 10% Pitch/Demo | Evaluation Criteria PDF |

---

## 3. Standards & Cryptographic Requirements

### 3.1 Protocols
- **OpenID for Verifiable Credential Issuance (OpenID4VCI)**:
  - Standard compliance: **Draft 13** (used by Inji Certify).
  - Flows: Authorization Code Flow with PKCE, Pre-Authorized Code Flow.
  - Endpoints: `/.well-known/openid-credential-issuer`, `/credential_offer`, `/token`, `/credential`.
- **OpenID for Verifiable Presentations (OpenID4VP)**:
  - Standard compliance: **Draft 21–23** (used by Inji Verify).
  - Flows: Cross-device QR flow (`openid4vp://` scheme or HTTPS URI with request URI), Same-device deep link / Digital Credentials API bridge.
  - Data structures: `presentation_definition` (DIF Presentation Exchange 2.0), `vp_token`, `presentation_submission`.
  - Response modes: `direct_post` and `direct_post.jwt`.

### 3.2 Credential Formats & Proof Types
1. **W3C VC 1.1 / 2.0 (JSON-LD / JWT)**:
   - Cryptographic suites: `Ed25519Signature2020`, `JsonWebSignature2020` (RSA / secp256k1).
2. **IETF SD-JWT VC (Selective Disclosure JWT)**:
   - Format: `compact_jwt~disclosure1~disclosure2~...~key_binding_jwt`.
   - Algorithm: `ES256` / `EdDSA`.
3. **mso_mdoc (ISO/IEC 18013-5)**:
   - Binary CBOR / COSE Sign1 structures (via Inji Certify mock mode / synthetic simulator).

---

## 4. Functional Requirements Checklist

### 4.1 Mandatory Requirements (Target: 100% Pass)
- [x] **FR-M01: 3-Column Visual Matrix**: Issuer, Wallet, and Verifier column selector with status badges (Online, Mocked, Inji-Native).
- [x] **FR-M02: Live Issuance Flow (OpenID4VCI)**: Trigger credential offer, pre-auth/auth token request, proof generation, and credential return.
- [x] **FR-M03: Live Presentation & Verification Flow (OpenID4VP)**: Generate authorization request with presentation definition, present via wallet, verify signature, issuer DID, and expiration.
- [x] **FR-M04: Real-Time Protocol Inspector**: Live payload stream displaying headers, claims, DIDs, signatures, and raw JSON/CBOR at every stage.
- [x] **FR-M05: Multi-Format Support**: Native support and visual badge distinction for both W3C VC JSON-LD and IETF SD-JWT VC.
- [x] **FR-M06: Pass/Fail Interoperability Report**: Automated scorecard showing status, latency, format, proof type, and explicit error breakdown if failed.
- [x] **FR-M07: Docker Compose Bundle**: Clean orchestration bringing up the BFF, Frontend, Inji Mocks, and Verification engine.

### 4.2 Good-to-Have Requirements (High Value for 1st Place)
- [x] **FR-G01: External Interop Reference Mock**: Standards-compliant DIF / Walt.id / Sphereon compatible issuer & verifier mock to prove cross-ecosystem interop.
- [x] **FR-G02: Interactive Mermaid Protocol Sequence**: Real-time rendering of the actual message exchange with dynamic node highlighting.
- [x] **FR-G03: Negative Path "Replay & Tamper" Suite**: UI switch to inject forged signatures, expired timestamps, mismatched issuers, or stripped disclosures to prove Inji Verify defense mechanisms.
- [x] **FR-G04: mDoc / mDL (ISO 18013-5) Playground**: Visual parser for CBOR/COSE mobile driving licenses.
- [x] **FR-G05: Historical Regression Dashboard**: Filterable SQLite/JSON store tracking previous test executions across versions.

### 4.3 Bonus Requirements
- [x] **FR-B01: CI/CD Interop Test Harness**: GitHub Action / CLI runner executing matrix permutations and uploading Markdown reports.
- [x] **FR-B02: Live Telemetry & Observability**: Handshake latency breakdown (ms) per protocol hop.
- [x] **FR-B03: Automated Bug & Gap Export**: Formatted issue templates ready for filing against MOSIP upstream repos.

---

## 5. Non-Functional Requirements
- **Performance**: Protocol Inspector updates within `< 100ms` via WebSockets.
- **Portability**: Must run seamlessly on Linux, macOS, and Windows via Docker Desktop.
- **Aesthetics & Usability**: Modern dark/light cyber-themed UI with clean typography (Inter / JetBrains Mono) and zero generic styling.
- **Documentation**: Comprehensive README with setup steps under 3 minutes, architecture diagrams, API specs, and video walk-through script.
