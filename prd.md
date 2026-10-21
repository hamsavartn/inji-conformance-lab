# Product Requirements Document (PRD)
## Project: Inji Interoperability Playground (Inji-Playground)
### Event: MOSIP Decode 2026 | Problem Statement 2 (High Complexity)

---

## 1. Vision & Problem Statement

### 1.1 The Challenge
The MOSIP Inji Stack (Inji Certify, Inji Wallet, Inji Verify) is built upon modern decentralized identity specifications:
- **OpenID4VCI (Draft 13)** for credential issuance.
- **OpenID4VP (Draft 21–23)** for presentation exchange.
- **W3C VC 1.1 / 2.0, SD-JWT VC, and ISO 18013-5 mdoc** for credential payloads.

However, developers, government evaluators, and system integrators lack a unified, visual environment to:
1. Validate how Inji components interact with each other across different configurations.
2. Verify cross-ecosystem interoperability against non-MOSIP wallets, issuers, and verifiers (e.g., EUDI Wallets, Walt.id, Sphereon).
3. Inspect and debug cryptographic payloads, protocol handshakes, and failure modes in real time.

### 1.2 The Solution
**Inji Interop Playground**: A browser-based visual sandbox and orchestration engine that allows users to configure any 3-way permutation of `[Issuer] -> [Wallet] -> [Verifier]`, execute the end-to-end credential lifecycle in real time, inspect every protocol handshake, tamper with payloads to test resilience, and export verified interoperability audits.

---

## 2. Target Personas
1. **MOSIP Integrators & Government Architects**: Need verifiable proof that Inji modules comply with international digital identity standards (EUDI, ISO, W3C) without proprietary lock-in.
2. **Third-Party Wallet Developers**: Want to test whether their external wallet can accept VCs issued by Inji Certify and present them cleanly to Inji Verify.
3. **Inji Core Engineers & QA**: Need an automated regression matrix and negative testing workbench to detect subtle spec drift, QR payload limits, and cryptographic mismatch bugs.
4. **Hackathon Evaluators**: Need a zero-friction, one-command setup (`docker compose up`) with an intuitive visual dashboard that immediately showcases high-complexity protocol mechanics.

---

## 3. Product Architecture & User Journeys

```
+---------------------------------------------------------------------------------------+
|                               INJI INTEROP PLAYGROUND UI                              |
+---------------------------+---------------------------+-------------------------------+
|  1. ISSUER CONFIGURATION  |  2. WALLET CONFIGURATION  |   3. VERIFIER CONFIGURATION   |
|   - Inji Certify          |   - Inji Web (Browser)    |   - Inji Verify               |
|   - Mock VCI Issuer       |   - Inji Mobile (QR/Link) |   - Mock VP Relying Party     |
|   - External (Walt.id)    |   - Mock VCI/VP Wallet    |   - External Verifier         |
+---------------------------+---------------------------+-------------------------------+
                                          |
                                          v
+---------------------------------------------------------------------------------------+
|                             INTERACTIVE LIFECYCLE RUNNER                              |
|   [ Issue Credential ]  ===>  [ Store / Inspect ]  ===>  [ Request & Verify VP ]      |
+---------------------------------------------------------------------------------------+
        |                                   |                                   |
        v                                   v                                   v
+------------------+             +--------------------+             +-------------------+
| PROTOCOL INSPECT |             | SEQUENCE DIAGRAM   |             | INTEROP REPORT    |
| - Credential Offer             | - Animated Mermaid |             | - Pass/Fail Matrix|
| - Token & Proofs |             | - Live State Nodes |             | - Latency & Specs |
| - Raw VC / SD-JWT|             | - Message hops     |             | - Tamper Audit    |
+------------------+             +--------------------+             +-------------------+
```

### 3.1 User Journey 1: Standard Inji Issue & Verify Flow
1. User selects `Inji Certify` as Issuer, `Inji Web` as Wallet, and `Inji Verify` as Verifier.
2. Selects credential format: `IETF SD-JWT VC (National ID)`.
3. Clicks **"Initialize Lifecycle"**.
4. Issuer generates an OpenID4VCI Credential Offer.
5. Inji Web retrieves the offer, performs DPoP / Key-binding proof generation, and exchanges the token for the SD-JWT credential.
6. The UI displays the raw issued credential alongside the decoded disclosures.
7. User triggers presentation to Inji Verify. OpenID4VP request object with `presentation_definition` is fetched.
8. Inji Web produces `presentation_submission` and `vp_token`.
9. Inji Verify validates signatures, issuer DID, and status list. The playground displays a **VALID (PASS)** badge with a latency breakdown.

### 3.2 User Journey 2: Cross-Ecosystem Interoperability (Walt.id / External Mock)
1. User selects `External OpenID4VCI Issuer` (Walt.id / DIF Mock) with `Inji Web` and `Inji Verify`.
2. Validates whether Inji modules accept external schemas without MOSIP-specific proprietary fields.
3. Playground logs protocol differences (e.g., slight differences in metadata discovery or JWT header parameters).

### 3.3 User Journey 3: Negative Path "Replay & Tamper" Testing
1. User enables **"Adversarial / Tamper Mode"** in the top navigation.
2. Selects attack vector from dropdown:
   - `Tampered Signature` (Altered cryptographic payload).
   - `Expired Credential` (`exp` timestamp backdated by 30 days).
   - `Untrusted Issuer DID` (DID missing from trusted issuer registry).
   - `Stripped SD-JWT Disclosures` (Disclosed claims don't match disclosure digest).
3. Submits VP to Inji Verify.
4. Verifier rejects the payload with precise error code (`ERR_CRYPTO_SIGNATURE_INVALID` or `ERR_CREDENTIAL_EXPIRED`).
5. Playground verifies that the negative assertion passed as expected.

---

## 4. Feature Matrix & Scope

| Feature ID | Feature Name | Description | Priority |
| :--- | :--- | :--- | :--- |
| **FEAT-01** | Matrix Selector | 3-column interactive role picker with real-time health checks | P0 (Must Have) |
| **FEAT-02** | OpenID4VCI Engine | Full implementation of Draft 13 issuance flow with live token exchange | P0 (Must Have) |
| **FEAT-03** | OpenID4VP Engine | Draft 21-23 presentation flow with QR and direct post handling | P0 (Must Have) |
| **FEAT-04** | Dual Format Engine | Native parser & encoder for W3C JSON-LD (Ed25519) and SD-JWT VC | P0 (Must Have) |
| **FEAT-05** | Protocol Inspector | Live split-pane JSON/Hex inspector with JWT decoding and claim viewer | P0 (Must Have) |
| **FEAT-06** | Pass/Fail Scorecard | Comprehensive audit report with export to JSON / Markdown | P0 (Must Have) |
| **FEAT-07** | Live Mermaid Sequence | WebSocket-driven sequence diagram dynamically highlighting message hops | P1 (Good to Have) |
| **FEAT-08** | Adversarial Tamperer | 6 one-click tamper vectors to validate verification edge cases | P1 (Good to Have) |
| **FEAT-09** | External Interop Mock | DIF/Walt.id compatible external endpoints for true cross-testing | P1 (Good to Have) |
| **FEAT-10** | ISO 18013-5 mdoc Demo | Synthetic CBOR/COSE parsing simulator for mobile driving licenses | P1 (Good to Have) |
| **FEAT-11** | Historical Dashboard | Persistence of past runs with filtering by format, version, and status | P2 (Bonus) |
| **FEAT-12** | CI/CD Automated Testrig | Headless CLI test harness for automated regression runs | P2 (Bonus) |

---

## 5. Success Metrics for Hackathon Evaluation
- **Functional Completeness (40%)**: All 7 mandatory tasks + 4 good-to-have tasks fully implemented and demonstrable live.
- **Engineering Quality (40%)**: Clean, modular TypeScript/Node.js or Go architecture, Docker Compose orchestration, comprehensive test suite with 85%+ coverage.
- **User Experience (10%)**: Responsive, modern, accessible UI with dark-mode aesthetic, zero UI jank, and instant WebSocket payload telemetry.
- **Storytelling & Pitch (10%)**: Clear 5-minute video demonstrating real-world interoperability gaps surfaced and resolved.
