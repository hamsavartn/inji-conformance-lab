# MOSIP Inji Conformance Laboratory — Requirements Verification Matrix

**Document Version:** 2.0.0-reverified
**Target Specification:** MOSIP Decode 2026 — Problem Statement 02 (Inji Interoperability Playground)
**Evaluation Standard:** Zero-Trust Runtime Evidence (RFC 7515, RFC 9449, RFC 9901, OpenID4VCI Draft 13/14, OpenID4VP Draft 21-23, DIF PE 2.0, ISO/IEC 18013-5)
**Re-verification Date:** 2026-10-24 (independent re-audit; every status below is backed by live execution this session, not inherited)

---

## 1. Traceability Matrix: PRD Core Features (FEAT-01 to FEAT-12)

| Feature ID | Requirement Name | Expected Behavior | Implementation Location | Verification Evidence & Test Method | Status |
|:---|:---|:---|:---|:---|:---:|
| **FEAT-01** | **Matrix Selector** | 3-column topology picker (Issuer, Wallet, Verifier) with honest option labeling. | `frontend/src/App.tsx`<br>`backend/server.js` (`/api/v1/matrix`) | Probed `GET /api/v1/matrix` live; UI renders 3 lanes; wallet/issuer options that execute via the synthetic agent are explicitly labeled "Simulated". | **PASS** |
| **FEAT-02** | **OpenID4VCI Engine** | Draft 13 issuance with pre-authorized code, DPoP sender-constraining (`ath`, `jti`, `htm`/`htu`, `cnf.jkt`), holder proof `aud`/`iat` binding. | `mocks/issuer/server.js`<br>`backend/server.js` | e2e VULN-01/03/07; security suite SEC-01 (forged token now `401`), SEC-10 (`htm=GET` proof now `400 invalid_dpop_proof`). | **PASS** |
| **FEAT-03** | **OpenID4VP Engine** | Draft 21–23 presentation flow, DIF PE 2.0, single-use session nonces, fail-closed replay defense. | `mocks/verifier/server.js`<br>`backend/server.js` | e2e VULN-02/04/08; **genuine** replay regression (REGRESSION-02 resubmits the same nonce → `ERR_NONCE_ALREADY_CONSUMED`); SEC-08. | **PASS** |
| **FEAT-04** | **Dual Format Engine** | `vc+sd-jwt`/`dc+sd-jwt` with mandatory RFC 9901 `sd_hash`; `ldp_vc` Ed25519 with fail-closed key resolution. | `mocks/issuer/server.js`<br>`mocks/verifier/server.js` | e2e VULN-09/10; SEC-02 (missing `sd_hash` rejected), SEC-03 (foreign audience rejected), SEC-06 (byte-flipped proof rejected by real signature check). W3C canonicalization documented as a bounded simulation (see §5). | **PASS** |
| **FEAT-05** | **Protocol Inspector** | JWT/disclosure anatomy with **real** per-disclosure digest verification. | `frontend/src/App.tsx` (anatomy tab) | Badges now computed client-side via `crypto.subtle` SHA-256 against `_sd` (UNBOUND DIGEST on mismatch). tsc + build clean. | **PASS** |
| **FEAT-06** | **Scorecard & Export** | Honest pass/fail scorecard; RFC 7807 GitHub defect exporter. | `frontend/src/App.tsx`<br>`backend/server.js` | Scorecard previously hardcoded "100% CERTIFIED" — now renders actual `compliancePercentage` and failed-lane count; confetti only at 100%. Exporter exercised (FEATURE-1). | **PASS (corrected)** |
| **FEAT-07** | **Live Sequence Diagram** | WebSocket-driven Mermaid with debounced rendering. | `frontend/src/App.tsx` (sequence tab) | Render logic reviewed; diagram driven by actual selections. **Interactive click-through unverified this session** (no browser automation available). | **PARTIALLY VERIFIED** |
| **FEAT-08** | **Adversarial Tamperer** | 8 chaos vectors with code-specific RFC 7807 rejections. | `backend/server.js`, `mocks/verifier/server.js` | e2e VEC-01..08 all assert their specific error codes (generic `invalid_presentation` fallbacks removed from assertions). UI dropdown labels corrected to match. | **PASS** |
| **FEAT-09** | **External Interop** | External ecosystems; honest labeling where execution routes to local mocks. | `backend/server.js` (two-phase Collab probe)<br>`frontend/src/App.tsx` | Live Collab discovery probe + PMS boundary telemetry verified (VULN-06); deterministic fallback labeled in UI/README. **Walt.id selection routes to the local mock — simulation, explicitly labeled.** No external implementation was available for true cross-ecosystem testing. | **PARTIAL (labeled)** |
| **FEAT-10** | **ISO 18013-5 mdoc** | CBOR Tag 24, COSE_Sign1, per-attribute `valueDigests`, integer `digestID`, nonce binding. | `mocks/issuer/server.js`<br>`mocks/verifier/server.js` | MDOC-01..04 fail-closed suite (omitted nonce, tampered attribute, deleted `digestID`, replay). DeviceSigned/NFC-BLE out of scope and not claimed. | **PASS (bounded)** |
| **FEAT-11** | **Historical Dashboard** | Persistent SQLite WAL history. | `backend/server.js`<br>`db/conformance.db` | History verified across runs; **PII leak in `trace_blob` found and fixed** (SEC-07: redaction at write + read). | **PASS** |
| **FEAT-12** | **CLI Conformance Runner** | Fail-closed headless harness. | `scripts/cli_interop_runner.sh` | 8/8 lanes exit 0 this session; health probe gates execution; CI workflow now covers `master`/PRs with fail-closed health wait. | **PASS** |

---

## 2. Functional Requirements Breakdown (PRD §4.1 - §4.3)

| Requirement Code | Category | Requirement Description | Implementation Artifact | Status |
|:---|:---|:---|:---|:---:|
| **FR-M01** | Mandatory | 3-Column Visual Matrix with honest status labeling. | `frontend/src/App.tsx` | **PASS** |
| **FR-M02** | Mandatory | Live Issuance Flow (OpenID4VCI Draft 13, DPoP sender-constraining). | `mocks/issuer/server.js`, `backend/server.js` | **PASS** |
| **FR-M03** | Mandatory | Live Presentation & Verification Flow (OpenID4VP Draft 21-23, DIF PE 2.0). | `mocks/verifier/server.js`, `backend/server.js` | **PASS** |
| **FR-M04** | Mandatory | Real-Time Protocol Inspector (real digest verification). | `frontend/src/App.tsx` | **PASS** |
| **FR-M05** | Mandatory | Multi-Format Support (`vc+sd-jwt`, `dc+sd-jwt`, `ldp_vc`, `mso_mdoc`). | `mocks/*`, `backend/server.js` | **PASS** |
| **FR-M06** | Mandatory | Pass/Fail Report with JSON/Markdown export (honest percentage). | `frontend/src/App.tsx`, `INTEROP_MATRIX.md` | **PASS** |
| **FR-M07** | Mandatory | Docker Compose bundle under 920MB RAM. | `docker-compose.yml` (healthchecks + ordering added) | **PARTIALLY VERIFIED** (config valid; daemon offline locally — CI verifies on push) |
| **FR-G01** | Good-to-Have | External Interop Reference Mock. | `backend/server.js` | **PARTIAL (labeled simulation)** |
| **FR-G02** | Good-to-Have | Interactive Mermaid Sequence Diagram. | `frontend/src/App.tsx` | **PARTIALLY VERIFIED** (static evidence) |
| **FR-G03** | Good-to-Have | Negative Path "Replay & Tamper" Suite (8 vectors). | `scripts/test_e2e_local.js`, `scripts/test_security_regression.js` | **PASS** |
| **FR-G04** | Good-to-Have | ISO 18013-5 mdoc Playground & Verifier. | `mocks/*` | **PASS (bounded)** |
| **FR-G05** | Good-to-Have | Historical Regression Dashboard (SQLite WAL). | `backend/server.js` | **PASS** |
| **FR-B01** | Bonus | CI/CD Headless Conformance Harness. | `scripts/cli_interop_runner.sh`, `.github/workflows/interop-matrix.yml` | **PASS** |
| **FR-B02** | Bonus | Live Telemetry & Observability (origin-guarded WS). | `backend/server.js` | **PASS** (403 on cross-origin verified live) |
| **FR-B03** | Bonus | RFC 7807 Upstream Bug Exporter. | `backend/server.js` | **PASS** |

---

## 3. Cryptographic Invariants & Negative Rejection Matrix

All rows re-executed this session against the running services. The **Evidence Source** column names the exact suite that fails if the protection regresses.

| Vector ID | Attack Description | Expected Rejection Code | Verification Source |
|:---|:---|:---|:---|
| **VEC-01** | Issuer signature bit-flip | `ERR_INVALID_ES256_SIGNATURE` | `test_e2e_local.js` (strict assertion) |
| **VEC-02** | kb `iat` backdated beyond skew | `ERR_KB_JWT_IAT_OUTSIDE_SKEW_WINDOW` | `test_e2e_local.js` |
| **VEC-03** | Cut-and-paste `sd_hash` desync | `ERR_KB_SD_HASH_MISMATCH` | `test_e2e_local.js` (VULN-02b strict) |
| **VEC-04** | Unbound disclosure injection | `ERR_UNBOUND_DISCLOSURE_DIGEST` | `test_e2e_local.js` |
| **VEC-05** | Expired credential | `ERR_CREDENTIAL_EXPIRED` | `test_e2e_local.js` |
| **VEC-06** | Recursive `_sd` nesting | `ERR_RECURSIVE_SD_NESTING_LIMIT_EXCEEDED` | `test_e2e_local.js` |
| **VEC-07** | INJIVER-1131 type mismatch | `ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE` | `test_e2e_local.js` (strict) |
| **VEC-08** | ASN.1 DER signature injection | `ERR_NON_P1363_SIGNATURE_LENGTH` | `test_e2e_local.js` |
| **REG-01** | Rogue self-signed `header.jwk` issuer | `ERR_UNTRUSTED_ISSUER` | `test_e2e_local.js` REGRESSION-01 |
| **REG-02** | **Genuine** single-use nonce replay (same nonce resubmitted) | `ERR_NONCE_ALREADY_CONSUMED` | `test_e2e_local.js` REGRESSION-02 (rewritten — previously tested missing-kb, not replay) + SEC-08 |
| **REG-03** | Garbage/unrecognized payload | `ERR_UNSUPPORTED_OR_MALFORMED_VP_TOKEN` | `test_e2e_local.js` REGRESSION-03 (strict) |
| **REG-04** | Tampered mdoc attribute | `ERR_MDOC_DIGEST_MISMATCH` | `test_mdoc_tamper_and_replay.js` MDOC-02 |
| **REG-05** | Deleted/non-integer mdoc `digestID` | `ERR_MALFORMED_ISSUER_SIGNED_ITEM` | MDOC-03 |
| **REG-06** | Omitted nonce (mdoc) | `ERR_MISSING_SESSION_NONCE` | MDOC-01 |
| **REG-07** | Omitted nonce (W3C VC) | `ERR_MISSING_SESSION_NONCE` | code-enforced (verifier) |
| **SEC-01** | Forged/unknown access token at `/credential` | `401 invalid_token` | `test_security_regression.js` SEC-01 (was exploitable: HTTP 200) |
| **SEC-02** | kb+jwt without `sd_hash` | `ERR_MISSING_SD_HASH` | SEC-02 (was exploitable: HTTP 200) |
| **SEC-03** | kb+jwt with foreign audience | `ERR_KB_JWT_AUD_MISMATCH` | SEC-03 (was exploitable: HTTP 200) |
| **SEC-04** | Presentation missing requested claims (UIN/fullName) | `ERR_REQUIRED_CLAIM_NOT_DISCLOSED` | SEC-04 (was exploitable: HTTP 200) |
| **SEC-05** | UIN violating `^[0-9]{12}$` pattern | `ERR_REQUIRED_CLAIM_NOT_DISCLOSED` | SEC-05 (was exploitable: HTTP 200) |
| **SEC-06** | Tampered ldp_vc proofValue | `ERR_INVALID_ED25519_PROOF_SIGNATURE` | SEC-06 (real crypto; `CORRUPT` special-case removed) |
| **SEC-07** | PII in persisted/served history `trace_blob` | redaction | SEC-07 (was leaking UIN/name/phone) |
| **SEC-10** | DPoP proof with `htm=GET` at `/token` | `invalid_dpop_proof` | SEC-10 (was exploitable: token issued) |
| **CSWSH** | Cross-origin WebSocket telemetry connection | HTTP 403 | live ws-client probe (403 / open / open) |

---

## 4. Verification Methodology & Reproducibility

```bash
# 1. Start live microservices (zero-docker orchestrator)
node scripts/start_local.js

# 2. 26-check conformance & chaos suite (fail-closed, code-specific assertions)
node scripts/test_e2e_local.js

# 3. Independent adversarial security suite (attacker-held keys, 10 probes)
node scripts/test_security_regression.js

# 4. mdoc tamper & replay suite (fail-closed, 4 scenarios)
node scripts/test_mdoc_tamper_and_replay.js

# 5. 8-lane concurrent interoperability matrix
bash scripts/cli_interop_runner.sh
```

All five suites exit nonzero on failure. The e2e suite can also bootstrap its own in-process services when none are running.

## 5. Verification Boundary (read this before citing statuses)

- **Verified by live execution:** everything in §3, the FEAT rows marked PASS, the four Node suites, the WS origin guard, SQLite persistence, and the zero-docker startup path.
- **Labeled simulation (by design):** W3C VC canonicalization (not URDNA2015), Walt.id/Inji-Web/Inji-Mobile selections (synthetic agent + local mock), live-Collab fallback after the PMS `.p12` boundary, mdoc DeviceSigned.
- **Unverified here:** Docker runtime (daemon offline on the audit machine — validated statically and in CI), interactive browser UX (no automation tool available — tsc/build/HTTP evidence only), real cross-ecosystem interop with an external non-MOSIP implementation.
