# Project Memory & Technical Knowledge Base
## Project: Inji Interoperability Playground (Inji-Playground)
### Hackathon: MOSIP Decode 2026 | Problem Statement 2 (High Complexity)

---

## 1. Project Context & Current State
- **Current Milestone**: Research & Verification Complete (All 50 technical & cryptographic questions verified).
- **Target Deadline**: October 26, 2026, 11:59 PM IST (5 Days Remaining).
- **Objective**: Deliver a 1st-place winning interoperability playground that proves cross-ecosystem compliance of the MOSIP Inji stack across OpenID4VCI (Draft 13), OpenID4VP (Draft 21–23), W3C VC JSON-LD, SD-JWT VC, and ISO 18013-5 mdoc.

---

## 2. Core Architecture & Cryptographic Stack

| Component | Technology | Rationale & Specifications |
| :--- | :--- | :--- |
| **BFF / Backend Runtime** | Node.js 20+ Fastify / Express + TypeScript | Native V8 runtime crypto, async WebSockets, ultra-low latency proxying. |
| **Frontend Framework** | React 18 + Vite + TypeScript | High performance, Monaco Editor integration, Tailwind / Vanilla CSS design system. |
| **State Management** | Zustand | Slices: `useMatrixStore` (topology), `useTelemetryStore` (active payloads), `useTamperStore` (failure vectors). |
| **Protocol Inspector** | Monaco Editor | Synchronized highlighting of Base64URL vs decoded JSON via character-offset delta decorations. |
| **Sequence Diagram** | Mermaid.js (Dynamic SVG) | Driven by React state array of WebSocket intercepted events (`type: INTERCEPT_EVENT`). |
| **Cryptographic Engine** | `jose` (v5+), `@sd-jwt/core`, `cbor-x` | Native ES256 / Ed25519 support in Node 20+, standard disclosure hashing, CBOR Tag 24 parsing. |
| **Storage Engine** | SQLite (`db/schema.sql`) | Persistent records in `test_runs` table with JSON trace blobs and latency metrics. |
| **Container Topology** | Docker Compose (`inji-net`) | Total memory under 1.5GB: UI (256M), BFF (512M), Mocks (256M). |

---

## 3. Verified MOSIP Infrastructure & Endpoints

### 3.1 Live Collab Sandbox
- **Mock Issuer Base URL**: `https://injicertify-mock.collab.mosip.net`
- **Relying Party / Verifier Base URL**: `https://injiverify.collab.mosip.net`
- **Issuer Metadata Path**: `/.well-known/openid-credential-issuer` (Unauthenticated open HTTP access).
- **Inji Certify Docker Image**: `mosipid/inji-certify-with-plugins:0.11.0`
  - Env vars: `mosip.certify.domain.url`, `mosip.certify.authorization.url`, `mosip.certify.authn.allowed-audiences`.
- **Inji Verify Docker Image**: `inji-verify-service:0.13.0`
- **Mimoto BFF Config**: `mimoto/docker-compose/config/mimoto-issuers-config.json`

### 3.2 Protocol Mechanics & Cryptographic Nuances
- **OpenID4VCI (Draft 13)**:
  - Offer Scheme: `openid-credential-offer://?credential_offer_uri=...`
  - Token Grant: `urn:ietf:params:oauth:grant-type:pre-authorized_code` (`pre-authorized_code` param).
  - Proof Object: `proof_type: "jwt"` containing `iss`, `aud`, `iat`, `nonce` (`aud` = credential issuer URL).
  - DPoP `ath` Validation: RFC 9449 requires `ath` (base64url-encoded sha256 hash of access token) inside DPoP proof at `/credential`. BFF dynamically computes and injects `ath`.
  - Spring Boot Jackson Deserializer: Strictly expects singular `"proof": { "proof_type": "jwt", "jwt": "..." }`. Sending Draft 14 `"proofs"` causes HTTP 400 deserialization failure.
  - Nonce Replay Prevention: `c_nonce` returned dynamically by issuer in `/token` response payload.
  - DPoP Token Binding Curve: Inji Certify backend enforces **ES256 (ECDSA P-256)** for DPoP and credential request proofs. EdDSA risks algorithmic rejection (`invalid_dpop_proof`). Headless agent must generate ephemeral P-256 keys.
  - Formats supported: `ldp_vc` (native), `vc+sd-jwt` (experimental), `mso_mdoc`.
  - Draft 13 vs Draft 14 breaking change: Draft 13 uses `credentials_supported` array; Draft 14 (Walt.id) uses `credential_configurations_supported` object.
- **OpenID4VP (Draft 21–23)**:
  - Cross-device QR: `openid4vp://?request_uri=https://...` (Claim-169 compliant). BFF hosts request and serves lightweight URI to avoid unreadable QR density.
  - Presentation Definition: DIF Presentation Exchange v2.0 (`input_descriptors`).
  - Selective Disclosure Disclosures: Object disclosures must be 3-element `[salt, claim_name, claim_value]`; array element disclosures must be 2-element `[salt, claim_value]`.
  - Response Mode: Live Inji Verify Collab sandbox defaults to standard unencrypted `direct_post` with `application/x-www-form-urlencoded` containing `vp_token` and `presentation_submission`. JWE encryption (`direct_post.jwt` via ECDH-ES+A256GCM) is an optional Chaos Monkey test vector.
  - HTTP 200 OK responds with inline success payload or `redirect_uri`.
  - HTTP 400 failure responds with `invalid_presentation` or `invalid_signature`.
  - Identity & DID: Native resolution of `did:web` and `did:jwk`. Client ID scheme: `redirect_uri` or `did`.
- **Fastify & Node 20 Runtime Settings**:
  - `bodyLimit: 5242880` (5MB) on `/direct_post` to handle large mDoc and SD-JWT cert chains without HTTP 413.
  - Native `URLSearchParams` parsing to protect Base64URL characters.
  - CORS strictly configured for `http://localhost:3000` and `http://127.0.0.1:3000`.
  - Pure JS `jsonld.js` for URDNA2015 canonicalization to prevent Alpine C++ `node-gyp` segmentation faults.
  - Memory leak prevention: Traces flushed synchronously to SQLite; memory references nulled out immediately.
  - Expiration clock-skew: Backdate `exp` and forward-date `nbf` by at least 300 seconds (5 mins) for negative testing.
  - 60-Second Judge Mode: "One-Click Automated Conformance Matrix" button for instant evaluation.
- **SD-JWT VC Cryptography**:
  - Disclosure formula: Base64URL(SHA-256(ASCII(JSON([salt, claim_name, claim_value])))) without padding.
  - Format: `<issuer_jwt>~<disclosure1>~...~<disclosureN>~<kb_jwt>`. If no KB-JWT, ends with trailing `~`.
  - Key Binding JWT: Requires `nonce` and `aud` bound to RP session.
  - Signing: ES256 (ECDSA P-256) default; `_sd_alg: "sha-256"`.
- **W3C VC JSON-LD**:
  - Signatures: `Ed25519Signature2020` and `JsonWebSignature2020`.
  - Canonicalization: URDNA2015 dataset canonicalization before signing.
- **ISO 18013-5 mdoc**:
  - Payload: Enclosed in CBOR Tag 24 (`#6.24`) wrapper enclosing a `COSE_Sign1` object with `MobileSecurityObject` (MSO).

---

## 4. Adversarial Tamper Engine Vectors
1. **Signature Bit-Flip**: Alter final byte of Base64URL signature (`replace_last_char_with_Z`) -> Triggers HTTP 400 `invalid_signature`.
2. **SD-JWT Disclosure Strip**: Truncate SD-JWT at first `~` delimiter -> Triggers HTTP 400 verification failure.
3. **KB-JWT Nonce Mutation**: Append random string to `nonce` in holder key binding -> Triggers HTTP 400 replay rejection.
4. **Expiration Backdating**: Modify `exp` claim to timestamp in past -> Triggers HTTP 400 expired credential error.

---

## 5. Telemetry & WebSocket Schema
- Framing: `{"type": "INTERCEPT_EVENT", "timestamp": "ISO8601", "direction": "INBOUND|OUTBOUND", "payload": {}, "latencyMs": 42}`
- Real-time proxy broadcast over WebSocket `ws://localhost:4000/telemetry`.

---

## 6. Hackathon Deliverables Tracker
- [x] Verified Research & 50 Architectural Questions Answered.
- [x] Core Contract Specifications (`openapi_spec.yaml`, `docker-compose.yml`, `db/schema.sql`).
- [x] Test Fixtures (`fixtures/sample_credentials.json`, `fixtures/tamper_vectors.json`).
- [x] Automation Harness (`scripts/cli_interop_runner.sh`, `.github/workflows/interop-matrix.yml`).
- [ ] Backend BFF Implementation (Express/Fastify + WebSockets + SQLite + Proxy).
- [ ] Mock Issuer (OpenID4VCI Draft 13 + W3C + SD-JWT).
- [ ] Mock Verifier (OpenID4VP Draft 21-23 + DIF PE 2.0).
- [ ] Frontend Application (React + Vite + Monaco + Mermaid + Zustand + Tamper UI).
- [ ] CLI Interop Runner execution & `INTEROP_MATRIX.md` generation.
- [ ] Documentation, Demo Video Script & Slide Deck.
