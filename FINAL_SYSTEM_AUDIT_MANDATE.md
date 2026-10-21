# ULTIMATE ZERO-TOLERANCE SYSTEM AUDIT MANDATE
## Project: MOSIP Inji Conformance & Interoperability Laboratory (`Inji-Conformance-Lab`)
## Objective: Undisputed 1st Place / Flawless Competitive Dominance (MOSIP Decode 2026 - PS02)

---

### Executive Directive for Deep Research Agent
Execute an exhaustive, top-to-bottom adversarial audit of the entire architecture, cryptographic engine, container topology, and protocol state machine. Apply **first-principles formal verification, invariant testing, and red-team fault analysis** across every layer. Identify all subtle failure modes, edge-case crashes, specification mismatches, and cryptographic vulnerabilities before a single line of backend or frontend code is locked in.

---

## 1. COMPREHENSIVE ARCHITECTURAL BLUEPRINT (BOTTOM-TO-TOP)

```
==========================================================================================
LAYER 7: JUDGE EVALUATION & EXECUTIVE UX
- Interactive 3-Lane Matrix: Issuer (Inji Certify / Mock VCI / External Walt.id)
                             Wallet (Inji Web / Inji Mobile QR / Headless Synthetic Agent)
                             Verifier (Inji Verify / Mock VP / External Verifier)
- Real-time Conformance Scorecard with SVG Certification Badge & Markdown Export
- Automated 1-Click Upstream GitHub Issue Generator (RFC 7807 Problem Details diagnostics)
==========================================================================================
LAYER 6: PRESENTATION & REAL-TIME OBSERVABILITY
- React 18 + Vite + TypeScript (Single-page dark cyber-minimalist design)
- Monaco Editor: Synchronized Base64URL/Hex <-> Decoded JSON with delta-decoration highlights
- Dynamic Animated Mermaid.js Sequence Visualizer: Step-by-step time-travel scrubber
- SD-JWT Visual Disclosure Tree: Real-time sha-256 verification of disclosed vs blinded claims
- ISO 18013-5 mdoc Inspector: Binary CBOR Tag 24 envelope & COSE_Sign1 structure breakdown
==========================================================================================
LAYER 5: ORCHESTRATION & STATE MACHINE (Fastify :4000)
- WebSocket Telemetry Hub (`/telemetry`): Low-latency `INTERCEPT_EVENT` streaming
- OpenID4VCI Draft 13 State Machine: Discovery -> Offer -> Token (DPoP) -> Proof -> Credential
- OpenID4VP Draft 21-23 State Machine: Auth Request (DIF PE 2.0) -> QR / Deep-link -> direct_post
- Cross-Draft Transpilation Bridge: Live on-the-fly translation between Draft 13 and Draft 14
- SQLite Trace Logger: Persistent records in `test_runs` with nanosecond latencies & trace JSON
==========================================================================================
LAYER 4: 5-LAYER ADVERSARIAL CHAOS MONKEY ENGINE
- Layer 1 (Crypto): Signature byte corruption, Algorithm confusion (`alg: "none"`), Curve injection
- Layer 2 (Temporal): Backdated `exp`, Future `nbf`/`iat`, Clock-skew boundary tests
- Layer 3 (Holder Binding): Mutated `kb_jwt.nonce`, Spoofed `aud`, Consumed `c_nonce` replay
- Layer 4 (Selective Disclosure): Disclosure stripping, Tampered claims, Orphaned digests
- Layer 5 (Transport): Malformed Content-Type, Missing parameters, Corrupted CBOR Tag 24 bytes
- Negative Assertion Engine: Validates that verifiers strictly fail-closed with HTTP 400
==========================================================================================
LAYER 3: HEADLESS SYNTHETIC WALLET AGENT
- Ephemeral Key-pair generation: SECP256R1 (P-256) for DPoP and Proofs; Ed25519 for W3C VCs
- DPoP Header Construction: `typ: "dpop+jwt"`, `htm`, `htu`, `jti`, `ath` (Access Token Hash)
- Holder Key Binding Assembly: `kb_jwt` generation with verifier `nonce` and `aud`
==========================================================================================
LAYER 2: CRYPTOGRAPHIC PRIMITIVES & ENCODING ENGINES
- `jose` (v5+): Native V8 runtime WebCrypto for ES256, EdDSA, and JWE (ECDH-ES + A256GCM)
- `@sd-jwt/core`: Canonical RFC disclosure hashing: Base64URL(SHA-256(ASCII(JSON([salt, k, v]))))
- `cbor-x`: Fast binary decoding of Tag 24 (`#6.24`) envelopes and COSE_Sign1 MSO payloads
- IEEE P1363 vs DER conversion: Strict 64-byte raw `r || s` signature formatting for ES256
==========================================================================================
LAYER 1: INFRASTRUCTURE, NETWORKING & RUNTIME
- Docker Compose: 3-container topology (`inji-lab-ui`, `inji-lab-bff`, `mock-certify`) on `inji-net`
- Strict RAM Cap: <1.5GB total (UI: 256M, BFF: 512M, Mocks: 256M)
- V8 Memory Flags: `--max-old-space-size=384 --optimize_for_size --max-semi-space-size=16`
- Network Isolation: Bridge network `inji-net` with dual loopback / container DNS routing
==========================================================================================
```

---

## 2. ADVANCED ADVERSARIAL AUDIT CHECKLIST: 10 HIGH-RISK FAILURE VECTORS

Please scrutinize the following 10 edge cases where identity and credential platforms most commonly crash or fail conformance:

### 1. DPoP Access Token Hash (`ath`) Binding in Draft 13 vs Draft 14
- **The Risk**: When the wallet presents a DPoP-bound access token to the `/credential` endpoint, RFC 9449 requires calculating the base64url-encoded SHA-256 hash of the access token and binding it inside the DPoP proof JWT as `ath`.
- **Audit Question**: Does MOSIP Inji Certify 0.11.0 strictly validate `ath` in the DPoP proof at `/credential`, or does it only validate the `c_nonce` and key thumbprint (`jkt`)? What happens if `ath` is omitted?

### 2. IEEE P1363 vs ASN.1 DER ECDSA Signature Formatting
- **The Risk**: OpenSSL and Java Spring Boot crypto providers often default to ASN.1 DER-encoded signatures for ECDSA (variable length 70–72 bytes), whereas JWS RFC 7515 and WebCrypto mandate IEEE P1363 format (concatenation of zero-padded `r` and `s`, exactly 64 bytes for P-256).
- **Audit Question**: Does Inji Certify emit IEEE P1363 or DER signatures in its ES256 tokens? What signature formatting conversion must our BFF enforce to guarantee seamless parsing across WebCrypto / `jose`?

### 3. URDNA2015 Dataset Canonicalization for W3C JSON-LD
- **The Risk**: Inji Certify uses `Ed25519Signature2020` for W3C VCs, which requires canonicalizing the JSON-LD document using the URDNA2015 algorithm (RDF dataset normalization) before computing the SHA-256 digest.
- **Audit Question**: Can Node 20 handle URDNA2015 canonicalization reliably without heavy C++ native dependencies, or should the laboratory utilize a pure JS canonicalizer (e.g., `jsonld.js`) to guarantee deterministic cross-platform execution in Alpine Docker?

### 4. Cross-Device QR Code URI Scheme & URL Length Boundaries
- **The Risk**: When testing the cross-device flow with a real Inji Mobile wallet scanning a QR code on the desktop monitor, mobile camera lenses cannot decode QR codes with >500 characters of density.
- **Audit Question**: What is the exact URI scheme that Inji Mobile Wallet parses for OpenID4VP? Does it use `openid4vp://?request_uri=https://...` or plain `https://...?request_uri=...`? How does Inji Verify compress or proxy the `presentation_definition` via Claim-169?

### 5. `application/x-www-form-urlencoded` vs Multipart in `/direct_post`
- **The Risk**: OpenID4VP Draft 21–23 specifies that the response must be submitted to `/direct_post` with `application/x-www-form-urlencoded`. However, large Verifiable Presentations (especially mDoc binaries or VCs with extensive credential subjects) can exceed HTTP body limits or trigger URL-encoding corruption of Base64URL characters (e.g. `+` being interpreted as space if improperly handled).
- **Audit Question**: What are the exact parser configurations required in Fastify for `/direct_post` to ensure that incoming `vp_token` and `presentation_submission` parameters never get corrupted or truncated?

### 6. Selective Disclosure Claims Discrepancy: Salt Delimiters & Types
- **The Risk**: According to `draft-ietf-oauth-sd-jwt-vc`, a disclosure array is `[salt, claim_name, claim_value]`. For array elements, it is `[salt, claim_value]`.
- **Audit Question**: How does Inji Verify handle selectively disclosed array elements versus object properties? If a disclosure contains nested JSON objects, does Inji Verify require the child object to be canonicalized with sorted keys before disclosure hash verification?

### 7. Container Network Routing (`inji-net`) vs Browser Host Resolution
- **The Risk**: When the frontend running in the user's host browser requests `http://inji-lab-bff:4000`, the host OS cannot resolve the Docker container name `inji-lab-bff`. Conversely, if the backend issues redirects to `localhost:4000`, other containers inside the Docker network cannot reach it via `localhost`.
- **Audit Question**: What is the bulletproof network configuration pattern for Docker Compose to ensure seamless communication both from the host browser (via `localhost`) and between inter-container communications (via `inji-net` service names) without triggering CORS or connection refused errors?

### 8. V8 Memory Leaks under Continuous Chaos Fuzzing
- **The Risk**: Running 100+ rapid cryptographic tamper tests in succession produces thousands of discarded `Buffer` and `Uint8Array` allocations from signature bit-flipping and hash calculation.
- **Audit Question**: Does our configured `--max-old-space-size=384 --optimize_for_size --max-semi-space-size=16` guarantee total stability under continuous looping, or are explicit buffer re-use / manual garbage collection hooks needed in the Node.js Fastify process?

### 9. Clock-Skew Tolerance in Expiration Checks
- **The Risk**: Cryptographic verifiers often allow a 60-second or 300-second clock-skew window (`clockSkew: 60s`). When the Chaos Monkey Engine tests backdated `exp` injection, if it only backdates by 10 seconds, Inji Verify may still accept the credential as valid!
- **Audit Question**: What is the default clock-skew tolerance in Inji Verify? By how many seconds/minutes must the Chaos Monkey Engine backdate `exp` (and forward-date `nbf`) to guarantee an unambiguous, deterministic HTTP 400 rejection?

### 10. Conformance Scorecard & Evidence Generation for Hackathon Judges
- **The Risk**: Judges spend an average of 5–10 minutes evaluating each submission. If they have to dig through logs or execute manual commands, the score drops.
- **Audit Question**: How should the final Interoperability Scorecard be structured in both the Web UI and the generated `INTEROP_MATRIX.md` so that a judge can verify 100% compliance, zero regressions, and full resilience in under 60 seconds?

---

## 3. INSTRUCTION FOR RESEARCH AGENT

Audit the entire system plan against the 10 failure vectors above. Provide:
1. Exact cryptographic, network, and parser validations for each vector.
2. The definitive "Zero-Tolerance" sign-off confirming our architectural specifications are completely bulletproof.
3. Any single remaining nuance that could prevent this project from taking 1st place in MOSIP Decode 2026.
