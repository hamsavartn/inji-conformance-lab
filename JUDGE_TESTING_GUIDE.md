# MOSIP INJI CONFORMANCE LABORATORY — JUDGE TESTING & AUDITING GUIDE
## Comprehensive Evaluation Manual for Hackathon Judges & Security Auditors
### Target Artifact: `mosip_inji_conformance_lab.zip` (MOSIP Decode 2026 - Problem Statement 02)

---

## 1. SUBMISSION OVERVIEW

The **MOSIP Inji Conformance Laboratory** is a complete, production-hardened interoperability testbed and conformance oracle designed for certifying digital wallets, credential issuers, and verifiers against the **MOSIP Inji ecosystem** (Inji Certify, Inji Verify, Inji Wallet, and Mimoto).

### Architecture at a Glance:
```
┌────────────────────────────────────────────────────────────────────────┐
│                   MOSIP INJI CONFORMANCE LABORATORY                    │
│                                                                        │
│   ┌─────────────────────┐                 ┌────────────────────────┐   │
│   │  Mock Inji Certify  │                 │    Mock Inji Verify    │   │
│   │     (Port 8080)     │                 │      (Port 8081)       │   │
│   │  OpenID4VCI Draft13 │                 │  OpenID4VP Draft21-23  │   │
│   └──────────▲──────────┘                 └───────────▲────────────┘   │
│              │                                        │                │
│              │     ┌────────────────────────────┐     │                │
│              └─────┤  Hardened BFF Hub (:4000)  ├─────┘                │
│                    │  • Conformance Engine      │                      │
│                    │  • 8-Lane Matrix Runner    │                      │
│                    │  • Cross-Draft Transpiler  │                      │
│                    │  • WebSocket Telemetry     │                      │
│                    │  • WAL SQLite Persistence  │                      │
│                    └─────────────▲──────────────┘                      │
│                                  │                                     │
│                    ┌─────────────┴──────────────┐                      │
│                    │  Interactive Web UI (:3000)│                      │
│                    │  • Token Anatomy Visualizer│                      │
│                    │  • Privacy Slider & QR Meter│                     │
│                    │  • Mermaid Sequence Graph  │                      │
│                    │  • Conformance Scorecard   │                      │
│                    └────────────────────────────┘                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. HOW TO UNPACK & RUN THE SYSTEM

### Step 1: Unzip the Submission Archive
```bash
unzip mosip_inji_conformance_lab.zip -d inji-conformance-lab
cd inji-conformance-lab
```

### Step 2: Choose Execution Mode

#### Option A: Headless Verification Suites (Zero-Config, Instant Audit)
Run these five suites **in order**. All are fail-closed: any failure exits nonzero and prints which check broke.

```bash
# 1. Chain of Verification — 26 checks: DPoP, sd_hash, P1363 signatures,
#    8 chaos vectors, transpilers, SQLite, genuine nonce replay, mdoc lifecycle
node scripts/test_e2e_local.js

# 2. Independent Adversarial Security Suite — 10 probes driven with attacker-held keys
#    (forged tokens, missing sd_hash, foreign audience, withheld claims, bad UIN,
#     tampered Ed25519 proofs, PII redaction, replay on both formats, wrong DPoP htm)
node scripts/test_security_regression.js

# 3. ISO/IEC 18013-5 mdoc adversarial suite — 4 scenarios (fail-closed)
node scripts/test_mdoc_tamper_and_replay.js

# 4. Core invariants walkthrough (garbage rejection, replay, forged nonce, rogue issuer)
node scripts/verify_six_tests.js

# 5. CI Interop Matrix Runner — 8 concurrent lanes, writes INTEROP_MATRIX.md
bash scripts/cli_interop_runner.sh
```

*Expected Result (verified 2026-10-24 from a cold start):*
- Suite 1: **26/26 Checks Passed (100%)**, exit code 0
- Suite 2: **10/10 SECURITY REGRESSION RESULTS PASSED**, exit code 0
- Suite 3: **4/4 MDOC ADVERSARIAL RESULTS PASSED**, exit code 0
- Suite 4: all statuses match the "expect" annotations, exit code 0
- Suite 5: **Compliance Score: 100% (8/8 Lanes Passed)**, exit code 0
- Total: **51 distinct checks**, ~30 seconds combined

If services are not running, suite 1 and 4 will bootstrap their own in-process servers automatically; suites 2, 3, and 5 require services started per Option B.

#### Option B: Zero-Docker Native Microservices (Interactive Web Testing)
Launches all 4 microservices concurrently:
```bash
node scripts/start_local.js
```
⚠️ **Note:** on Windows this performs a pre-flight that **force-kills whatever is listening on ports 3000/4000/8080/8081**. Close unrelated apps on those ports first.

All four services bind immediately:
- 🌐 **Interactive Web UI:** `http://localhost:3000`
- 🚀 **BFF Orchestration Gateway:** `http://localhost:4000`
- 📡 **Live Telemetry Stream:** `http://localhost:4000/telemetry`
- 🏛️ **Mock Inji Certify (Issuer):** `http://localhost:8080`
- 🛡️ **Mock Inji Verify (Verifier):** `http://localhost:8081`

*Health check:* all four URLs above must return HTTP 200 (`curl -s -o /dev/null -w "%{http_code}" URL`).

#### Option C: Production Docker Compose Mode (Hard Container Constraints)
Enforces a hard **920 MB** RAM ceiling across all 4 containers (well under the 1,500 MB hackathon budget):
```bash
docker compose up --build
```
Mock services now have healthchecks and the BFF waits for them (`depends_on: service_healthy`). The CI pipeline (`.github/workflows/interop-matrix.yml`) runs this exact flow plus the CLI runner on every push.

---

## 3. VERIFYING THE 10 CRITICAL PROTOCOL INVARIANTS

Judges and auditors can verify the core protocol and cryptographic invariants using direct CLI curl commands:

### 1. OpenID4VCI Issuer Discovery (`/.well-known/openid-credential-issuer`)
```bash
curl -s http://localhost:8080/.well-known/openid-credential-issuer | jq .
```
*Verifies:* Standard OpenID4VCI metadata, `credential_issuer`, `token_endpoint`, `credential_endpoint`, and supported credential formats (`vc+sd-jwt`, `dc+sd-jwt`, `ldp_vc`, `mso_mdoc`).

### 2. DPoP Sender-Constraining (`cnf.jkt` Binding)
```bash
# 1. Fetch pre-authorized credential offer
OFFER_CODE=$(curl -s http://localhost:8080/credential-offer | jq -r '.credential_offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]')

# 2. Exchange pre-authorized code for DPoP access token (binds cnf.jkt)
TOKEN_RES=$(curl -s -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=$OFFER_CODE")

echo $TOKEN_RES | jq .
```
*Verifies:* Token response contains `token_type: "DPoP"`, `access_token`, and `c_nonce`.

### 3. OpenID4VP Authorization Request Generation (`/api/v1/request`)
```bash
curl -s -X POST http://localhost:8081/api/v1/request \
  -H "Content-Type: application/json" \
  -d '{"format":"vc+sd-jwt"}' | jq .
```
*Verifies:* Emits standard OpenID4VP authorization request with DIF Presentation Exchange 2.0 `input_descriptors`, `fields` with multi-path JSONPath expressions, `nonce`, and Claim-169 QR scheme.

### 4. Full Concurrent 8-Lane Conformance Matrix Execution
```bash
curl -s -X POST http://localhost:4000/api/v1/orchestrate/full-matrix | jq .summary
```
*Verifies:* Executes all 8 combinatorial permutations (Issuer $\times$ Wallet $\times$ Verifier $\times$ Drafts) simultaneously:
```json
{
  "totalTests": 8,
  "passed": 8,
  "failed": 0,
  "compliancePercentage": 100,
  "conformanceBadge": "https://img.shields.io/badge/MOSIP--Inji--Conformance-100%25%20COMPLIANT-brightgreen"
}
```

### 5. Adversarial Chaos Monkey Rejection (VEC-03: `sd_hash` Desync)
```bash
# Issue credential
CRED=$(curl -s -X POST http://localhost:4000/api/v1/orchestrate/issue \
  -H "Content-Type: application/json" \
  -d '{"issuerType":"mock-vci","credentialFormat":"vc+sd-jwt"}' | jq -r .credential)

# Submit with VEC-03 tamper config
curl -s -X POST http://localhost:4000/api/v1/orchestrate/verify \
  -H "Content-Type: application/json" \
  -d "{\"verifierType\":\"mock-vp\",\"credential\":\"$CRED\",\"format\":\"vc+sd-jwt\",\"tamperConfig\":{\"vector\":\"VEC-03\"}}" | jq .
```
*Verifies:* Fails closed with `HTTP 400` and specific error description: `ERR_KB_SD_HASH_MISMATCH: Cut-and-paste disclosure tampering detected`.

### 6. INJIVER-1131 Credential Type Mismatch Rejection
```bash
curl -s -X POST http://localhost:4000/api/v1/orchestrate/verify \
  -H "Content-Type: application/json" \
  -d "{\"verifierType\":\"mock-vp\",\"credential\":\"$CRED\",\"format\":\"vc+sd-jwt\",\"tamperConfig\":{\"vector\":\"VEC-07\"}}" | jq .
```
*Verifies:* Rejects mismatched credential with `HTTP 400` and `ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE: Unexpected credential type LifeInsuranceCredential`.

### 7. Upstream RFC 7807 GitHub Bug Exporter
```bash
curl -s -X POST http://localhost:4000/api/v1/export-issue \
  -H "Content-Type: application/json" \
  -d '{"issueType":"INJIVER-1131","module":"inji-verify"}' | jq -r .markdown
```
*Verifies:* Emits formatted RFC 7807 GitHub defect report with reproduction curl commands, expected vs actual behavior, and JSON traces.

### 8. Cross-Draft OpenID4VCI Transpilation
```bash
curl -s -X POST http://localhost:4000/api/v1/transpile \
  -H "Content-Type: application/json" \
  -d '{"protocol":"openid4vci","targetSchema":"draft-14","sourceData":{"proof":{"proof_type":"jwt","jwt":"mock.jwt"}}}' | jq .
```
*Verifies:* Transpiles Draft 13 singular `proof` to Draft 14 plural `proofs: { jwt: [...] }` dictionary.

### 9. OpenID4VP DIF PE 2.0 to DCQL Transpilation
```bash
curl -s -X POST http://localhost:4000/api/v1/transpile \
  -H "Content-Type: application/json" \
  -d '{"protocol":"openid4vp","targetSchema":"dcql"}' | jq .
```
*Verifies:* Transpiles DIF Presentation Definition into Draft 23 DCQL format, populating `meta.vct_values`, `meta.type_values`, and `require_cryptographic_holder_binding: true`.

### 10. Persistent SQLite Telemetry History
```bash
curl -s http://localhost:4000/api/v1/history | jq '.runs | length'
```
*Verifies:* Returns persistent test run records from SQLite database (`db/conformance.db`) operating in WAL mode.

---

## 4. INTERACTIVE UI DASHBOARD GUIDE (`http://localhost:3000`)

Navigate to `http://localhost:3000` to interact with the full suite:

1. **Header Bar:**
   - Real-time `Telemetry WS: LIVE` indicator with glowing green pulse.
   - `Run Judge Conformance Matrix` button that triggers all 8 permutations concurrently.
2. **Actor Selection Topology:**
   - Credential Issuer: Select between Local Mock Inji Certify, Live MOSIP Collab Certify, or External Walt.id.
   - Wallet / Holder: Select between Automated Synthetic Agent, Inji Web Browser Bridge, or Inji Mobile QR Bridge.
   - Relying Party: Select between Local Mock Inji Verify or Live MOSIP Collab Inji Verify.
3. **Execution Controls:**
   - Format Dropdown: Toggle between `vc+sd-jwt`, `dc+sd-jwt`, `ldp_vc`, and `mso_mdoc`.
   - Chaos Fuzzer: Select from 8 negative vectors (`VEC-01` through `VEC-08`).
   - `Execute Handshake Flow` button.
4. **Real-time Status Banner:**
   - Green banner displays: `FULL LIFECYCLE HANDSHAKE VERIFIED (HTTP 200 OK)` with `Subject`, `Format`, and `sd_hash Verified: TRUE`.
   - If a Chaos vector is selected, displays: `NEGATIVE ASSERTION CONFIRMED (HTTP 400 REJECTION AS EXPECTED)` with exact cryptographic error code.
   - Direct button: `Export GitHub Bug Report` opening the RFC 7807 bug dialog.
5. **Lower Workbench Tabs:**
   - **Tab 1: Token Anatomy & Claims:** Visual color-coded legend of JWT header, claims, issuer signature, salted disclosures, and key-binding JWT.
   - **Tab 2: Privacy Slider & QR Density Meter:** Interactive toggles to disclose or redact claims, displaying real-time ISO/IEC 18004 QR byte density and scannability scores.
   - **Tab 3: Cross-Draft Transpiler:** Interactive JSON transpilation between OpenID4VCI Draft 13/14 and OpenID4VP DIF PE/DCQL.
   - **Tab 4: Dynamic Sequence Diagram:** Asynchronous Mermaid sequence diagram tracing all 14 end-to-end hops.
   - **Tab 5: Telemetry Stream:** Real-time log of WebSocket frames with directional badges and response latencies.
   - **Tab 6: Conformance Scorecard:** Comprehensive 8-lane matrix results table with SVG compliance badge.

---

## 5. RESOURCE BUDGET & CONCURRENCY CONSTRAINTS

| Resource Metric | Hackathon Constraint | Laboratory Actual | Status |
|---|:---:|:---:|:---:|
| **Total Container RAM** | $< 1,500\text{ MB}$ | **920 MB** ($240 + 280 + 200 + 200\text{ MB}$) | ✅ Strictly Enforced |
| **V8 Old-Space Heap** | N/A | $\le 224\text{ MB}$ per process | ✅ Optimized |
| **Active Idle RSS** | N/A | **~15 MB** V8 Heap Used | ✅ Ultra-Lightweight |
| **Max Payload Size** | $5\text{ MB}$ cap | $5\text{ MB}$ ceiling with $4\times$ concurrency semaphore | ✅ DoS Hardened |
| **WebSocket Backpressure** | N/A | $512\text{ KB}$ per-client threshold (auto-drop slow consumers) | ✅ Event Loop Protected |
| **Database Concurrency** | N/A | WAL mode + $5,000\text{ms}$ busy timeout | ✅ Zero Locks |

---

## 6. HOW TO KNOW IT IS WORKING PERFECTLY — Acceptance Checklist

Work top to bottom. Every line is observable in a terminal or browser; nothing requires trusting a report.

### Level 1 — Services are alive (1 min)
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/health   # expect 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/health   # expect 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:4000/api/v1/health  # expect 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/          # expect 200
```

### Level 2 — All 51 automated checks pass (~30 s)
Run the five suites from §2 Option A. **The definition of green:**
- Every line prints `✅ PASS` (no `❌ FAIL`).
- The summary lines read exactly: `26/26 CHECKS PASSED (100%)`, `SECURITY REGRESSION RESULTS: 10/10 PASSED`, `MDOC ADVERSARIAL RESULTS: 4/4 PASSED`, `Compliance Score: 100% (8/8 Lanes Passed)`.
- `echo $?` after each suite prints `0`.
If any suite exits nonzero, the printed `[CHECK-ID] ❌ FAIL` line names exactly what regressed — bring that line to the maintainers.

### Level 3 — Adversarial rejection is real, not cosmetic (2 min)
These prove the security is enforced by real cryptography, by directly attacking the endpoints:
```bash
# 1. A garbage presentation must be rejected (never silently accepted)
curl -s -X POST http://localhost:8081/direct_post -d "vp_token=GARBAGE" | jq .
#    expect: {"error":"invalid_presentation","error_description":"ERR_UNSUPPORTED_OR_MALFORMED_VP_TOKEN..."}

# 2. An unknown access token must NOT yield a credential (401)
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/credential \
  -H "Content-Type: application/json" -H "Authorization: DPoP FORGED_TOKEN" \
  -d '{"format":"vc+sd-jwt"}'
#    expect: 401

# 3. A cross-origin WebSocket must be refused (403)
node -e "new (require('./backend/node_modules/ws'))('ws://localhost:4000/telemetry',{headers:{Origin:'https://evil.example'}}).on('error',e=>console.log(e.message))"
#    expect: Unexpected server response: 403

# 4. History must not leak PII (no full UIN visible)
curl -s http://localhost:4000/api/v1/history | jq '[.runs[].trace_blob] | map(select(test("123456789012"))) | length'
#    expect: 0
```

### Level 4 — Interactive UI (5 min, manual)
1. Open `http://localhost:3000` — Telemetry WS badge must show **LIVE**.
2. Press **Run Judge Conformance Matrix** — scorecard must show **100% CONFORMANCE CERTIFIED** with 8 green PASS rows and confetti.
3. Select Chaos Fuzzer **VEC-05** → **Execute Handshake Flow** — banner must read **NEGATIVE ASSERTION CONFIRMED** with `ERR_CREDENTIAL_EXPIRED`.
4. **Token Anatomy** tab — every disclosure card must show a green **SHA-256 MATCH** badge (computed in your browser, not hardcoded).
5. **Privacy Slider** — uncheck the UIN claim, re-run: the verifier must now **reject** with `ERR_REQUIRED_CLAIM_NOT_DISCLOSED` (this is correct PE 2.0 behavior — the verifier asked for the UIN).
6. Open `http://localhost:4000/telemetry` in a second tab, re-run a flow, and watch live frames appear.

### Honest boundaries — what "working perfectly" does NOT claim
- **Wallet / Walt.id / Inji Web / Inji Mobile selections** execute through the built-in synthetic agent and local mock (labeled in the UI) — they demonstrate protocol mechanics, not integration with those external products.
- **Live MOSIP Collab** lanes probe the real sandbox discovery, then fall back to the local mock at the PMS `.p12` auth boundary (visible in telemetry).
- **W3C VC (ldp_vc)** uses simplified deterministic canonicalization, not URDNA2015 Data Integrity conformance.
- **Docker mode** is validated statically and by CI; if your Docker Desktop daemon is stopped, start it before Option C.
- No system is bug-free: what this checklist establishes is that every protection claimed has a test that fails loudly if it regresses.
