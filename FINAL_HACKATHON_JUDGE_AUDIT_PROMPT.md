# FINAL HACKATHON JUDGE & AUDIT MANDATE
## Official Evaluation of MOSIP Inji Conformance Laboratory (`Inji-Conformance-Lab`)
### Target Package: `mosip_inji_conformance_lab.zip` | Benchmark: MOSIP Decode 2026 - Problem Statement 02

---

## 1. JUDICIAL DIRECTIVE & EVALUATION PHILOSOPHY

You are acting as an elite **Senior Hackathon Judge**, **Principal Cryptographic Auditor**, and **Lead Identity Standards Architect** evaluating submissions for **MOSIP Decode 2026 - Problem Statement 02: Inji Playground & Conformance Suite**.

Your duty is to conduct a **rigorous, uncompromising, line-by-line evaluation** of the submission contained in `mosip_inji_conformance_lab.zip`.

> ### ZERO-NEGLIGENCE JUDICIAL RULES:
> 1. **Evaluate Like a Seasoned Industry Judge:** Grade strictly against the published criteria. Give no charity points, accept no hand-waving, and do not assume correctness without inspecting actual source code and runtime behavior.
> 2. **Expose AI Agent Hallucinations & Protocol Misconceptions:** Generative AI models frequently confuse identity protocols (e.g., Draft 13 vs Draft 14 proof schemas, ASN.1 DER vs IEEE P1363 padding, RFC 9901 `sd_hash` calculation, DPoP `cnf.jkt` thumbprint binding). You must actively probe for these domain-specific blind spots.
> 3. **Execute the 10-Step Sequential Verification Framework:** You must systematically evaluate all 10 steps defined in Section 3 before determining final scores.
> 4. **Fail-Closed Adversarial Stress Testing:** Verify that every security control rejects tampered inputs with strict, specific error codes rather than generic parser crashes.
> 5. **Inspect Full Surface Area:** Scrutinize the backend orchestration engine (`backend/server.js`), mock issuer (`mocks/issuer/server.js`), mock verifier (`mocks/verifier/server.js`), test runner (`scripts/test_e2e_local.js`), local daemon starter (`scripts/start_local.js`), database layer (`db/schema.sql`), and the frontend telemetry dashboard (`frontend/src/App.tsx`).

---

## 2. OFFICIAL HACKATHON EVALUATION CRITERIA & WEIGHTING

Score the software across the 4 official hackathon dimensions (0 to 100 total points):

| Evaluation Dimension | Weight | Target | Core Assessment Focus |
|---|:---:|:---:|---|
| **1. Functionality & Technical Completion** | **40%** | **38–40 pts** | Full OpenID4VCI (Draft 13) and OpenID4VP (Draft 21–23) end-to-end flows, dual credential formats (`vc+sd-jwt`, `dc+sd-jwt`, `ldp_vc`, `mso_mdoc`), 8-lane combinatorial matrix execution, persistent SQLite telemetry, live WebSocket streaming, and automated upstream RFC 7807 bug reporting. |
| **2. Architectural Innovation & Technical Approach** | **20%** | **19–20 pts** | Bidirectional cross-draft transpiler (Draft 13 $\leftrightarrow$ Draft 14), DIF PE 2.0 to DCQL (Draft 23) converter, RFC 9901 byte-exact `sd_hash` verification, 128-bit CSPRNG salt entropy with decoy digests, RFC 7638 DPoP `cnf.jkt` thumbprint sender-constraining, and RP-side INJIVER-1131 credential type mitigation. |
| **3. Usability, Developer Experience & Observability** | **20%** | **19–20 pts** | Real-time interactive UI dashboard (:3000) with dark cyber-minimalist aesthetics, interactive SVG sequence visualizer (Mermaid.js), real-time color-coded token anatomy inspector, privacy disclosure slider with QR density meter, and dedicated developer landing portals on ports :4000, :8080, and :8081. |
| **4. Code Quality, Modularity & Documentation** | **20%** | **19–20 pts** | Modular microservice architecture, comprehensive JSDoc/inline documentation, robust error boundaries, SQLite WAL mode with busy timeout handling, zero-Docker native startup (`node scripts/start_local.js`), and strict container memory discipline (< 1.5 GB RAM hard cap). |
| **TOTAL COMPOSITE SCORE** | **100%** | **95–100 pts** | **Minimum Passing Threshold for 1st Place Recommendation: $\ge 95.0$ / 100.0** |

---

## 3. THE 10-STEP RIGOROUS PROTOCOL & EDGE-CASE AUDIT FRAMEWORK

Before awarding any scores, execute the following 10-step auditing methodology. Each step represents a critical failure surface where typical implementations fail:

```
[STEP 1] Protocol Disambiguation & Anti-Hallucination Audit
    │
[STEP 2] Cryptographic Primaries, ASN.1 DER-to-P1363 & High-S Normalization
    │
[STEP 3] RFC 9901 SD-JWT Byte-Exact Wire Hashing & Disclosure Entropy
    │
[STEP 4] RFC 9449 DPoP Sender-Constraining (cnf.jkt & ath Cryptographic Binding)
    │
[STEP 5] Multi-Draft Transpilation Fidelity (OpenID4VCI & DCQL)
    │
[STEP 6] Relying Party Authorization & Credential Type Substitution (INJIVER-1131)
    │
[STEP 7] W3C VC JSON-LD Canonical Data Integrity & ISO 18013-5 mdoc Parsing
    │
[STEP 8] 8-Layer Adversarial Chaos Monkey Engine & Error Code Strictness
    │
[STEP 9] Concurrency, Event-Loop Non-Blocking I/O & Memory Footprint (<1.5GB)
    │
[STEP 10] Production Developer Experience, Live Telemetry & Upstream Filing
```

---

### Step 1: Protocol Disambiguation & Anti-Hallucination Audit
*Domain Trap:* AI agents frequently hallucinate that OpenID4VCI and OpenID4VP are stable monolithic RFCs. In reality, they are rapidly moving drafts with incompatible breaking changes across revisions.
- **Audit Requirement:**
  1. Verify whether the code distinguishes between OpenID4VCI **Draft 13** (singular `proof: { proof_type: "jwt", jwt: "..." }`, `format`, `credential_definition`) and **Draft 14** (plural `proofs: { jwt: [...] }`, `credential_configuration_id`, `credential_requests`).
  2. Verify whether OpenID4VP distinguishes between **DIF Presentation Exchange 2.0** (`presentation_definition`, `input_descriptors`) and **Draft 23 DCQL** (Digital Credentials Query Language: `credentials`, `meta.vct_values`, `meta.type_values`).
  3. Verify that the code handles both `vc+sd-jwt` and `dc+sd-jwt` without conflating their typ header constraints.

### Step 2: Cryptographic Primaries, ASN.1 DER-to-P1363 & High-$S$ Normalization
*Domain Trap:* OpenSSL / Node.js native ECDSA signatures emit ASN.1 DER formatting with variable length (70–72 bytes). Java Spring Boot / Nimbus JOSE in Inji Certify and Inji Verify strictly require 64-byte IEEE P1363 ($r \parallel s$). Furthermore, OpenSSL produces malleable signatures with $S > n/2$, which strict verifiers reject.
- **Audit Requirement:**
  1. Inspect `convertDerToP1363` in `backend/server.js` and `mocks/verifier/server.js`:
     - Does it parse sequence tag `0x30` and handle multi-byte ASN.1 lengths (`seqLen & 0x80`)?
     - When $r$ or $s$ is 33 bytes (leading `0x00` sign pad in signed two's complement integer encoding), does it strip the leading zero without bounds error?
     - When $r$ or $s$ is $\le 31$ bytes, does it left-pad with zero bytes to exactly 32 bytes big-endian?
     - Does it enforce Low-$S$ canonicalization ($S \le n/2$) using the secp256r1 group order $n$?
  2. Verify Ed25519 / EdDSA signature handling in `ldp_vc`: does it verify raw 64-byte Ed25519 signatures without hashing parameters (`crypto.verify(null, signingInput, key, sig)`)?

### Step 3: RFC 9901 SD-JWT Byte-Exact Wire Hashing & Disclosure Entropy
*Domain Trap:* Many implementations decode the disclosures, re-serialize them with `JSON.stringify()`, and re-hash. This breaks if whitespace, key order, or delimiter placement varies.
- **Audit Requirement:**
  1. Inspect `sd_hash` calculation in `mocks/verifier/server.js` and `backend/server.js`:
     - Is `sd_hash` computed over the exact raw substring preceding the Key Binding JWT (`tokenStr.slice(0, lastTildeIdx + 1)`)?
     - Does the parser reject any empty disclosure segment (`d.length === 0`) caused by consecutive tildes (`~~`) per RFC 9901 §4?
     - Does the verifier validate `issPay._sd_alg` (must be `sha-256`) and reject unsupported algorithms?
     - Does the disclosure parser detect and reject duplicate disclosures (`seenDisclosureDigests`)?
     - Does the issuer in `mocks/issuer/server.js` use $\ge 128$-bit CSPRNG salts (`crypto.randomBytes(16)`) and inject decoy digests to conceal attribute counts?

### Step 4: RFC 9449 DPoP Sender-Constraining (`cnf.jkt` & `ath` Binding)
*Domain Trap:* Verifying `ath` on a DPoP proof is useless if the verifier doesn't check that the DPoP key matches the key bound to the access token during issuance.
- **Audit Requirement:**
  1. Inspect `POST /token` in `mocks/issuer/server.js`:
     - Does it compute the RFC 7638 JWK thumbprint (`jkt`) of the client's DPoP public key (`computeRfc7638JwkThumbprint`)?
     - Does it bind `cnf: { jkt: boundJkt }` to the issued access token?
  2. Inspect `POST /credential` in `mocks/issuer/server.js`:
     - Does it verify that the DPoP proof's public key thumbprint matches the access token's `cnf.jkt`?
     - Does it normalize `htu` (stripping query/fragment and case-normalizing)?
     - Does it track `jti` in a bounded TTL cache to prevent replay within the clock window?

### Step 5: Multi-Draft Transpilation Fidelity (OpenID4VCI & DCQL)
*Domain Trap:* Transpilers often lose data when translating from plural batch formats to singular endpoints.
- **Audit Requirement:**
  1. Inspect `transpileVciRequest` in `backend/server.js`:
     - If a Draft 14 request contains multiple `credential_requests`, does it reject single-endpoint submissions with `ERR_DRAFT13_BATCH_REQUIRES_FANOUT`?
     - Does it resolve `credential_configuration_id` against the issuer's metadata into `format`, `vct`, and `credential_definition`?
  2. Inspect `transpilePe2ToDcql` in `backend/server.js`:
     - Does it correctly map DIF PE field paths into DCQL claims?
     - Does it populate `meta.vct_values` for SD-JWT and `meta.type_values` for JSON-LD?
     - Does it set `require_cryptographic_holder_binding: true`?

### Step 6: Relying Party Authorization & Credential Type Substitution (INJIVER-1131)
*Domain Trap:* Inji Verify v0.17.0 suffered from advisory INJIVER-1131, where any cryptographically valid VC was accepted regardless of whether its type matched what the Relying Party asked for.
- **Audit Requirement:**
  1. Inspect `POST /direct_post` in `mocks/verifier/server.js`:
     - Does the verifier validate the submitted credential's `vct` (for SD-JWT) or `type` (for W3C VC) against the requested presentation definition?
     - Does it reject mismatched credentials (e.g., `LifeInsuranceCredential` instead of `MosipIdentityCredential`) with `ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE`?
  2. Inspect multi-path JSONPath evaluation: does it evaluate fallback paths (`$.credentialSubject.UIN || $.vc.credentialSubject.UIN || $.UIN`)?

### Step 7: W3C VC JSON-LD Canonical Data Integrity & ISO 18013-5 mdoc Parsing
*Domain Trap:* Naively signing `JSON.stringify(credentialSubject)` leaves top-level fields (`expirationDate`, `issuer`) completely unsigned and forgeable.
- **Audit Requirement:**
  1. Inspect `ldp_vc` issuance and verification:
     - Does it use deterministic canonicalization (`computeLdpSigningInput`) hashing canonical proof options and canonical document separately?
     - Does the verifier validate `expirationDate` with clock-skew tolerance, rejecting expired credentials with `ERR_CREDENTIAL_EXPIRED`?
  2. Inspect mdoc handling: does the verifier accept ISO 18013-5 format structures?

### Step 8: 8-Layer Adversarial Chaos Monkey Suite & Error Code Strictness
*Domain Trap:* Weak test suites check `res.status === 400` without asserting error codes, allowing generic Express body-parser syntax errors to pass as security validations.
- **Audit Requirement:**
  1. Inspect `scripts/test_e2e_local.js` and `backend/server.js`:
     - Execute the 8 Chaos Monkey vectors:
       - `VEC-01`: Issuer Signature Bit-Flip $\implies$ `ERR_INVALID_ES256_SIGNATURE`
       - `VEC-02`: Key Binding Nonce/IAT Mismatch $\implies$ `ERR_KB_JWT_IAT_OUTSIDE_SKEW_WINDOW`
       - `VEC-03`: Cut-and-Paste `sd_hash` Desync $\implies$ `ERR_KB_SD_HASH_MISMATCH`
       - `VEC-04`: Unbound Disclosure Injection $\implies$ `ERR_UNBOUND_DISCLOSURE_DIGEST`
       - `VEC-05`: Expired Credential Presentation $\implies$ `ERR_CREDENTIAL_EXPIRED`
       - `VEC-06`: Malformed Recursive SD Nesting Loop $\implies$ `ERR_RECURSIVE_SD_NESTING_LIMIT_EXCEEDED`
       - `VEC-07`: INJIVER-1131 Credential Type Mismatch $\implies$ `ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE`
       - `VEC-08`: ASN.1 DER Signature Injection $\implies$ `ERR_NON_P1363_SIGNATURE_LENGTH`
     - Verify that every negative test asserts both HTTP status `400` **and** the specific error code.

### Step 9: Concurrency, Event-Loop Non-Blocking I/O & Memory Footprint (<1.5GB)
*Domain Trap:* Synchronous SQLite calls or unbuffered WebSockets lock the Node.js event loop; high-volume multi-megabyte payloads trigger V8 OOM crashes.
- **Audit Requirement:**
  1. Inspect `docker-compose.yml`:
     - Are container RAM limits explicitly defined?
     - Does the sum of limits across all 4 containers stay strictly below the 1,500 MB budget cap (configured to 920 MB: 240M + 280M + 200M + 200M)?
  2. Inspect `db/schema.sql` and `backend/server.js`:
     - Is SQLite operating in WAL mode (`PRAGMA journal_mode = WAL;`)?
     - Is `PRAGMA busy_timeout = 5000;` configured to prevent `SQLITE_BUSY` crashes?
  3. Inspect `/direct_post` upload concurrency in `mocks/verifier/server.js`:
     - Does it enforce an upload semaphore (`MAX_CONCURRENT_UPLOADS = 4`) on payloads $> 256\text{ KB}$ returning HTTP 429?
     - Does it reject payloads $> 5\text{ MB}$ with HTTP 413?

### Step 10: Production Developer Experience, Live Telemetry & Upstream Filing
*Domain Trap:* Many testbeds operate as black boxes with no human-readable telemetry or actionable bug reporting for upstream maintainers.
- **Audit Requirement:**
  1. Verify the web interface at `http://localhost:3000`:
     - Does it provide live WebSocket telemetry streaming with directional badges?
     - Does it feature an interactive Token Anatomy inspector with color-coded JWT segments?
     - Does it provide a Privacy Slider with real-time QR density and byte scannability calculations?
     - Does it render an asynchronous Mermaid sequence diagram of the 14-hop handshake?
     - Does the Judge Conformance Matrix execute all 8 permutations concurrently and display a 100% compliant badge?
  2. Verify developer portals on `:4000`, `:8080`, and `:8081` (no raw "Cannot GET" errors).
  3. Verify the Upstream RFC 7807 Defect Exporter (`POST /api/v1/export-issue`): does it emit copy-paste ready GitHub issue templates for `INJIVER-1131`, `Mimoto Missing Discovery`, and `Nimbus IEEE P1363 vs DER`?

---

## 4. DOMAIN-SPECIFIC AI AGENT HALLUCINATION CATALOG

As a judge, actively test for these 10 subtle misconceptions common in AI-generated identity codebases:

1. **The DER/P1363 Length Fallacy:** Assuming ASN.1 DER ECDSA signatures are always 70, 71, or 72 bytes and can be converted with fixed index offsets without inspecting the tag-length-value stream.
2. **The High-$S$ Blindspot:** Assuming any valid mathematical ECDSA signature $(r, s)$ is accepted by standard verifiers, overlooking that Java Nimbus JOSE strictly requires $s \le n/2$.
3. **The `sd_hash` Re-Serialization Error:** Assuming `sd_hash` is computed over `disclosures.join('~')` instead of the exact byte substring of the wire presentation preceding the kb-jwt.
4. **The Empty Tilde (`~~`) Mutation Hole:** Assuming splitting by `~` and filtering by `Boolean` is harmless, ignoring that consecutive tildes violate RFC 9901 §4.
5. **The DPoP `ath`-Only Illusion:** Assuming validating `ath` prevents credential theft, missing that without `cnf.jkt` thumbprint matching, an attacker can generate a new DPoP key and redeem stolen tokens.
6. **The Unsigned JSON-LD Expiration:** Assuming `Ed25519Signature2020` on `credentialSubject` protects the whole document, leaving `expirationDate` and `issuer` forgeable.
7. **The INJIVER-1131 Verification Bypass:** Believing cryptographic validity implies authorization compliance, allowing low-assurance credentials to satisfy high-assurance requests.
8. **The Express `+` Space Corruption:** Believing `replace(/ /g, '+')` is safe for base64url inputs, corrupting JSON-LD text fields containing real spaces.
9. **The Memory Allocation Myth:** Believing `--max-old-space-size=384` limits total RSS to 384MB, ignoring young-generation semi-spaces, C++ buffers, and OS overhead.
10. **The Silent Sandbox Fallback Lie:** Catching sandbox connection timeouts and silently falling back to local mocks while reporting `outcome: "PASS"` under `sandboxMode: "collab"`.

---

## 5. REQUIRED FORMAT OF YOUR FINAL JUDICIAL AUDIT REPORT

Your evaluation report must be returned in the following structured format:

### Part I: Scorecard & Judicial Verdict
- **Executive Summary:** High-level architectural verdict.
- **Quantitative Scorecard Table:**
  - Functionality & Technical Completion (0–40 pts)
  - Architectural Innovation & Technical Approach (0–20 pts)
  - Usability, Developer Experience & Observability (0–20 pts)
  - Code Quality, Modularity & Documentation (0–20 pts)
  - **Total Composite Score (0–100 pts)**
- **Hackathon Ranking Recommendation:** (1st Place Candidate / Finalist / Rejection).

### Part II: Step-by-Step Verification Findings (Steps 1 to 10)
For each of the 10 steps in Section 3, document:
- **Observed Implementation:** Specific file and line references.
- **Adversarial / Chaos Test Result:** Exact output from automated tests or manual probes.
- **Domain Hallucination Check:** Confirmation of whether any of the 10 pitfalls exist.
- **Step Assessment:** (SATISFIED / EXCEEDED / PARTIAL / FAILED).

### Part III: Defense of Edge Cases (Devil's Advocate Analysis)
Document how the system handles:
1. High-$S$ signature malleability across OpenSSL and Java Nimbus JOSE.
2. Syntactic vs. binding validation order on recursive selective disclosures.
3. Asymmetric container clock drift vs. strict `iat` validation.
4. Large URL-encoded presentation payloads without V8 heap OOM.
5. P-256 elliptic curve coordinate left-padding and sign-byte handling.

### Part IV: Upstream MOSIP Ecosystem Impact
- Assessment of the pre-loaded RFC 7807 GitHub defect templates.
- Assessment of the cross-draft transpilers for transitioning the ecosystem from Draft 13 to Draft 14 and DIF PE 2.0 to DCQL.

---

**BEGIN YOUR FINAL AUDIT OF `mosip_inji_conformance_lab.zip` NOW. BE RIGOROUS, CLINICAL, AND THOROUGH.**
