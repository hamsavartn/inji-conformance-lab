# MOSIP Inji Conformance Laboratory — Independent Audit, Remediation & Release Readiness Report

**Project:** Inji Interoperability Playground / Conformance Laboratory (`Inji-Conformance-Lab`)
**Hackathon:** MOSIP Decode 2026 — Problem Statement 02 (High Complexity)
**Audit round:** Independent re-audit with live-execution evidence (supersedes the earlier report of the same name, whose claims were re-verified from scratch rather than trusted)
**Audit date:** 2026-10-24
**Auditor stance:** Every prior claim was treated as unverified until reproduced against the running system. New adversarial probes with attacker-held keys were used to confirm or refute suspected defects before and after remediation.

---

## A. Executive Summary

### What was inspected
All four services (`backend/server.js` BFF+telemetry, `mocks/issuer/server.js` OpenID4VCI, `mocks/verifier/server.js` OpenID4VP, `frontend/src/App.tsx` React UI), all test harnesses (`scripts/test_e2e_local.js`, `scripts/test_mdoc_tamper_and_replay.js`, `scripts/verify_six_tests.js`, `scripts/cli_interop_runner.sh`), Docker/CI configuration (`docker-compose.yml`, `.github/workflows/interop-matrix.yml`), dependency manifests, SQLite persistence, and the PRD/README documentation.

### What was actually executed (highlights)
- The three Node services were started and exercised over real HTTP/WebSocket for the entire session.
- `node scripts/test_e2e_local.js` — **26/26 PASS** (reproduced pre-fix; re-run post-fix with strengthened assertions).
- `node scripts/test_mdoc_tamper_and_replay.js` — **4/4 PASS** (upgraded from a print-only script to fail-closed assertions).
- `node scripts/test_security_regression.js` — **new auditor-written suite, 10/10 PASS post-fix** (was 3/10 pre-fix; the 7 failures were live confirmations of real defects).
- `bash scripts/cli_interop_runner.sh` — **8/8 lanes, exit 0**.
- `npx tsc --noEmit` (frontend) — exit 0; `npm run build` — success; `node --check` on all JS — clean.
- `npm audit` — 1 HIGH (body-parser DoS) found in all three services and **fixed** (1.20.8 → 1.20.9, re-verified 0 vulnerabilities); frontend 2 LOW (katex/mermaid) documented as accepted risk.
- WebSocket CSWSH guard verified live: malicious origin → HTTP 403; localhost origin → open.
- Docker **runtime** test **blocked**: Docker CLI 29.7.2 is installed but the Docker Desktop daemon is not running on this machine. `docker compose config` validates statically. No runtime container claim is made.

### Major defects found (confirmed by live adversarial execution, then fixed)
1. **Issuer accepted forged access tokens** — `/credential` issued credentials with a completely unknown `Authorization` token, bypassing DPoP sender-constraining (`cnf.jkt`) entirely. → now `401 invalid_token`.
2. **kb+jwt without `sd_hash` accepted** — RFC 9901 §5.2 violation; the key binding was not bound to the presented disclosures. → now `400 ERR_MISSING_SD_HASH`.
3. **kb+jwt audience never validated** — a binding JWT minted for a foreign verifier audience was accepted. → now `400 ERR_KB_JWT_AUD_MISMATCH`.
4. **Presentation Exchange constraints never enforced** — a presentation disclosing *zero* requested claims, or a UIN violating the requested `^[0-9]{12}$` pattern, verified successfully. → now `400 ERR_REQUIRED_CLAIM_NOT_DISCLOSED` (SD-JWT and W3C VC paths).
5. **ldp_vc fail-open signature path** — if the trusted issuer's JWKS contained no Ed25519 key, W3C VC signature verification was silently skipped and the credential accepted. → now fail-closed (`ERR_UNTRUSTED_ISSUER_KEY`). Also removed a special-case `proofValue.includes('CORRUPT')` string check that stood in for real tamper detection.
6. **PII persisted and served unredacted** — the verifier's full response (UIN, name, phone) was stored in `test_runs.trace_blob` and served by `GET /api/v1/history`. → sanitized at write and redacted at read (verified).
7. **DPoP proofs not bound at `/token`** — `htm`/`htu`/`iat` unchecked, `jti` replay cache unused at the token endpoint. → enforced; `htm=GET` proof now rejected.
8. **Telemetry viewer XSS** — the in-browser `/telemetry` monitor interpolated attacker-influenced payloads via `innerHTML`. → rebuilt with DOM `textContent`.
9. **UI fabricated results** — scorecard header hardcoded "100% CONFORMANCE CERTIFIED" regardless of outcome; anatomy tab showed hardcoded "SHA-256 MATCH" badges without computing anything. → scorecard now renders the real percentage (confetti only on 100); disclosure digests are now genuinely recomputed client-side (`UNBOUND DIGEST` badge on mismatch).
10. **Test infrastructure could silently lie** — the e2e "in-process fallback" required modules that never listen; REGRESSION-02 claimed replay defense but tested missing-kb rejection; chaos assertions accepted any `invalid_presentation` error; the mdoc suite always exited 0. All repaired; assertions are now code-specific.

### Important remaining risks (documented, not hidden)
- Docker runtime behavior is **unverified on this machine** (daemon down); CI validates it on every push.
- The **live MOSIP Collab** lanes genuinely probe live discovery but deterministically fall back to the local mock for the credential exchange (PMS `.p12` partner certs cannot ship in an open repo). The fallback is labeled in the UI and README, and is visible in telemetry.
- The W3C VC path uses deterministic-JSON-canonicalization Ed25519 proofs, **not** URDNA2015 Data Integrity conformance. It is a bounded simulation and is now labeled as such.
- Frontend `mermaid`/`katex` LOW advisories would require a semver-major mermaid upgrade to clear — not done per change-control rules; diagrams render only repository-controlled text.

### Controlled-demo readiness
**READY** for a controlled local demo via `node scripts/start_local.js` (zero-docker) — verified repeatedly this session. Docker Compose readiness is statically validated but runtime-unverified here (daemon offline); CI runs that verification on push.

---

## B. Requirements Matrix

| Feature | Status | Evidence |
|:---|:---:|:---|
| FEAT-01 Matrix Selector | **PASS** | `GET /api/v1/matrix` returns issuers/wallets/verifiers/formats/8 chaos vectors; UI renders 3 lanes. Non-existent selection options now honestly labeled (simulated wallet/issuer options marked). |
| FEAT-02 OpenID4VCI (Draft 13) | **PASS** | Full pre-authorized-code flow with DPoP (`ath`, `jti` replay cache, `htm`/`htu`/`iat`), holder proof `aud`+`iat` validation, single-use `c_nonce` with TTL. e2e VULN-01/03/07 + SEC-01/10. |
| FEAT-03 OpenID4VP (Draft 21-23) | **PASS** | DIF PE 2.0 auth requests, single-use session nonces, fail-closed replay defense now **genuinely** regression-tested (REGRESSION-02 resubmits the same nonce). |
| FEAT-04 Dual format engine | **PASS** | `vc+sd-jwt`/`dc+sd-jwt` (RFC 9901 `sd_hash` now mandatory) and `ldp_vc` (Ed25519 with fail-closed key resolution). W3C path documented as canonicalization-simplified simulation. |
| FEAT-05 Protocol Inspector | **PASS** | Token anatomy + disclosure viewer; badges now reflect **real client-side SHA-256 digest checks** against `_sd`. |
| FEAT-06 Scorecard & export | **PASS (corrected)** | Scorecard previously always claimed 100% — now renders actual compliance percentage and flags failed lanes; RFC 7807 exporter verified. |
| FEAT-07 Live sequence diagram | **PASS** | Mermaid v11, debounced render, driven by actual selections; **static verification only** (no browser automation available in this session). |
| FEAT-08 Adversarial tamperer | **PASS** | 8 vectors, each asserting its specific RFC 7807 error code (generic-fallback assertions removed). |
| FEAT-09 External interop | **PARTIAL (labeled)** | Live Collab discovery probing + telemetry boundary + deterministic fallback works and is now labeled in UI/README. Walt.id selection routes to the local mock — explicitly labeled "Simulated". No external non-MOSIP implementation was available to test real cross-ecosystem interop. |
| FEAT-10 ISO 18013-5 mdoc | **PASS (bounded)** | Genuine CBOR Tag 24 + COSE_Sign1 + per-attribute `valueDigests` validation, integer `digestID`, nonce binding, replay defense (MDOC-01..04). DeviceSigned/NFC-BLE out of scope and not claimed. |
| FEAT-11 Historical dashboard | **PASS** | SQLite WAL persistence verified across runs; **PII leak in trace_blob found and fixed**; history responses redacted. |
| FEAT-12 CLI/CI runner | **PASS** | Fail-closed runner verified (exit 0 on 8/8; health probe gates execution). CI workflow extended to `master`/PRs with a real health-wait loop. |

PRD mandatory tasks 1-7: all demonstrated live this session (see evidence below). Good-to-have 1-6 and bonuses as per FEAT rows above; PRD Journey 2 ("cross-ecosystem") is simulation-only and labeled.

---

## C. Defect Register

| ID | Severity | Location | Root cause | Fix | Regression test | Status |
|:---|:---:|:---|:---|:---|:---|:---:|
| SEC-01 | HIGH | `mocks/issuer/server.js` `/credential` | No access-token session lookup; `cnf.jkt` check skipped when token unknown | Require valid, unexpired token → `401 invalid_token`; `jkt` check now always applies | `test_security_regression.js` SEC-01 (was HTTP 200 with forged token, now 401) | CLOSED/VERIFIED |
| SEC-02 | HIGH | `mocks/verifier/server.js` SD-JWT branch | `sd_hash` treated as optional (`if (kbPay.sd_hash && ...)`) | Mandatory claim → `400 ERR_MISSING_SD_HASH` | SEC-02 | CLOSED/VERIFIED |
| SEC-03 | HIGH | `mocks/verifier/server.js` SD-JWT branch | `kb_jwt.aud` never compared to verifier client_id | Enforce audience before any session mutation → `ERR_KB_JWT_AUD_MISMATCH` | SEC-03 | CLOSED/VERIFIED |
| SEC-04 | MEDIUM | `mocks/verifier/server.js` (SD-JWT + ldp_vc) | PE 2.0 field constraints never evaluated | Required-claim enforcement (UIN + fullName, multi-path, pattern) → `ERR_REQUIRED_CLAIM_NOT_DISCLOSED` | SEC-04, SEC-05 | CLOSED/VERIFIED |
| SEC-05 | MEDIUM | `mocks/verifier/server.js` ldp_vc branch | Signature verification skipped when no Ed25519 key resolved; `CORRUPT` substring special-case stood in for real checks | Fail-closed key resolution; special-case removed; missing proofValue rejected | SEC-06 (byte-flipped proof rejected via real crypto) | CLOSED/VERIFIED |
| SEC-06 | MEDIUM | `backend/server.js` verify orchestrator + `/api/v1/history` | Raw verifier response (UIN/name/phone) persisted to `trace_blob` and served | Sanitize at write; redact at read; regexes extended to `extracted_uin` and `+`-formatted phones | SEC-07 (was FAIL, now PASS) | CLOSED/VERIFIED |
| SEC-07 | MEDIUM | `mocks/issuer/server.js` `/token` | DPoP `htm`/`htu`/`iat` unchecked; `jti` cache unused | Full RFC 9449 §4.2 proof binding at token endpoint | SEC-10 (htm=GET → 400) | CLOSED/VERIFIED |
| SEC-08 | MEDIUM | `mocks/issuer/server.js` `/credential` | Holder proof `aud`/`iat` unchecked; `c_nonce` TTL claimed but unenforced | `aud` must equal `ISSUER_URL`; ±300s iat window; 300s nonce TTL; pre-auth-code TTL | Covered by SEC probes (wrong-aud proof now 400) | CLOSED/VERIFIED |
| SEC-09 | MEDIUM | `backend/server.js` issue orchestrator | Live→mock fallback could leave `aud`/`htu` pointing at the live issuer while the mock served the token | Endpoints/audience re-bound to the actually-used issuer after any fallback | Lane-5 (live probe) still passes; e2e VULN-06 | CLOSED/VERIFIED |
| SEC-10 | LOW | `backend/server.js` `/telemetry` viewer | Payload HTML interpolated via `innerHTML` (XSS) | DOM construction with `textContent` | Code review; page serves 200 | CLOSED/VERIFIED |
| SEC-11 | LOW | `mocks/verifier/server.js` | `activeSessions` grew without bound on abandoned nonces | 60s sweeper + 5000-entry hard cap | Code review + suites | CLOSED/VERIFIED |
| UI-01 | HIGH | `frontend/src/App.tsx` scorecard | Hardcoded "100% CONFORMANCE CERTIFIED" | Real percentage, conditional styling, confetti only at 100 | tsc+build pass; code review | CLOSED (static) |
| UI-02 | MEDIUM | `frontend/src/App.tsx` anatomy | Hardcoded "SHA-256 MATCH" badges | Real `crypto.subtle` digest computation vs `_sd` | tsc+build pass | CLOSED (static) |
| UI-03 | LOW | `frontend/src/App.tsx` chaos dropdown | Labels described non-existent behaviors (VEC-02/04) | Aligned with actual error codes | build | CLOSED |
| UI-04 | LOW | `frontend/src/App.tsx` lanes | Wallet/issuer options that route to the local mock were unlabeled | "Simulated — …" labels added | build | CLOSED |
| TEST-01 | HIGH | `scripts/test_e2e_local.js` | Fallback "spawned" modules that never listen (all checks would fail with connection errors when services are down) | Real in-process binding with EADDRINUSE tolerance | Suite bootstrap | CLOSED/VERIFIED |
| TEST-02 | HIGH | `scripts/test_e2e_local.js` REGRESSION-02 | "Replay" test actually submitted a token without kb+jwt | Genuine replay: same nonce resubmitted, asserts `ERR_NONCE_ALREADY_CONSUMED` | REGRESSION-02 (now strict) | CLOSED/VERIFIED |
| TEST-03 | MEDIUM | `scripts/test_e2e_local.js` | Chaos assertions accepted any `invalid_presentation` error | Code-specific assertions (VULN-02b, VULN-08, REGRESSION-03) | 26/26 suite | CLOSED/VERIFIED |
| TEST-04 | MEDIUM | `scripts/test_mdoc_tamper_and_replay.js` | Printed statuses but always exited 0 | Real assertions + nonzero exit | 4/4 fail-closed suite | CLOSED/VERIFIED |
| OPS-01 | LOW | `.github/workflows/interop-matrix.yml` | Only `main` trigger; fixed sleep 15; checkout@v3 | `master`+PR+manual triggers; fail-closed health-wait loop; checkout@v4 | YAML validated | CLOSED (static) |
| OPS-02 | LOW | `.gitignore` | `db/*.db-shm`/`*.db-wal` not ignored (untracked noise) | Added | git status clean | CLOSED/VERIFIED |
| OPS-03 | MEDIUM | deps (backend, mocks) | body-parser 1.20.8 HIGH DoS advisory | `npm audit fix` → 1.20.9 (patch), re-verified 0 vulnerabilities; all suites re-run | suites re-run | CLOSED/VERIFIED |
| OPS-04 | LOW | `docker-compose.yml` | Mocks had no healthchecks; BFF had no start ordering | Healthchecks + `depends_on: service_healthy` | `docker compose config` valid | CLOSED (static) |

Earlier defects DEF-01..06 from the previous audit round (issuer trust injection, fall-through bypass, nonce binding, mdoc digests, CSWSH/PII telemetry, unconditional CLI PASS) were **re-verified live** and remain closed: REGRESSION-01/03, SEC-08/09, MDOC-01..04, CSWSH 403 probe, and the fail-closed CLI runner all reproduce the protections this session.

---

## D. Verification Evidence (commands, exit statuses)

All commands executed 2026-10-24 on Windows (Git Bash, Node v24.19.0, npm 11.17.0):

| Command | Result |
|:---|:---|
| `node --check` × 8 source files | all OK (pre and post change) |
| `node scripts/test_e2e_local.js` (pre-fix baseline) | **26/26 PASS, exit 0** (claimed results reproduced) |
| `node scripts/test_mdoc_tamper_and_replay.js` (pre-fix) | printed 4/4, exit 0 (no assertions existed — a finding) |
| `bash scripts/cli_interop_runner.sh` (pre-fix) | 100% 8/8, exit 0 |
| `node scripts/test_security_regression.js` (pre-fix) | **3/10 — 7 live-confirmed defects** (SEC-01/02/03/04/05/07/10) |
| `npx tsc --noEmit` (frontend) | exit 0 (both rounds) |
| `npm run build` (frontend) | success, built in ~16-26s (both rounds) |
| `npm audit --omit=dev` (3 services) | 1 HIGH body-parser → after `npm audit fix`: **0 vulnerabilities** (1.20.8→1.20.9 verified in lockfile + node_modules) |
| Services restart on patched deps + full re-run | e2e **26/26**, security **10/10**, mdoc **4/4**, CLI **8/8** — all exit 0 |
| WS origin probe (ws client) | `https://evil.attacker.example` → **403**; `http://localhost:3000` → open; no-origin → open (CLI clients intended) |
| `docker compose config` | valid (static) |
| `docker compose up` | **BLOCKED** — Docker Desktop daemon not running (`failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`). Not worked around; no runtime claim made. |
| `curl` UI/BFF/telemetry pages | `:3000` → 200, `:4000` → 200, `:4000/telemetry` → 200 |
| Interactive browser walkthrough | **UNVERIFIED this session** — no browser-automation tool available (browser-use MCP backend not present; Playwright not installed). Compensating evidence: tsc clean, production build clean, HTTP checks, code review. |

Reproducibility: `node scripts/start_local.js` → run the four suites in README §2 order. Final diff inspected: no hardcoded secrets, no weakened assertions, no test-only bypasses; unrelated pre-existing modifications (`frontend/index.html`, `package_project.ps1`, mock package manifests from the previous round) were left intact.

---

## E. Protocol & Security Limitations (explicit classification)

**Genuinely implemented and runtime-verified:**
- OpenID4VCI Draft 13 issuance: pre-authorized code (TTL, single-use), DPoP (RFC 9449 `ath`, `jti` replay, `htm`/`htu`, `jkt` sender-constraining), holder proof (`aud`, `iat`, single-use `c_nonce`), IEEE P1363 64-byte ES256 with low-S normalization, Draft 13⇄14 proof-shape transpilation.
- OpenID4VP: DIF PE 2.0 request + nonce sessions, SD-JWT presentation with **mandatory** RFC 9901 `sd_hash`, **audience-checked** kb+jwt, PE required-claim + UIN-pattern enforcement, single-use nonces for all three formats.
- Issuer trust: explicit allowlist registry + JWKS resolution, `header.jwk` never trusted, userinfo-SSF tricks rejected, fail-closed key resolution.
- mdoc: COSE_Sign1 ES256 verification, per-attribute SHA-256 `valueDigests` (§9.1.2.4), integer `digestID`, namespace checks, nonce binding + replay defense.
- Adversarial: 8 chaos vectors with code-specific rejections; independent 10-probe security suite; fail-closed test tooling.

**Implemented only within the local mock environment:**
- All wallet selections (synthetic agent executes every flow) — labeled.
- Walt.id "external issuer" selection (routes to local mock) — labeled.
- DCQL / DIF-PE transpilation (structural normalization, not a spec-suite implementation).

**Simulated (documented, labeled):**
- W3C VC JSON-LD: deterministic-canonicalization Ed25519 proofs — **not** URDNA2015/W3C Data Integrity conformance.
- Live Collab fallback: live discovery probe + telemetry, then local mock exchange (PMS `.p12` boundary).
- mdoc DeviceSigned / NFC-BLE engagement (issuer-signed path only).

**Unsupported:**
- Real external-wallet interoperability (no external implementation available to test against).
- Status-list / revocation checking (`status` claim not evaluated).

**Unverified (blocked):**
- Docker runtime behavior on this machine (daemon offline); validated statically and in CI.
- Interactive browser UX (no automation tool this session); build/type/HTTP evidence only.

---

## F. Remaining Risks & Next Actions

1. **Docker runtime (medium urgency).** Impact: judges using `docker compose up` rely on CI validation rather than a local run. Action: start Docker Desktop and re-run `docker compose up -d` + `cli_interop_runner.sh`; expect pass given static validation and env-consistent config.
2. **Browser walkthrough (medium).** Action: run through README §7 demo script manually in a browser before recording the submission video; verify the new scorecard/badges visually.
3. **Mermaid 12 upgrade (low).** Clears 2 LOW frontend advisories; requires migration testing — deliberately deferred.
4. **Status-list revocation (low, out of scope).** Documented unsupported; would be a natural post-hackathon extension.
5. **`start_local.js` port pre-flight kills any process on :3000/:4000/:8080/:8081** (pre-existing behavior). Documented here as a known aggressive convenience; scope it to own PIDs if this becomes a problem.

---

## G. Final Release Assessment (evidence-based labels)

| Category | Assessment | Basis |
|:---|:---:|:---|
| Build & runtime reliability | **VERIFIED** | tsc/build/syntax clean; 4 services start and serve; suites run repeatedly on patched deps |
| Core workflow correctness | **VERIFIED** | issue→hold→present→verify across 4 formats; 8/8 matrix lanes; strengthened 26-check suite |
| Security | **VERIFIED (within threat model)** | 7 live-confirmed vulns fixed and regression-locked by an independent 10-probe suite; CSWSH 403 verified; PII redaction verified. Local-demo tool: no auth/rate-limiting by design, LAN exposure noted |
| Protocol conformance | **PARTIALLY VERIFIED** | Strong for the implemented subset (verified above); W3C canonicalization and DCQL are labeled simulations; no external implementation cross-tested |
| UI functionality | **PARTIALLY VERIFIED** | Fabricated-result defects fixed; build/type/HTTP verified; interactive clicking not exercised this session |
| Test quality | **VERIFIED** | Suites fail-closed with code-specific assertions; genuine replay test; independent adversarial suite; no hardcoded passes |
| Deployment reproducibility | **PARTIALLY VERIFIED** | Zero-docker path verified repeatedly; Docker statically valid, runtime blocked (daemon offline), CI-verified on push |
| Hackathon requirement coverage | **PARTIALLY VERIFIED** | All mandatory features demonstrated; external-interop claim honestly downgraded to labeled simulation |

**Bottom line:** the previous report's "100% everywhere" claim was not sustainable — live adversarial probing found seven exploitable-or-conformance-breaking defects in the very paths that report called fully hardened. All are now fixed, locked behind fail-closed regression tests that demonstrably failed before the fixes and pass after, and the documentation now distinguishes verified behavior from labeled simulation. Remaining uncertainty is concentrated in Docker runtime and interactive browser UX, both blocked by environment limitations and both covered by the strongest available static evidence.
