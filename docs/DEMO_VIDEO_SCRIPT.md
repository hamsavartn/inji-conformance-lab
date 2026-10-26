# 5-Minute Demo Video — Complete Recording Script
### MOSIP Inji Conformance Laboratory | MOSIP Decode 2026, Problem Statement 02

This is a **shoot-ready script**: every step lists the exact click/key, the narration to speak (in *italics*), and what MUST be visible on screen. Total runtime target: **4:45–5:15**. Practice the full run once before recording; if a step doesn't match its "You should see" line, stop and fix before continuing.

---

## 0. Pre-Recording Setup (10 minutes before pressing record)

1. **Resolution & browser**: 1920×1080, Chrome, zoom 100%, close all other tabs and apps (no notification pop-ups).
2. **Fresh start** (guarantees deterministic state):
   ```bash
   node scripts/start_local.js
   ```
   Wait for the "ALL CONFORMANCE LABORATORY SERVICES READY" banner. Verify: `http://localhost:3000` loads and the **Telemetry WS: LIVE** badge is green.
3. **Open two terminal windows** side by side (white background, 16pt+ font — judges must read them):
   - Terminal A: project root (for test suites in Part 7)
   - Terminal B: unused (spare)
4. **Browser tabs to pre-open** (in this order):
   - Tab 1: `http://localhost:3000` (main UI)
   - Tab 2: `http://localhost:4000/telemetry` (live telemetry viewer)
5. **Optional recording tools**: OBS Studio or Xbox Game Bar (Win+G). Record at 1080p/30fps. Do a 10-second test clip and check audio levels.
6. **Reset history noise** (optional, cosmetic): the History tab will show prior runs — that's fine, it actually demonstrates persistence.

---

## Part 1 — Hook & Problem Statement (0:00 – 0:30)

**Screen**: Tab 1, the UI top bar. Slowly scroll once through the full page top-to-bottom so judges see the whole layout, then return to top.

**Narration**:
> *"Digital identity fails in the field, not in the demo. Wallets built against OpenID4VCI Draft 13 break against Draft 14 verifiers. A credential with a valid signature but the wrong type gets silently accepted. Nobody can see WHY it failed. We built the MOSIP Inji Conformance Laboratory — a zero-trust playground that runs the full issue-hold-present-verify lifecycle, inspects every raw protocol byte, and then attacks its own verifier with cryptographic tamper vectors to prove it fails closed. Everything you'll see runs locally, from one command, under 920 megabytes."*

**On screen at cut**: the three-lane matrix (Issuer | Wallet | Verifier).

---

## Part 2 — Happy Path: SD-JWT Issuance + Live Protocol Inspector (0:30 – 1:30)

**Setup**: lanes at defaults (Mock Inji Certify / Automated Synthetic Agent / Mock Inji Verify), Format = `vc+sd-jwt`, Chaos Fuzzer = **Disabled**.

1. **Point at each lane** (mouse only, no click): issuer → wallet → verifier.
   **Narration**: *"Any permutation — mock issuer, live MOSIP Collab probe, or Draft-14 transpilation on the issuer side; the headless wallet agent with real ephemeral P-256 keys; mock or live Inji Verify. Simulated paths are labeled as simulated — we don't pretend."*
2. **Click `Execute Handshake Flow`** (top right).
3. Watch the **Telemetry Stream** fill — switch to the **Telemetry Stream** tab when the run completes.
   **You should see**: 6 hop cards — Discovery, Credential Offer, Token Request (DPoP), Credential Issued, Auth Request, direct_post — each with an HTTP 200 badge and millisecond latency.
   **Narration**: *"Every protocol hop, live over WebSocket, with real latency. Discovery, pre-authorized offer, DPoP-bound token exchange, and issuance."*
4. Switch to the **Token Anatomy & Claims** tab.
   **You should see**: the color-coded legend (Header / Claims / P-256 signature / disclosures / kb-jwt), disclosure cards each showing a **green SHA-256 MATCH** badge, and the split raw-token / decoded-payload view.
   **Narration**: *"The inspector decodes the SD-JWT — and those SHA-256 MATCH badges are not decoration: your browser recomputes each disclosure digest against the issuer's underscore-SD array right now. If a disclosure were forged, it would light up UNBOUND DIGEST in red."*
5. Hover the decoded payload: point at `_sd`, `cnf.jwk`, `vct`.
   **Narration**: *"Eight selective-disclosure digests — five real claims plus three decoys — the holder's binding key in CNF, and the credential type. Selective disclosure by construction."*

---

## Part 3 — Dynamic Mermaid Sequence Diagram (1:30 – 2:00)

1. Switch to the **Dynamic Sequence Diagram** tab.
   **You should see**: the Mermaid sequence diagram with participants User/BFF/Issuer/Wallet/Verifier and ~14 numbered arrows, ending in "200 OK (Verification Confirmed)".
2. Change the **Chaos Fuzzer dropdown to VEC-01** (do NOT execute yet).
   **You should see**: the diagram re-render automatically with a red "[CHAOS MUTATION INJECTED]: VEC-01" note and the final arrow becoming "400 Bad Request (Negative Security Assertion PASSED)".
   **Narration**: *"The sequence diagram is generated from the actual selected topology and attack vector — change the fuzzer and it re-renders to predict the negative path. DIF Presentation Exchange on the request side, direct_post submission on the response side, exactly as Inji Verify expects."*
3. Set the Chaos Fuzzer **back to Disabled** before Part 4.

---

## Part 4 — The Chaos Monkey: Adversarial Negative Assertions (2:00 – 3:00)

The core differentiator — do these three vectors; each takes ~15 seconds.

1. **VEC-01 Signature Bit-Flip**: select `VEC-01` in the Chaos dropdown → click **Execute Handshake Flow**.
   **You should see**: green banner "**NEGATIVE ASSERTION CONFIRMED (HTTP 400 REJECTION AS EXPECTED)**" with `ERR_INVALID_ES256_SIGNATURE`.
   **Narration**: *"Vector one flips one bit inside the issuer's ES256 signature. The verifier recomputes the ECDSA verification with the trusted issuer key — it must reject. This is real OpenSSL-grade crypto failing closed, not a string check."*
2. **VEC-03 sd_hash desync**: switch dropdown to `VEC-03` → Execute.
   **You should see**: banner with `ERR_KB_SD_HASH_MISMATCH`.
   **Narration**: *"Vector three is a cut-and-paste attack — a key-binding JWT signed over different disclosures than the ones presented. RFC 9901's sd_hash catches it."*
3. **VEC-05 Expired credential**: switch to `VEC-05` → Execute.
   **You should see**: banner with `ERR_CREDENTIAL_EXPIRED`.
   **Narration**: *"An authentically issuer-signed but expired credential — rejected beyond the five-minute clock-skew window."*
4. Click **Export GitHub Bug Report** on the banner.
   **You should see**: the RFC 7807 bug-exporter modal with pre-filled Markdown; briefly scroll it.
   **Narration**: *"Every failure is exportable as an RFC 7807 problem-details issue, pre-loaded with four documented MOSIP gaps — INJIVER-1131 credential-type confusion among them — ready to file upstream. The lab doesn't just find interop gaps, it packages them."*
5. Close the modal. Set Chaos Fuzzer back to **Disabled**.

---

## Part 5 — Selective Disclosure Enforcement + mdoc (3:00 – 3:50)

1. Switch to the **Privacy Slider & QR Density Meter** tab.
   **Narration**: *"The wallet discloses only what the user consents to — watch the QR density meter and privacy score react as I toggle claims."*
2. **Uncheck the `UIN` claim** (National ID).
   **You should see**: privacy score % rises, "X of 5 Disclosed" drops.
3. Go back to the top, keep Chaos disabled, click **Execute Handshake Flow**.
   **You should see**: a **red banner: UNEXPECTED INTEROPERABILITY REJECTION** with `ERR_REQUIRED_CLAIM_NOT_DISCLOSED: ... UIN (not disclosed)`.
   **Narration**: *"And here's the interesting part — the verifier asked for the UIN in its presentation definition, so withholding it is correctly REJECTED. That's DIF Presentation Exchange constraint enforcement working — the wallet can't silently under-disclose. That red banner is the system being honest."*
4. **Re-check UIN**. Switch Format dropdown to **`mso_mdoc` (ISO 18013-5)** → Execute.
   **You should see**: green 200 banner. Switch to Token Anatomy tab — the raw CBOR base64url credential.
   **Narration**: *"ISO 18013-5 mobile driving license: the issuer builds a CBOR Tag-24 Mobile Security Object, signs it as COSE_Sign1, and the verifier re-hashes every disclosed attribute against the MSO valueDigests — ISO section 9.1.2.4 digest binding. Tamper one byte of one attribute and it's rejected."*

---

## Part 6 — Judge Mode: One-Click Conformance Matrix + History (3:50 – 4:20)

1. Click **Run Judge Conformance Matrix** (top bar).
   **You should see**: confetti, then the Scorecard tab: "**100% CONFORMANCE CERTIFIED**", 8 rows all green PASS — spanning `vc+sd-jwt`, `dc+sd-jwt`, `ldp_vc`, `mso_mdoc`, Draft-14 transpiled, live-Collab probe lane, and the inji-verify lane — each with millisecond latency.
   **Narration**: *"One click: eight concurrent lifecycle permutations across formats and drafts, scored honestly — if a lane failed, this header would show the real percentage in red with the failing lanes listed. Nothing here is hardcoded."*
2. Switch to the **Run History** tab.
   **You should see**: the SQLite-backed table of every run you just did, filterable by format and outcome.
   **Narration**: *"Everything persists in SQLite WAL — including this session's negative assertions — with personally-identifying claims redacted at rest. Filterable regression history."*

---

## Part 7 — The Receipts: Fail-Closed Test Suites (4:20 – 4:50)

**Screen**: switch to Terminal A, font large.

```bash
node scripts/test_e2e_local.js
```
**You should see**: 26 checks stream past, ending `FINAL VERIFICATION RESULTS: 26/26 CHECKS PASSED (100%)`.

Quickly run (or pre-run and scroll to results):
```bash
node scripts/test_security_regression.js
```
**You should see**: `SECURITY REGRESSION RESULTS: 10/10 PASSED`.

**Narration**:
> *"Everything you watched is pinned by fail-closed suites: twenty-six conformance checks, plus an independent adversarial suite that attacked this system with attacker-held keys — forged tokens, stripped sd_hash, foreign audiences, replayed nonces. It found seven real vulnerabilities during our audit; each is now fixed and locked behind the probe that caught it. The audit report, verification matrix, and judge guide ship in the repo — we'd rather show you an honest defect register than a polished claim."*

---

## Part 8 — Close (4:50 – 5:00)

**Screen**: back to the browser, full-page slow scroll.

**Narration**:
> *"The MOSIP Inji Conformance Laboratory: real cryptography, four credential formats, eight attack vectors, honest scorecards, and a one-command Docker bundle under 920 megabytes. Zero-trust interoperability for the Inji ecosystem — proven, not promised. Thank you."*

Stop recording.

---

## Post-Production Checklist

- [ ] Trim dead air; total ≤ 5:15
- [ ] Verify terminal text is legible at 720p playback (zoom-crop if needed in Part 7)
- [ ] Add a 3-second title card: project name + PS02 + team name
- [ ] Export 1080p MP4; filename: `inji-conformance-lab-demo.mp4`
- [ ] Watch once end-to-end against this script — every "You should see" must hold

## If Something Breaks Mid-Recording

| Symptom | Fix |
|:---|:---|
| Telemetry badge DISCONNECTED | Wait 3s (auto-reconnect); if persistent, restart `node scripts/start_local.js` |
| A 200-flow shows red banner with services healthy | You likely left a chaos vector selected — set to Disabled and re-run |
| Port conflicts on restart | `start_local.js` auto-frees ports on Windows; on mac/linux kill node processes first |
| Judge Matrix < 100% | Do NOT record past it — run once more; if persistent, check `bash scripts/cli_interop_runner.sh` output for the failing lane before re-recording |
