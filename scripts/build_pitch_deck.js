const pptxgen = require("pptxgenjs");
const p = new pptxgen();
p.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
p.author = "MOSIP Decode 2026 Team";
p.title = "MOSIP Inji Conformance Laboratory";

// Palette — derived from the product's own UI (deep navy wire, cyan protocol, emerald pass)
const BG = "0B1220", CARD = "121B2F", BORDER = "22304E";
const PRIMARY = "22D3EE", ACCENT = "34D399", ROSE = "FB7185", AMBER = "FBBF24";
const TEXT = "F1F5F9", MUTED = "8DA2BD";
const SANS = "Segoe UI", MONO = "Consolas";

const W = 13.33, H = 7.5, M = 0.6;
const shadow = () => ({ type: "outer", color: "000000", blur: 8, offset: 3, angle: 90, opacity: 0.35 });
const bu = () => ({ code: "25B8", indent: 12 });

function card(s, x, y, w, h, fill = CARD) {
  s.addShape(p.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: fill }, line: { color: BORDER, width: 1 }, rectRadius: 0.08, shadow: shadow() });
}
function kicker(s, txt, color = PRIMARY) {
  s.addText(txt.toUpperCase(), { x: M, y: 0.42, w: W - 2 * M, h: 0.34, fontFace: MONO, fontSize: 13, color, charSpacing: 3, margin: 0 });
}
function title(s, txt, color = TEXT) {
  s.addText(txt, { x: M, y: 0.72, w: W - 2 * M, h: 0.85, fontFace: SANS, fontSize: 38, bold: true, color, margin: 0 });
}
function footer(s, n) {
  s.addText(`MOSIP Decode 2026 · PS02 · Inji Conformance Laboratory`, { x: M, y: H - 0.5, w: 8, h: 0.3, fontFace: SANS, fontSize: 10, color: MUTED, margin: 0 });
  s.addText(String(n).padStart(2, "0"), { x: W - M - 0.6, y: H - 0.5, w: 0.6, h: 0.3, fontFace: MONO, fontSize: 10, color: MUTED, align: "right", margin: 0 });
}
function chip(s, txt, x, y, w, color = PRIMARY) {
  s.addShape(p.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 0.38, fill: { color: BG }, line: { color, width: 1 }, rectRadius: 0.19 });
  s.addText(txt, { x, y, w, h: 0.38, fontFace: MONO, fontSize: 11.5, color, align: "center", valign: "middle", margin: 0 });
}

/* ---------------- SLIDE 1 — TITLE ---------------- */
let s = p.addSlide(); s.background = { color: BG };
s.addShape(p.shapes.OVAL, { x: 9.4, y: -2.3, w: 6.4, h: 6.4, fill: { color: "0E1B33" }, line: { color: BORDER, width: 1 } });
s.addShape(p.shapes.OVAL, { x: 10.6, y: -1.2, w: 4.2, h: 4.2, fill: { color: "11213D" }, line: { color: BORDER, width: 1 } });
chip(s, "MOSIP DECODE 2026 · PROBLEM STATEMENT 02 · HIGH COMPLEXITY", M, 1.05, 6.4);
s.addText("MOSIP Inji\nConformance Laboratory", { x: M, y: 1.7, w: 11.5, h: 2.3, fontFace: SANS, fontSize: 54, bold: true, color: TEXT, margin: 0, lineSpacingMultiple: 1.02 });
s.addText("A zero-trust interoperability playground that runs the full Issue → Hold → Present → Verify lifecycle, inspects every protocol byte — then attacks its own verifier to prove it fails closed.", { x: M, y: 4.15, w: 9.6, h: 1.0, fontFace: SANS, fontSize: 18, color: MUTED, margin: 0, lineSpacingMultiple: 1.15 });
const stats = [
  { n: "51/51", l: "automated checks passing" },
  { n: "4", l: "credential formats end-to-end" },
  { n: "8+10", l: "adversarial attack vectors" },
  { n: "920 MB", l: "hard Docker RAM ceiling" },
];
stats.forEach((st, i) => {
  const x = M + i * 3.12;
  card(s, x, 5.5, 2.85, 1.35);
  s.addText(st.n, { x: x + 0.22, y: 5.66, w: 2.5, h: 0.55, fontFace: MONO, fontSize: 28, bold: true, color: i === 0 ? ACCENT : PRIMARY, margin: 0 });
  s.addText(st.l, { x: x + 0.22, y: 6.24, w: 2.5, h: 0.45, fontFace: SANS, fontSize: 11.5, color: MUTED, margin: 0 });
});

/* ---------------- SLIDE 2 — PROBLEM ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "The problem");
title(s, "A valid signature is not a valid credential");
s.addText("Cross-ecosystem credential exchange fails in the field, and nobody can see why. Wallets crash on draft mismatches; verifiers silently accept what they should reject.", { x: M, y: 1.62, w: 11.6, h: 0.75, fontFace: SANS, fontSize: 16.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.15 });
const fails = [
  { h: "Draft drift", d: "OpenID4VCI Draft 13 wallets break against Draft 14 verifiers — singular proof vs plural proofs DTO.", tag: "Draft 13 ⇄ 14" },
  { h: "Silent acceptance", d: "INJIVER-1131: a LifeInsuranceCredential with a valid signature passes a national-ID presentation request.", tag: "Type confusion" },
  { h: "Binding gaps", d: "DPoP ath mismatches and key-binding JWTs that never verify sd_hash or audience let replayed proofs through.", tag: "RFC 9449 / 9901" },
  { h: "No visibility", d: "Raw protocol payloads are invisible — judges, integrators and QA cannot inspect a single hop.", tag: "Black box" },
];
fails.forEach((f, i) => {
  const x = M + i * 3.12;
  card(s, x, 2.75, 2.85, 3.5);
  s.addText(f.tag, { x: x + 0.22, y: 3.0, w: 2.4, h: 0.3, fontFace: MONO, fontSize: 11, color: ROSE, margin: 0 });
  s.addText(f.h, { x: x + 0.22, y: 3.38, w: 2.4, h: 0.75, fontFace: SANS, fontSize: 19, bold: true, color: TEXT, margin: 0 });
  s.addText(f.d, { x: x + 0.22, y: 4.2, w: 2.42, h: 1.85, fontFace: SANS, fontSize: 12.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.18 });
});
s.addText("Every failure above is reproducible in this laboratory — and every defense is enforced by a test that fails loudly if it regresses.", { x: M, y: 6.5, w: 11.5, h: 0.4, fontFace: MONO, fontSize: 13, color: ACCENT, margin: 0 });
footer(s, 2);

/* ---------------- SLIDE 3 — SOLUTION ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "The solution");
title(s, "A conformance playground, not another mock");
const lanes = [
  { h: "ISSUER", items: ["Mock Inji Certify (Draft 13)", "Live Collab sandbox probe", "Draft 14 transpilation mode"] },
  { h: "WALLET", items: ["Headless synthetic agent", "Real ephemeral P-256 keys", "DPoP + kb+jwt proof engine"] },
  { h: "VERIFIER", items: ["Mock Inji Verify (Draft 21-23)", "DIF PE 2.0 + DCQL queries", "Fail-closed trust registry"] },
];
lanes.forEach((l, i) => {
  const x = M + i * 4.13;
  card(s, x, 1.95, 3.85, 2.3);
  s.addText(l.h, { x: x + 0.25, y: 2.18, w: 3.3, h: 0.35, fontFace: MONO, fontSize: 14, bold: true, color: PRIMARY, charSpacing: 2, margin: 0 });
  s.addText(l.items.map((t, j) => ({ text: t, options: { bullet: bu(), breakLine: j < l.items.length - 1 } })), { x: x + 0.25, y: 2.62, w: 3.4, h: 1.5, fontFace: SANS, fontSize: 13.5, color: TEXT, paraSpaceAfter: 8, margin: 0 });
  if (i < 2) s.addText("→", { x: x + 3.82, y: 2.85, w: 0.4, h: 0.5, fontFace: SANS, fontSize: 24, color: PRIMARY, align: "center", margin: 0 });
});
const caps = [
  ["Execute", "any permutation of the 3 lanes across 4 credential formats with one click"],
  ["Inspect", "every raw payload — decoded JWTs, disclosures, digests, MSO valueDigests, live WS telemetry"],
  ["Attack", "8 chaos vectors + 10 adversarial probes must each be rejected with its exact RFC 7807 code"],
  ["Report", "honest scorecard, SQLite history, and upstream RFC 7807 bug exports ready to file"],
];
caps.forEach((c, i) => {
  const x = M + (i % 2) * 6.35, y = 4.55 + Math.floor(i / 2) * 1.12;
  s.addShape(p.shapes.ROUNDED_RECTANGLE, { x, y, w: 0.9, h: 0.55, fill: { color: "0E1B33" }, line: { color: BORDER, width: 1 }, rectRadius: 0.08 });
  s.addText(c[0], { x, y, w: 0.9, h: 0.55, fontFace: MONO, fontSize: 12.5, bold: true, color: ACCENT, align: "center", valign: "middle", margin: 0 });
  s.addText(c[1], { x: x + 1.1, y: y + 0.02, w: 5.15, h: 1.0, fontFace: SANS, fontSize: 13.5, color: TEXT, valign: "top", margin: 0, lineSpacingMultiple: 1.12 });
});
footer(s, 3);

/* ---------------- SLIDE 4 — ARCHITECTURE ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "Architecture");
title(s, "Four services, one command, real cryptography");
const boxes = [
  { x: M, y: 2.3, w: 2.7, h: 1.9, h1: "React UI", h2: ":3000", d: "3-lane matrix, 7-tab inspector, live Mermaid, scorecard" },
  { x: 3.85, y: 2.3, w: 2.7, h: 1.9, h1: "BFF Gateway", h2: ":4000", d: "Orchestrator, 8-lane matrix runner, WS telemetry, SQLite WAL" },
  { x: 7.7, y: 2.3, w: 2.7, h: 1.9, h1: "Mock Certify", h2: ":8080", d: "OpenID4VCI Draft 13/14 issuer, DPoP + proof validation" },
  { x: 11.55, y: 2.3, w: 1.15, h: 1.9, h1: "Verify", h2: ":8081", d: "OpenID4VP RP" },
];
boxes.forEach(b => {
  card(s, b.x, b.y, b.w, b.h);
  s.addText(b.h1, { x: b.x + 0.18, y: b.y + 0.16, w: b.w - 0.3, h: 0.35, fontFace: SANS, fontSize: 15.5, bold: true, color: TEXT, margin: 0 });
  s.addText(b.h2, { x: b.x + 0.18, y: b.y + 0.5, w: b.w - 0.3, h: 0.3, fontFace: MONO, fontSize: 12, color: PRIMARY, margin: 0 });
  s.addText(b.d, { x: b.x + 0.18, y: b.y + 0.84, w: b.w - 0.32, h: 1.0, fontFace: SANS, fontSize: 11, color: MUTED, margin: 0, lineSpacingMultiple: 1.1 });
});
s.addShape(p.shapes.LINE, { x: 3.3, y: 3.25, w: 0.55, h: 0, line: { color: PRIMARY, width: 2 } });
s.addShape(p.shapes.LINE, { x: 6.55, y: 3.25, w: 1.15, h: 0, line: { color: PRIMARY, width: 2 } });
s.addShape(p.shapes.LINE, { x: 10.4, y: 3.25, w: 1.15, h: 0, line: { color: PRIMARY, width: 2 } });
card(s, M, 4.6, 12.13, 0.85, "0E1B33");
s.addText([
  { text: "$ ", options: { color: MUTED } },
  { text: "docker compose up --build", options: { color: ACCENT } },
  { text: "   →  4 healthchecked services, ordered startup, 920 MB hard ceiling  ·  or zero-Docker: ", options: { color: MUTED } },
  { text: "node scripts/start_local.js", options: { color: ACCENT } },
], { x: M + 0.3, y: 4.6, w: 11.6, h: 0.85, fontFace: MONO, fontSize: 14, valign: "middle", margin: 0 });
const rfcs = ["RFC 7515 · JWS P1363 64-byte r‖s, low-S", "RFC 9449 · DPoP ath, jti, htm/htu, cnf.jkt", "RFC 9901 · SD-JWT sd_hash key binding", "RFC 7638 · JWK thumbprints", "ISO 18013-5 · COSE_Sign1 + valueDigests"];
s.addText(rfcs.map((t, j) => ({ text: t, options: { bullet: bu(), breakLine: j < rfcs.length - 1 } })), { x: M, y: 5.75, w: 7.6, h: 1.35, fontFace: SANS, fontSize: 13, color: TEXT, paraSpaceAfter: 6, margin: 0 });
s.addText("No stubbed verification.\nNo string-matching shortcuts.\nEvery signature is checked with real crypto.", { x: 8.6, y: 5.75, w: 4.1, h: 1.35, fontFace: MONO, fontSize: 13, color: ACCENT, margin: 0, lineSpacingMultiple: 1.3 });
footer(s, 4);

/* ---------------- SLIDE 5 — INSPECTOR + FORMATS ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "Protocol inspection");
title(s, "Every byte, on screen, in real time");
const fmts = [
  { f: "vc+sd-jwt", d: "IETF SD-JWT VC — 5 salted disclosures + 3 decoy digests, RFC 9901 kb+jwt" },
  { f: "dc+sd-jwt", d: "Digital Credentials format — same engine, DC-style route" },
  { f: "ldp_vc", d: "W3C VC JSON-LD — Ed25519Signature2020 proofs" },
  { f: "mso_mdoc", d: "ISO 18013-5 — CBOR Tag 24, COSE_Sign1, per-attribute MSO digests" },
];
fmts.forEach((f, i) => {
  const y = 1.95 + i * 0.98;
  card(s, M, y, 5.6, 0.84);
  s.addText(f.f, { x: M + 0.22, y: y + 0.12, w: 1.75, h: 0.6, fontFace: MONO, fontSize: 14, bold: true, color: PRIMARY, valign: "middle", margin: 0 });
  s.addText(f.d, { x: M + 2.0, y: y + 0.08, w: 3.5, h: 0.7, fontFace: SANS, fontSize: 11, color: MUTED, valign: "middle", margin: 0, lineSpacingMultiple: 1.08 });
});
const insp = [
  ["Token anatomy", "color-coded header / claims / signature / disclosures / kb-jwt — with SHA-256 MATCH badges computed live in your browser against the issuer _sd array"],
  ["Live telemetry", "WebSocket stream of every hop with millisecond latency; origin-guarded (CSWSH 403); PII redacted"],
  ["Mermaid sequence", "diagram generated from the actual selected topology — re-renders when you pick an attack vector"],
  ["Privacy slider", "toggle disclosed claims; QR density + privacy score react; the verifier enforces what it requested (DIF PE 2.0)"],
];
insp.forEach((c, i) => {
  const y = 1.95 + i * 1.18;
  s.addText([
    { text: c[0] + " — ", options: { bold: true, color: TEXT } },
    { text: c[1], options: { color: MUTED } },
  ], { x: 6.75, y, w: 6.0, h: 1.1, fontFace: SANS, fontSize: 13.5, margin: 0, lineSpacingMultiple: 1.15 });
});
footer(s, 5);

/* ---------------- SLIDE 6 — CHAOS MONKEY ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "Adversarial engine", ROSE);
title(s, "8 chaos vectors — every attack must fail closed");
const vecRows = [
  [{ text: "Vector", options: { bold: true, color: PRIMARY, fontFace: MONO } }, { text: "Attack", options: { bold: true, color: PRIMARY, fontFace: MONO } }, { text: "Required rejection", options: { bold: true, color: PRIMARY, fontFace: MONO } }],
  ["VEC-01", "Issuer signature bit-flip (real 1-bit crypto corruption)", "ERR_INVALID_ES256_SIGNATURE"],
  ["VEC-02", "kb+jwt iat backdated beyond ±300s skew", "ERR_KB_JWT_IAT_OUTSIDE_SKEW_WINDOW"],
  ["VEC-03", "Cut-and-paste sd_hash desync", "ERR_KB_SD_HASH_MISMATCH"],
  ["VEC-04", "Unbound disclosure injection (digest ∉ issuer _sd)", "ERR_UNBOUND_DISCLOSURE_DIGEST"],
  ["VEC-05", "Expired credential presentation", "ERR_CREDENTIAL_EXPIRED"],
  ["VEC-06", "Recursive _sd nesting loop", "ERR_RECURSIVE_SD_NESTING_LIMIT_EXCEEDED"],
  ["VEC-07", "INJIVER-1131 credential type confusion", "ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE"],
  ["VEC-08", "ASN.1 DER signature where P1363 is mandated", "ERR_NON_P1363_SIGNATURE_LENGTH"],
];
s.addTable(vecRows.map(r => r.map ? r : [
  { text: r[0], options: { fontFace: MONO, color: ACCENT, bold: true } },
  { text: r[1], options: { fontFace: SANS, color: TEXT } },
  { text: r[2], options: { fontFace: MONO, color: ROSE } },
]), { x: M, y: 1.95, w: 9.1, colW: [1.0, 4.0, 4.1], fontSize: 10.5, color: TEXT, border: { pt: 0.5, color: BORDER }, fill: { color: CARD }, rowH: 0.44, valign: "middle", margin: 0.08 });
card(s, 10.05, 1.95, 2.68, 4.1, "0E1B33");
s.addText("+10", { x: 10.3, y: 2.2, w: 2.2, h: 0.7, fontFace: MONO, fontSize: 40, bold: true, color: ROSE, margin: 0 });
s.addText("independent adversarial probes driven with attacker-held keys", { x: 10.3, y: 2.95, w: 2.2, h: 0.95, fontFace: SANS, fontSize: 12.5, color: TEXT, margin: 0, lineSpacingMultiple: 1.15 });
s.addText("forged tokens · stripped sd_hash · foreign audience · withheld claims · byte-flipped Ed25519 proofs · replayed nonces · rogue issuers · DPoP htm attacks", { x: 10.3, y: 4.0, w: 2.2, h: 1.9, fontFace: SANS, fontSize: 10.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.2 });
s.addText("A vector passes only when the verifier returns HTTP 400 with its exact error code — any other outcome fails the suite.", { x: M, y: 6.45, w: 11.5, h: 0.4, fontFace: MONO, fontSize: 12.5, color: ACCENT, margin: 0 });
footer(s, 6);

/* ---------------- SLIDE 7 — AUDIT STORY ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "Engineering integrity", AMBER);
title(s, "We did not trust our own first audit");
s.addText("An internal report once claimed \u201C100% everywhere.\u201D We discarded it, re-derived every claim from live execution, and attacked the system with an auditor-written probe suite using attacker-held keys.", { x: M, y: 1.62, w: 12.1, h: 0.7, fontFace: SANS, fontSize: 15.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.15 });
p.charts && s.addChart(p.charts.BAR, [{
  name: "Adversarial suite",
  labels: ["Before remediation", "After remediation"],
  values: [3, 10],
}], {
  x: M, y: 2.65, w: 5.3, h: 3.4, barDir: "col",
  chartColors: [ROSE, ACCENT], varyColors: true,
  chartArea: { fill: { color: CARD } }, plotArea: { fill: { color: CARD } },
  catAxisLabelColor: MUTED, valAxisLabelColor: MUTED, catAxisLabelFontFace: SANS, valAxisLabelFontFace: MONO,
  valAxisMaxVal: 10, valAxisMajorUnit: 2, valGridLine: { color: BORDER, size: 0.5 }, catGridLine: { style: "none" },
  showValue: true, dataLabelPosition: "outEnd", dataLabelColor: TEXT, dataLabelFontFace: MONO, dataLabelFontSize: 14,
  showLegend: false, showTitle: true, title: "Adversarial security probes passing (of 10)", titleColor: TEXT, titleFontFace: SANS, titleFontSize: 13,
});
const audit = [
  ["7 live-exploited vulnerabilities found", "forged access tokens issued credentials; kb+jwt without sd_hash or with a foreign audience verified; zero-claim presentations passed; PII persisted unredacted"],
  ["Every defect fixed & locked", "each fix is pinned by the exact probe that originally broke it — the suite is now a permanent regression gate in CI"],
  ["Honesty applied to the UI itself", "the scorecard no longer hardcodes \u201C100%\u201D; anatomy badges compute real SHA-256 digests; everything simulated is labeled \u201CSimulated\u201D"],
  ["Full evidence ledger ships in the repo", "AUDIT_REPORT.md — defect register with IDs, root causes, fixes and tests; docs/verification-matrix.md — requirement-to-test traceability"],
];
audit.forEach((a, i) => {
  const y = 2.65 + i * 0.92;
  s.addText([
    { text: a[0], options: { bold: true, color: TEXT, breakLine: true } },
    { text: a[1], options: { color: MUTED, fontSize: 11.5 } },
  ], { x: 6.4, y, w: 6.3, h: 0.9, fontFace: SANS, fontSize: 13.5, margin: 0, lineSpacingMultiple: 1.1 });
});
s.addText("\u201CWe would rather show you an honest defect register than a polished claim.\u201D", { x: M, y: 6.45, w: 11.5, h: 0.4, fontFace: SANS, fontSize: 14, italic: true, color: ACCENT, margin: 0 });
footer(s, 7);

/* ---------------- SLIDE 8 — JUDGE MODE / EVIDENCE ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "Judge mode & evidence");
title(s, "One click, 51 checks, zero trust required");
card(s, M, 1.95, 5.9, 2.1);
s.addText("Run Judge Conformance Matrix", { x: M + 0.25, y: 2.15, w: 5.4, h: 0.4, fontFace: SANS, fontSize: 17, bold: true, color: TEXT, margin: 0 });
s.addText("8 concurrent lanes — vc+sd-jwt · dc+sd-jwt · ldp_vc · mso_mdoc · Draft-14 transpiled · live Collab probe · inji-verify lane — scored in ~0.4s with an honest scorecard and exportable report.", { x: M + 0.25, y: 2.6, w: 5.4, h: 1.3, fontFace: SANS, fontSize: 12.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.18 });
const suites = [
  ["Chain of Verification", "26/26", "DPoP · sd_hash · P1363 · 8 chaos vectors · replay · mdoc"],
  ["Adversarial Security Suite", "10/10", "attacker-held keys — was 3/10 before remediation"],
  ["mdoc Tamper & Replay", "4/4", "MSO digest mismatch · digestID · nonce replay"],
  ["CI Interop Matrix", "8/8", "fail-closed CLI + GitHub Action on every push"],
];
suites.forEach((t, i) => {
  const y = 4.35 + i * 0.62;
  s.addText([
    { text: t[1] + "  ", options: { fontFace: MONO, bold: true, color: ACCENT } },
    { text: t[0] + " — ", options: { bold: true, color: TEXT } },
    { text: t[2], options: { color: MUTED } },
  ], { x: M, y, w: 12.1, h: 0.5, fontFace: SANS, fontSize: 13.5, margin: 0 });
});
card(s, 6.85, 1.95, 5.88, 2.1, "0E1B33");
s.addText([
  { text: "$ ", options: { color: MUTED } },
  { text: "node scripts/test_e2e_local.js\n", options: { color: ACCENT } },
  { text: "FINAL VERIFICATION RESULTS: 26/26 CHECKS PASSED (100%)\n", options: { color: TEXT, bold: true } },
  { text: "$ ", options: { color: MUTED } },
  { text: "node scripts/test_security_regression.js\n", options: { color: ACCENT } },
  { text: "SECURITY REGRESSION RESULTS: 10/10 PASSED", options: { color: TEXT, bold: true } },
], { x: 7.1, y: 2.15, w: 5.4, h: 1.75, fontFace: MONO, fontSize: 12, margin: 0, lineSpacingMultiple: 1.25 });
footer(s, 8);

/* ---------------- SLIDE 9 — PRODUCTION READINESS ---------------- */
s = p.addSlide(); s.background = { color: BG };
kicker(s, "Production readiness");
title(s, "Boring where it counts");
const ops = [
  { n: "920 MB", l: "hard Docker RAM ceiling across 4 containers (budget: 1,500 MB)", c: PRIMARY },
  { n: "< 100 ms", l: "inspector updates over WebSocket per protocol hop", c: PRIMARY },
  { n: "0", l: "npm audit vulnerabilities across all services (HIGH body-parser patched)", c: ACCENT },
  { n: "1", l: "command to run: docker compose up --build — offline, no config", c: PRIMARY },
  { n: "Apache-2.0", l: "OSI-approved license; zero proprietary or paid APIs", c: PRIMARY },
  { n: "~15 MB", l: "idle V8 heap per service — runs on a laptop", c: PRIMARY },
];
ops.forEach((o, i) => {
  const x = M + (i % 3) * 4.13, y = 2.0 + Math.floor(i / 3) * 2.15;
  card(s, x, y, 3.85, 1.9);
  s.addText(o.n, { x: x + 0.25, y: y + 0.2, w: 3.3, h: 0.65, fontFace: MONO, fontSize: 30, bold: true, color: o.c, margin: 0 });
  s.addText(o.l, { x: x + 0.25, y: y + 0.92, w: 3.35, h: 0.9, fontFace: SANS, fontSize: 12, color: MUTED, margin: 0, lineSpacingMultiple: 1.15 });
});
s.addText("Healthchecked containers · ordered startup · SQLite WAL persistence · CI workflow on push/PR/manual · fail-closed test exits on every suite", { x: M, y: 6.42, w: 12.1, h: 0.4, fontFace: MONO, fontSize: 12, color: MUTED, margin: 0 });
footer(s, 9);

/* ---------------- SLIDE 10 — CLOSE ---------------- */
s = p.addSlide(); s.background = { color: BG };
s.addShape(p.shapes.OVAL, { x: -2.4, y: 4.0, w: 6.6, h: 6.6, fill: { color: "0E1B33" }, line: { color: BORDER, width: 1 } });
s.addText("Proven,\nnot promised.", { x: M, y: 1.3, w: 7.0, h: 2.2, fontFace: SANS, fontSize: 60, bold: true, color: TEXT, margin: 0, lineSpacingMultiple: 1.0 });
s.addText("Real cryptography. Four credential formats. Eighteen attack vectors, each rejected with its exact error code. An honest audit that found and fixed its own vulnerabilities before you could. One command, 920 MB, Apache-2.0.", { x: M, y: 3.7, w: 6.9, h: 1.35, fontFace: SANS, fontSize: 16.5, color: MUTED, margin: 0, lineSpacingMultiple: 1.2 });
card(s, 7.85, 1.3, 4.88, 2.6, "0E1B33");
s.addText("FULL DOCUMENTATION IN THE REPO", { x: 8.1, y: 1.52, w: 4.4, h: 0.3, fontFace: MONO, fontSize: 11, color: PRIMARY, charSpacing: 2, margin: 0 });
s.addText([
  { text: "README.md", options: { color: ACCENT, fontFace: MONO, breakLine: true } },
  { text: "setup, architecture, compliance matrix, audit method", options: { color: MUTED, fontSize: 10.5, breakLine: true } },
  { text: "AUDIT_REPORT.md", options: { color: ACCENT, fontFace: MONO, breakLine: true } },
  { text: "defect register, evidence ledger, release assessment", options: { color: MUTED, fontSize: 10.5, breakLine: true } },
  { text: "docs/verification-matrix.md", options: { color: ACCENT, fontFace: MONO, breakLine: true } },
  { text: "requirement-to-test traceability, honest statuses", options: { color: MUTED, fontSize: 10.5 } },
], { x: 8.1, y: 1.95, w: 4.5, h: 1.85, fontFace: SANS, fontSize: 12.5, margin: 0, lineSpacingMultiple: 1.2 });
card(s, 7.85, 4.15, 4.88, 1.1, "0E1B33");
s.addText([
  { text: "JUDGE_TESTING_GUIDE.md", options: { color: ACCENT, fontFace: MONO, breakLine: true } },
  { text: "acceptance checklist — verify every claim yourself", options: { color: MUTED, fontSize: 10.5 } },
], { x: 8.1, y: 4.32, w: 4.5, h: 0.8, fontFace: SANS, fontSize: 12.5, margin: 0, lineSpacingMultiple: 1.2 });
const verify = [
  "node scripts/start_local.js",
  "node scripts/test_e2e_local.js",
  "node scripts/test_security_regression.js",
  "bash scripts/cli_interop_runner.sh",
];
card(s, M, 5.5, 6.9, 1.5, "0E1B33");
s.addText("VERIFY EVERYTHING YOURSELF", { x: M + 0.25, y: 5.62, w: 6.2, h: 0.28, fontFace: MONO, fontSize: 10.5, color: PRIMARY, charSpacing: 2, margin: 0 });
s.addText(verify.map((t, j) => ({ text: "$ " + t, options: { breakLine: j < verify.length - 1 } })), { x: M + 0.25, y: 5.92, w: 6.4, h: 1.0, fontFace: MONO, fontSize: 11.5, color: ACCENT, margin: 0, lineSpacingMultiple: 1.2 });
s.addText("MOSIP Decode 2026 · Problem Statement 02 · Thank you", { x: M, y: 7.02, w: 12.1, h: 0.35, fontFace: MONO, fontSize: 12, color: TEXT, margin: 0 });

p.writeFile({ fileName: "PITCH_DECK.pptx" }).then(() => console.log("PITCH_DECK.pptx written"));
