# UI/UX Design Specifications & Wireframes
## Project: Inji Interoperability Playground

---

## 1. Design Vision & Aesthetic Direction
The Inji Interoperability Playground is designed as a **cyber-grade, developer-first diagnostic dashboard**. It moves away from generic corporate templates, adopting a sleek dark-mode glassmorphic interface inspired by top developer tools (Vercel, Raycast, Postman, Wireshark).

### 1.1 Design Pillars
- **Radical Transparency**: Every protocol exchange, cryptographic signature, and HTTP header is visually surfaced without digging through hidden logs.
- **Cognitive Clarity**: Uses color-coded lanes, interactive sequence diagrams, and visual state indicators to explain high-complexity multi-module flows at a glance.
- **Immediate Responsiveness**: Instant UI feedback (< 50ms) using WebSocket event piping, live progress bars, and glowing status pulses.

---

## 2. Color Palette & Design Tokens

```css
:root {
  /* Surface Tokens */
  --bg-primary: #0B0F19;       /* Deep slate black */
  --bg-secondary: #111827;     /* Elevated panel background */
  --bg-tertiary: #1F2937;      /* Hover states & nested cards */
  --border-subtle: #374151;    /* Panel borders */
  --border-active: #6366F1;    /* Focused / Active node border */

  /* Brand & Accent Tokens */
  --accent-primary: #6366F1;   /* Electric Indigo */
  --accent-cyan: #06B6D4;      /* Cyber Cyan (VCI Issuance) */
  --accent-emerald: #10B981;   /* Emerald Green (Verified Pass) */
  --accent-amber: #F59E0B;     /* Amber Warning (Expired / Mismatch) */
  --accent-rose: #F43F5E;      /* Crimson Rose (Negative Fail / Tampered) */

  /* Typography Tokens */
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  --text-primary: #F9FAFB;
  --text-secondary: #9CA3AF;
  --text-muted: #6B7280;
}
```

---

## 3. UI Layout & Wireframe Architecture

```
+----------------------------------------------------------------------------------------------------+
|  [MOSIP LOGO]  Inji Interoperability Playground   |  Mode: [Live Sandbox]  |  [Tamper Mode: OFF]   |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  1. INTEROP MATRIX SELECTOR (3-COLUMN CONFIGURATOR)                                                |
|  +----------------------------+  +----------------------------+  +-------------------------------+ |
|  | ISSUER                     |  | WALLET / HOLDER            |  | VERIFIER / RELYING PARTY      | |
|  | (o) Inji Certify (Draft 13)|  | (o) Inji Web (React)       |  | (o) Inji Verify (Draft 21-23) | |
|  | ( ) Mock OpenID4VCI Issuer |  | ( ) Inji Mobile (QR Bridge)|  | ( ) Mock OpenID4VP Verifier   | |
|  | ( ) Walt.id External Mock  |  | ( ) Automated Agent Wallet |  | ( ) External VP Verifier      | |
|  | Status: [ONLINE 14ms]      |  | Status: [ONLINE 8ms]       |  | Status: [ONLINE 18ms]         | |
|  +----------------------------+  +----------------------------+  +-------------------------------+ |
|                                                                                                    |
|  Format: [ IETF SD-JWT VC (v1.0) v ]   Preset: [ National Identity Card v ]  [ RUN END-TO-END > ]  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  2. SPLIT-PANE REAL-TIME WORKSPACE                                                                 |
|  +--------------------------------------------+  +-----------------------------------------------+ |
|  | LEFT PANE: INTERACTIVE SEQUENCE DIAGRAM    |  | RIGHT PANE: DEEP PROTOCOL INSPECTOR           | |
|  |                                            |  | [Overview] [Raw JSON] [Decoded JWT] [Proofs]  | |
|  |   Issuer         Wallet        Verifier    |  |-----------------------------------------------| |
|  |     |   Offer       |             |        |  | HTTP 200 OK  POST /credential                 | |
|  |     |-------------->|             |        |  | Headers: Content-Type: application/json       | |
|  |     |   Token       |             |        |  | Payload: {                                    | |
|  |     |<=============>|             |        |  |   "format": "vc+sd-jwt",                      | |
|  |     |   Credential  |             |        |  |   "credential": "eyJhbGciOiJFUzI1NiIs...",    | |
|  |     |-------------->|             |        |  |   "c_nonce": "98a7sd6f-asdf-4991"             | |
|  |     |               |   Auth Req  |        |  | }                                             | |
|  |     |               |<------------|        |  |                                               | |
|  |     |               |   VP Token  |        |  | [ Copy Payload ]  [ Pretty Print ]  [ Decode ]| |
|  |     |               |------------>| (PASS) |  |                                               | |
|  +--------------------------------------------+  +-----------------------------------------------+ |
|                                                                                                    |
|  3. ADVERSARIAL TAMPER & STRESS WORKBENCH (NEGATIVE PATH TESTING)                                  |
|  [ ] Mutate Crypto Signature  [ ] Expire Validity Date  [ ] Strip Salted Disclosures  [ ] Spoof DID |
|                                                                                                    |
|  4. INTEROPERABILITY COMPATIBILITY SCORECARD                                                       |
|  Permutation                  Format      Status     Verification Code     Latency     Audit Log   |
|  ------------------------------------------------------------------------------------------------- |
|  Inji Certify -> Inji Web     SD-JWT      PASS       200 VERIFIED_OK       142ms       [View Log]  |
|  Walt.id Mock -> Inji Web     SD-JWT      PASS       200 VERIFIED_OK       189ms       [View Log]  |
|  Inji Certify -> Mock Wallet  W3C-LD      PASS       200 VERIFIED_OK       112ms       [View Log]  |
|  Inji Certify -> Inji Verify  SD-JWT      TAMPERED   400 ERR_SIG_INVALID   94ms        [View Log]  |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. Key UI Components Specification

### 4.1 Matrix Selector Card
- Contains a status pulse dot (Green: connected, Red: offline, Gray: mock).
- Pill badges indicating protocol standard supported (`OpenID4VCI D13`, `OpenID4VP D21-23`).
- Single-click radio selection updating the active execution topology.

### 4.2 Interactive Protocol Inspector
- **Overview Tab**: Highlights high-level metadata (Issued To DID, Issuer DID, Issued At, Expiry, Claims extracted).
- **Raw JSON Tab**: Monospace formatted syntax-highlighted editor with line numbers and diff comparison against RFC reference schemas.
- **Decoded JWT Tab**: Visual breakdown of 3 parts: Header (Red), Payload (Purple), Signature (Cyan). For SD-JWT, displays individual decoded disclosure salts alongside blinded hashes.
- **Cryptographic Proofs Tab**: Visual cryptographic tree showing verification key resolution, public key thumbprint, and signature algorithm validation.

### 4.3 Adversarial Tamper Workbench
- Collapsible bottom drawer with toggle cards.
- Clicking an attack vector pre-configures an interceptor that will mutate the payload just before presentation to the verifier, demonstrating Inji Verify's robust negative error handling.

### 4.4 Exportable Interoperability Report Modal
- Modal triggered by "Export Interoperability Report".
- Generates a polished, exportable report in both **Markdown format** (for GitHub PRs and documentation) and **JSON format** (for automated CI/CD gating).
