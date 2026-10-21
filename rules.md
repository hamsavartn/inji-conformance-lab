# Engineering, Governance & Hackathon Rules
## Project: Inji Interoperability Playground

---

## 1. Hackathon & Community Compliance Rules

1. **OSI-Approved Open Source Licensing**:
   - All developed source code must be licensed under an OSI-approved license.
   - **Chosen License**: **Apache License 2.0** (standard for MOSIP ecosystem projects).
   - A `LICENSE` file must be committed at the root of the repository.

2. **MOSIP Code of Conduct & Contributor Covenant**:
   - Zero tolerance for harassment, offensive imagery, derogatory commentary, or unauthorized personal data publishing.
   - Maintain professional, inclusive language across all commit messages, PR descriptions, inline code comments, and documentation.

3. **Academic & Originality Integrity**:
   - All code written must be original. Open-source libraries are permitted provided their licenses are compliant (MIT, Apache-2.0, BSD-3-Clause).
   - No plagiarized code or copy-pasting of non-attributed community work.

---

## 2. Engineering & Architecture Rules

1. **Strict Type Safety & Code Quality**:
   - TypeScript must be configured in `strict: true` mode.
   - No implicit `any` types.
   - All API payloads, DIDs, and credentials must have explicit Zod or TypeScript schema definitions.

2. **Cryptographic Standards Compliance**:
   - OpenID4VCI must adhere strictly to **Draft 13** specification schemas.
   - OpenID4VP must adhere strictly to **Draft 21–23** specification schemas (`presentation_definition`, `vp_token`, `presentation_submission`).
   - Cryptographic signatures must follow exact RFC specifications (`Ed25519Signature2020`, `ES256`, `EdDSA`).
   - Disclosures in SD-JWT must follow `sha-256` hashing with proper base64url encoding.

3. **Zero Hardcoded Secrets**:
   - No production private keys, cloud tokens, or hardcoded passwords in any codebase file.
   - Testing keys must use standard ephemeral key-pairs generated dynamically or loaded from seed fixtures clearly marked as `TEST_USE_ONLY`.

4. **Modular Architecture & Separation of Concerns**:
   - **Frontend** must contain only visual presentation, state rendering, and user interaction logic.
   - **BFF / Backend Orchestrator** handles external network requests, protocol normalization, and WebSocket dispatching.
   - **Mock Services** must be isolated so they can run independently or be swapped with live MOSIP Collab sandbox endpoints.

5. **One-Command Reproducibility**:
   - Any judge or evaluator must be able to clone the repository and run `docker compose up --build` with zero prior manual environment configuration required.
   - Default ports must not conflict with common OS services (Frontend: `3000`, BFF: `4000`, Mock Certify: `8080`, Mock Verify: `8081`).

---

## 3. Git Hygiene & Version Control Standards

1. **Semantic Commit Messages**:
   - `feat(ui)`: New feature in the playground interface.
   - `feat(vci)`: OpenID4VCI protocol implementation or update.
   - `feat(vp)`: OpenID4VP verification or presentation logic.
   - `fix(crypto)`: Fix for signature verification or disclosure parsing.
   - `test(matrix)`: Added new automated interop test cases.
   - `docs(readme)`: Updated installation or architectural guidelines.

2. **Commit History Progression**:
   - The commit history must reflect a realistic, progressive engineering journey showing setup, feature increments, bug fixes, and testing refinement as evaluated by the jury.

---

## 4. UI/UX & Accessibility Standards

1. **Visual Excellence**:
   - Premium aesthetic with dark-mode default, clean typography (Inter + JetBrains Mono for code payloads), smooth animations, and high-contrast status badges (Success: `#10B981`, Error: `#EF4444`, Warning: `#F59E0B`, Info: `#3B82F6`).
2. **Developer-First Usability**:
   - All JSON payloads must have 1-click **Copy to Clipboard** and **Format/Minify** toggles.
   - Raw JWTs must feature synchronized hover-decoding (hover over payload highlights corresponding encoded segment).
   - Clear loading and error states for all asynchronous network operations.
