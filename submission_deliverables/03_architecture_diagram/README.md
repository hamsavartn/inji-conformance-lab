# 03. Architecture Diagrams & System Design

This directory contains the architectural documentation, system models, and sequence diagrams for the **MOSIP Inji Conformance Laboratory**.

## Deliverables Included

1. **`architecture.md`**: Comprehensive architectural specification detailing:
   - **System Topology**: Client-side React 18 SPA, Node.js V8 BFF Gateway, and decoupled Mock Services (`inji-net` bridge).
   - **Zero-Trust Boundary**: Complete separation between orchestration logic and cryptographic mock engines.
   - **Protocol Stack**:
     - **OpenID4VCI (Draft 13 & Draft 14)**: Credential Issuer Discovery, Credential Offer, DPoP (RFC 9449), Proof-of-Possession (`proof.jwt`).
     - **OpenID4VP (Draft 21–23)**: Presentation Exchange, `presentation_definition` (DIF PE 2.0), `/direct_post` response endpoint.
     - **Cryptographic Payloads**: SD-JWT VC (RFC 9901 / IETF), W3C Verifiable Credentials 1.1 / 2.0 (JSON-LD), ISO 18013-5 mdoc (CBOR Tag 24 + `COSE_Sign1`).
   - **Network Architecture**: Production single-port reverse proxy mapping for cloud hosts and local multi-container bridge networks.
   - **Mermaid Diagrams**: End-to-end multi-party sequence flows, data state machines, and fail-closed security models.
