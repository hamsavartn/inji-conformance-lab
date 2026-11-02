# 06. API Documentation

This directory contains the machine-readable API specifications and reference documentation for the **MOSIP Inji Conformance Laboratory**.

## Deliverables Included

1. **`openapi_spec.yaml`**: Full OpenAPI 3.0.3 specification covering all gateway and mock microservice endpoints.

## API Architecture & Endpoints Summary

### 1. BFF Gateway & Orchestration Engine
- `GET /api/v1/health`: System health and memory telemetry.
- `POST /api/v1/orchestrate/flow`: Multi-profile handshake orchestrator supporting:
  - OpenID4VCI Draft 13 & Draft 14
  - OpenID4VP Draft 21–23
  - SD-JWT VC, W3C JSON-LD, ISO 18013-5 mdoc
- `POST /api/v1/orchestrate/full-matrix`: Automated 8-lane conformance matrix test runner.
- `POST /api/v1/transpile/proof`: Real-time cross-draft key binding transpiler.
- `GET /api/v1/history`: Persistent audit log from SQLite.
- `WS /ws/telemetry`: Bidirectional WebSocket event stream.

### 2. Mock Inji Certify (Issuer)
- `GET /.well-known/openid-credential-issuer`: Metadata discovery endpoint.
- `GET /.well-known/jwks.json`: Issuer public JWKS key rotation endpoint.
- `POST /credential_offer`: Pre-authorized code credential offer generator.
- `POST /token`: OAuth2 / DPoP token exchange endpoint (Draft 13 & RFC 9449).
- `POST /credential`: Cryptographic credential issuance endpoint.

### 3. Mock Inji Verify (Verifier)
- `POST /api/v1/request`: OpenID4VP presentation definition generator (DIF PE 2.0).
- `POST /api/v1/verify`: Presentation verification engine with cryptographic signature, disclosure, and expiration checks.
