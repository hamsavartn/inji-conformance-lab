# 04. Test Data & Results

This directory contains the complete test data dossier, sample credential vectors, adversarial tamper fixtures, and conformance test execution matrices for the **MOSIP Inji Conformance Laboratory**.

## Deliverables Included

1. **`TEST_DATA.md`**: Specification of all cryptographic test vectors, schema definitions, key pairs, and credential attributes used in testing.
2. **`sample_credentials.json`**: Standardized credential payloads across all supported formats:
   - SD-JWT VC (P-256 ES256 with 5 selective disclosures)
   - W3C VC JSON-LD (VerifiableCredential with Ed25519 signature)
   - ISO 18013-5 mdoc (`org.iso.18013.5.1.mDL` document type in CBOR format)
3. **`tamper_vectors.json`**: Adversarial test vectors used by Chaos Monkey to verify fail-closed defenses:
   - `VEC-01`: Issuer Signature Bit-Flip
   - `VEC-02`: Expired Credential Timestamp Replay
   - `VEC-03`: DPoP `ath` Access Token Mismatch
   - `VEC-04`: CBOR MSO Tag 24 Byte Truncation
   - `VEC-05`: Unauthorized Claim Injection
4. **`INTEROP_MATRIX.md`**: Cross-ecosystem interoperability results across 8 actor permutations and protocol profiles.
5. **`verification-matrix.md`**: Detailed step-by-step test verification table with protocol RFC citations and pass/fail criteria.
6. **`AUDIT_REPORT.md`**: Comprehensive security, cryptographic, and performance audit verifying:
   - **40/40 Passing Tests** (0 failures, exit code 0)
   - Cryptographic conformance to IEEE P1363 (RFC 7515 / OpenSSL raw `r || s` 64-byte format)
   - Complete RFC 9449 DPoP enforcement
