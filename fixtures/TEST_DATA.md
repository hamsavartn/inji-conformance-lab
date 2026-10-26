# Test Data & Cryptographic Fixtures Dossier
## MOSIP Inji Conformance Laboratory & Interoperability Hub

This dossier catalogs all pre-seeded cryptographic keys, identity subjects, verifiable credential schemas, ISO/IEC 18013-5 mdoc data structures, and adversarial chaos injection vectors utilized across the Conformance Suite.

---

## 1. Cryptographic Key Inventory

### 1.1 Mock Inji Certify Issuer Keypair (P-256 / ES256)
- **Key ID (`kid`):** `inji-mock-issuer-key-1`
- **Algorithm (`alg`):** `ES256` (ECDSA using P-256 and SHA-256)
- **Key Type (`kty`):** `EC`
- **Curve (`crv`):** `P-256`
- **Signature Representation:** RFC 7515 IEEE P1363 64-byte raw $r \parallel s$ concatenated octets with low-$S$ canonicalization ($s \le \lfloor L/2 \rfloor$, VULN-01 compliance).
- **Public JWK:**
```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "inji-mock-issuer-key-1",
  "use": "sig",
  "alg": "ES256",
  "x": "WKn-EgA-pqP8clFY_gHnrn7G649Xy2238jW9LzHknl4",
  "y": "r8bB2_71qQ87q2Bq088sHk-023n81bK4l6y841_Jq7Q"
}
```

### 1.2 Synthetic Holder Agent Ephemeral Keypair (Key Binding)
- **Algorithm (`alg`):** `ES256`
- **Holder Public Key Claim in Credential (`cnf.jwk`):**
  Embedded directly inside the SD-JWT issuer payload to cryptographically tether the credential to the holder device.
- **Proof-of-Possession Mechanism:** RFC 9901 Key Binding JWT (`kb+jwt`) signed by the holder's private key, carrying verifier-issued `nonce`, `aud`, `iat`, and `sd_hash`.

### 1.3 Client DPoP Ephemeral Keypair (RFC 9449)
- **Algorithm (`alg`):** `ES256`
- **Header:** `typ: "dpop+jwt"`, `jwk: { kty: "EC", crv: "P-256", ... }`
- **Claims:**
  - `jti`: Unique base64url UUID (checked against the 300-second sliding replay cache)
  - `htm`: HTTP Method (`POST`)
  - `htu`: Normalized canonical URI (e.g. `http://localhost:8080/token` or `http://localhost:8080/credential`)
  - `ath`: Base64url-encoded SHA-256 digest of the access token string (mandatory on `/credential` per RFC 9449 §4.2)

---

## 2. Test Identity Subjects & Credentials

### 2.1 Canonical MOSIP Citizen Subject
- **Unique Identification Number (UIN):** `123456789012`
- **Full Legal Name:** `John Doe`
- **Date of Birth:** `1990-01-01`
- **Gender:** `M`
- **Residential Address:** `123 MOSIP Way, Tech City`
- **Biometric Modalities Enrolled:** Face, Dual Iris, 10-Fingerprint (Mock Template Hashes)
- **Issuing Authority:** MOSIP National Identity Authority (`did:web:injicertify-mock.collab.mosip.net`)

### 2.2 Pre-Authorized Issuance Code
- **Code:** `demo-pre-auth-code-12345`
- **User PIN:** `1234`
- **Grant Type:** `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- **Scope:** `MosipIdentityCredential`

---

## 3. Supported Credential Formats & Wire Payloads

### 3.1 Format 1: `vc+sd-jwt` (IETF SD-JWT VC)
- **Profile:** RFC 9901 / `draft-ietf-oauth-sd-jwt-vc-08`
- **Type (`vct`):** `MosipIdentityCredential`
- **Structure:**
  ```
  <Issuer_Signed_JWT>~<Disclosure_1>~<Disclosure_2>~...~<Disclosure_N>~<KB_JWT>
  ```
- **Disclosures Included:**
  1. `["_salt_uin", "UIN", "123456789012"]`
  2. `["_salt_name", "fullName", "John Doe"]`
  3. `["_salt_dob", "dateOfBirth", "1990-01-01"]`
  4. `["_salt_gender", "gender", "M"]`
  5. `["_salt_address", "address", "123 MOSIP Way, Tech City"]`
- **Key Binding Hash (`sd_hash`):**
  $$ \text{sd\_hash} = \text{base64url}(\text{SHA-256}(\text{Issuer\_Signed\_JWT} \parallel \text{"\~"} \parallel \text{Disclosures})) $$

### 3.2 Format 2: `dc+sd-jwt` (Digital Credentials with SD-JWT)
- **Profile:** W3C Verifiable Credentials 2.0 enveloped in SD-JWT format
- **Type (`vct`):** `urn:mosip:id:national-id`
- **Features:** W3C context headers combined with selective disclosure salt arrays.

### 3.3 Format 3: `ldp_vc` (W3C JSON-LD Linked Data Proof)
- **Context:**
  - `https://www.w3.org/2018/credentials/v1`
  - `https://w3id.org/security/suites/ed25519-2020/v1`
- **Proof Suite:** `Ed25519Signature2020`
- **Verification Method:** `did:web:injicertify-mock.collab.mosip.net#key-1`

### 3.4 Format 4: `mso_mdoc` (ISO/IEC 18013-5 Mobile Driving Licence)
- **DocType:** `org.iso.18013.5.1.mDL`
- **Namespace:** `org.iso.18013.5.1`
- **Structure:** CBOR-encoded IssuerSigned structure with Mobile Security Object (MSO Tag 24) and DeviceSigned payload.
- **Data Elements & Digest IDs:**
  | Digest ID (`digestID`) | Element Identifier | Sample Value |
  | :--- | :--- | :--- |
  | `0` | `family_name` | `"Doe"` |
  | `1` | `given_name` | `"John"` |
  | `2` | `birth_date` | `"1990-01-01"` |
  | `3` | `issue_date` | `"2025-01-01"` |
  | `4` | `expiry_date` | `"2035-01-01"` |
  | `5` | `issuing_country` | `"IN"` |
  | `6` | `document_number` | `"DL-9876543210"` |
  | `7` | `portrait` | `h'FFD8FFE0...'` (JPEG bytes) |

---

## 4. Adversarial Chaos Vectors (Fuzzing Matrix)

The suite includes 8 deterministic mutation vectors defined in `fixtures/tamper_vectors.json`:

| ID | Vector Name | Target Field / Payload | Mutation Action | Expected HTTP | Expected RFC 7807 Error Code |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **VEC-01** | Issuer Signature Bit-Flip | JWS Signature Segment | Flips last base64url character | `400` | `INVALID_ISSUER_SIGNATURE` |
| **VEC-02** | KB-JWT Nonce Mismatch | `kb_jwt.payload.nonce` | Replaces with random UUID | `400` | `NONCE_MISMATCH` |
| **VEC-03** | Stripped Disclosure (`sd_hash`) | Disclosure stream | Drops 1st disclosure segment | `400` | `SD_HASH_MISMATCH` |
| **VEC-04** | Presentation Replay Attack | `kb_jwt.payload.jti` | Resubmits consumed presentation | `400` | `JTI_ALREADY_CONSUMED` |
| **VEC-05** | Expired Credential Injection | `payload.exp` | Sets timestamp 24h in past | `400` | `CREDENTIAL_EXPIRED` |
| **VEC-06** | Malformed Recursive Nesting | Recursive `_sd` array | Injects cyclic disclosure hash | `400` | `MALFORMED_NESTED_DISCLOSURE` |
| **VEC-07** | Untrusted Issuer Origin | `iss` claim in JWT | Points to attacker domain | `400` | `ERR_UNTRUSTED_ISSUER` |
| **VEC-08** | mdoc CBOR Value Tampering | `IssuerSignedItemBytes` | Changes family_name in CBOR | `400` | `ERR_MDOC_DIGEST_MISMATCH` |

---

## 5. Automated Verification & Usage

To execute automated validation against all fixtures:
```bash
# Full E2E protocol lifecycle (26 checks)
node scripts/test_e2e_local.js

# Cryptographic and security regressions (10 checks)
node scripts/test_security_regression.js

# ISO/IEC 18013-5 mdoc adversarial tampering & replay suite (4 checks)
node scripts/test_mdoc_tamper_and_replay.js
```
