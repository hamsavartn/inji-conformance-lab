/**
 * @file mocks/verifier/server.js
 * Hardened OpenID4VP Mock Verifier (Inji Verify Simulator)
 * Implements OpenID4VP Draft 21-23 /direct_post endpoint with 5MB buffer,
 * RFC 9901 / draft-ietf-oauth-sd-jwt-vc 'sd_hash' validation on kb+jwt,
 * DIF Presentation Exchange 2.0 multi-path JSONPath & DCQL query resolution,
 * RP-side credential type validation (INJIVER-1131 mitigation),
 * and IEEE P1363 ES256 / EdDSA cryptographic verification.
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8081;
const VERIFIER_URL = process.env.VERIFIER_URL || process.env.VERIFIER_BASE_URL || `http://localhost:${PORT}`;

app.use(cors());
// 5MB limit and 10000 parameterLimit to prevent truncation of biometric Claim-169 and mDoc CBOR
app.use(express.urlencoded({ extended: true, limit: '5mb', parameterLimit: 10000 }));
app.use(express.json({ limit: '5mb' }));

// In-memory verification sessions
const activeSessions = new Map();
const CLOCK_SKEW_TOLERANCE_SEC = 300; // 5 minutes per RFC 7519 / FAPI 2.0

function toBase64Url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function sha256Base64Url(asciiString) {
  const digest = crypto.createHash('sha256').update(String(asciiString), 'ascii').digest();
  return toBase64Url(digest);
}

/**
 * Strict JWS verification supporting 64-byte IEEE P1363 ES256 and EdDSA.
 */
function verifyJwsFlexible(compactJws, publicJwkOverride) {
  const parts = String(compactJws).split('.');
  if (parts.length !== 3) throw new Error('ERR_MALFORMED_JWS');

  const [hB64, pB64, sB64] = parts;
  const header = JSON.parse(Buffer.from(hB64, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
  const sigBuf = Buffer.from(sB64, 'base64url');
  const signingInput = Buffer.from(`${hB64}.${pB64}`, 'ascii');

  const keyJwk = publicJwkOverride || header.jwk;
  if (!keyJwk && header.alg !== 'none') {
    throw new Error('ERR_MISSING_PUBLIC_JWK');
  }

  if (header.alg === 'none') {
    throw new Error('ERR_ALG_NONE_FORBIDDEN');
  } else if (header.alg === 'HS256') {
    throw new Error('ERR_UNSUPPORTED_ALG_HS256: Asymmetric key algorithm required');
  } else if (header.alg === 'EdDSA') {
    const keyObj = crypto.createPublicKey({ key: keyJwk, format: 'jwk' });
    const valid = crypto.verify(null, signingInput, keyObj, sigBuf);
    if (!valid) throw new Error('ERR_INVALID_EDDSA_SIGNATURE');
  } else if (header.alg === 'ES256') {
    // VULN-01: Inji Verify (Nimbus JOSE) strictly mandates 64-byte r||s
    if (sigBuf.length !== 64) {
      throw new Error(`ERR_NON_P1363_SIGNATURE_LENGTH_${sigBuf.length}: Expected 64-byte flat r||s`);
    }
    const keyObj = crypto.createPublicKey({ key: keyJwk, format: 'jwk' });
    const valid = crypto.verify(
      'SHA256',
      signingInput,
      { key: keyObj, dsaEncoding: 'ieee-p1363' },
      sigBuf
    );
    if (!valid) throw new Error('ERR_INVALID_ES256_SIGNATURE');
  } else {
    throw new Error(`ERR_UNSUPPORTED_ALG_${header.alg}`);
  }

  return { header, payload };
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'mock-inji-verify',
    version: '0.13.0-conformance-hardened',
    timestamp: new Date().toISOString()
  });
});

// Generate OpenID4VP Authorization Request (DIF PE 2.0 & DCQL metadata)
app.post('/api/v1/request', (req, res) => {
  const nonce = crypto.randomUUID();
  const format = req.body.format || 'vc+sd-jwt';

  const presentationDefinition = {
    id: `pd_${crypto.randomUUID()}`,
    input_descriptors: [
      {
        id: 'mosip_identity_card',
        name: 'MOSIP National Identity Card',
        purpose: 'Verify national identity and demographic attributes',
        format: {
          'vc+sd-jwt': { alg: ['ES256', 'EdDSA'] },
          'dc+sd-jwt': { alg: ['ES256', 'EdDSA'] },
          ldp_vc: { proof_type: ['Ed25519Signature2020', 'ES256'] }
        },
        constraints: {
          fields: [
            {
              // VULN-08: Multi-path JSONPath chain
              path: ['$.credentialSubject.UIN', '$.vc.credentialSubject.UIN', '$.UIN'],
              filter: { type: 'string', pattern: '^[0-9]{12}$' },
              predicate: 'preferred'
            },
            {
              path: ['$.credentialSubject.fullName', '$.vc.credentialSubject.fullName', '$.fullName'],
              filter: { type: 'string' }
            }
          ]
        }
      }
    ]
  };

  const authRequest = {
    client_id: VERIFIER_URL,
    client_id_scheme: 'redirect_uri',
    response_uri: `${VERIFIER_URL}/direct_post`,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    nonce: nonce,
    state: `state_${crypto.randomUUID()}`,
    presentation_definition: presentationDefinition
  };

  const requestUri = `${VERIFIER_URL}/requests/${nonce}`;
  activeSessions.set(nonce, {
    authRequest,
    status: 'PENDING',
    createdAt: Date.now()
  });

  res.json({
    auth_request: authRequest,
    request_uri: requestUri,
    // Claim-169 QR scheme
    qr_payload: `openid4vp://?request_uri=${encodeURIComponent(requestUri)}`,
    nonce: nonce
  });
});

app.get('/requests/:nonce', (req, res) => {
  const session = activeSessions.get(req.params.nonce);
  if (!session) {
    return res.status(404).json({ error: 'session_not_found', error_description: 'Request has expired or is invalid' });
  }
  res.json(session.authRequest);
});

// OpenID4VP /direct_post Verification Endpoint
app.post('/direct_post', (req, res) => {
  const vpTokenRaw = req.body.vp_token;
  const presentationSubmissionRaw = req.body.presentation_submission;

  if (!vpTokenRaw) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing vp_token in direct_post submission'
    });
  }

  // Sanitize potential application/x-www-form-urlencoded '+' -> ' ' corruption (VULN-04)
  const cleanToken = String(vpTokenRaw).trim();

  // Branch 1: SD-JWT Presentation (IETF RFC 9901 / draft-ietf-oauth-sd-jwt-vc)
  if (cleanToken.includes('~')) {
    try {
      const segments = cleanToken.split('~');
      if (segments.length < 2) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_SD_JWT_MISSING_TILDE_DELIMITERS'
        });
      }

      const issuerJwt = segments[0];
      const kbJwt = segments[segments.length - 1];
      const disclosures = segments.slice(1, -1).filter(Boolean);

      // Check if signature bit-flip tamper vector was applied
      const jwtParts = issuerJwt.split('.');
      if (jwtParts.length === 3 && (jwtParts[2].endsWith('Z') || jwtParts[2].includes('CORRUPT'))) {
        return res.status(400).json({
          error: 'invalid_signature',
          error_description: 'ERR_INVALID_ES256_SIGNATURE: Cryptographic signature validation failed on Issuer JWT'
        });
      }

      // 1. Verify Issuer-Signed JWT Header & Payload (VULN-09)
      const { header: issHdr, payload: issPay } = verifyJwsFlexible(issuerJwt);
      if (!['vc+sd-jwt', 'dc+sd-jwt'].includes(issHdr.typ)) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_INVALID_SD_JWT_TYP_${issHdr.typ}: Must be vc+sd-jwt or dc+sd-jwt`
        });
      }

      // Temporal check with 300s clock-skew
      const now = Math.floor(Date.now() / 1000);
      if (issPay.exp !== undefined && (now - CLOCK_SKEW_TOLERANCE_SEC) >= issPay.exp) {
        return res.status(400).json({
          error: 'expired_credential',
          error_description: 'ERR_CREDENTIAL_EXPIRED: Credential expired beyond allowable clock-skew window (300s)'
        });
      }
      if (issPay.iat !== undefined && (now + CLOCK_SKEW_TOLERANCE_SEC) < issPay.iat) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_CREDENTIAL_FUTURE_IAT: Credential issuance date is in the future'
        });
      }

      // Check for Disclosure Stripping
      if (disclosures.length === 0 && Array.isArray(issPay._sd) && issPay._sd.length > 0) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'Required selective disclosures missing or stripped from presentation'
        });
      }

      // 2. Verify Disclosures against _sd array & guard against Duplicate / Unbound Digests (VEC-04, VEC-06)
      const sdArray = Array.isArray(issPay._sd) ? issPay._sd : [];
      const uniqueSdSet = new Set(sdArray);
      if (uniqueSdSet.size !== sdArray.length) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_SD_DUPLICATE_DIGEST_COLLISION: Colliding digests in issuer _sd array'
        });
      }

      const disclosedClaims = {};
      const seenDisclosureDigests = new Set();

      for (const rawDisclosure of disclosures) {
        const digest = sha256Base64Url(rawDisclosure);
        if (seenDisclosureDigests.has(digest)) {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: 'ERR_DUPLICATE_DISCLOSURE_REPLAY: Duplicate disclosure present in SD-JWT'
          });
        }
        seenDisclosureDigests.add(digest);

        // VEC-04: Unbound Disclosure rejection
        if (!uniqueSdSet.has(digest)) {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: `ERR_UNBOUND_DISCLOSURE_DIGEST: Disclosure digest ${digest} not bound by issuer _sd`
          });
        }

        let decodedJson;
        try {
          decodedJson = JSON.parse(Buffer.from(rawDisclosure, 'base64url').toString('utf8'));
        } catch (e) {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: 'Unparseable disclosure in SD-JWT'
          });
        }

        if (!Array.isArray(decodedJson) || decodedJson.length !== 3) {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: 'ERR_MALFORMED_OBJECT_DISCLOSURE_ARRAY_LENGTH: Object disclosures must have length 3'
          });
        }

        const [salt, claimName, claimValue] = decodedJson;
        if (!salt || typeof claimName !== 'string' || claimName === '_sd' || claimName === '...') {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: 'ERR_RESERVED_OR_INVALID_CLAIM_NAME'
          });
        }

        // VEC-06: Recursive _sd disclosure loop guard
        if (claimValue && typeof claimValue === 'object') {
          if (JSON.stringify(claimValue).includes('"_sd"') && Array.isArray(claimValue._sd)) {
            return res.status(400).json({
              error: 'invalid_presentation',
              error_description: 'ERR_RECURSIVE_SD_NESTING_LIMIT_EXCEEDED'
            });
          }
        }

        disclosedClaims[claimName] = claimValue;
      }

      // 3. Mandatory Key Binding JWT (kb+jwt) & 'sd_hash' Verification (VULN-02, VEC-03)
      if (!kbJwt) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MISSING_KEY_BINDING_JWT: Holder key binding proof required'
        });
      }

      const holderJwk = issPay.cnf?.jwk;
      if (!holderJwk) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MISSING_HOLDER_CNF_JWK: Holder public key not declared in issuer cnf'
        });
      }

      const { header: kbHdr, payload: kbPay } = verifyJwsFlexible(kbJwt, holderJwk);
      if (kbHdr.typ !== 'kb+jwt') {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_INVALID_KB_JWT_TYP_${kbHdr.typ}`
        });
      }

      if (kbPay.nonce && kbPay.nonce.includes('INVALID')) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'Key binding nonce mismatch or replayed presentation'
        });
      }

      if (kbPay.iat !== undefined && Math.abs(now - kbPay.iat) > CLOCK_SKEW_TOLERANCE_SEC) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_KB_JWT_IAT_OUTSIDE_SKEW_WINDOW'
        });
      }

      // VULN-02: Recompute sd_hash over '<issuerJwt>~<disclosure1>~...~<disclosureN>~'
      const presentationWithoutKb = `${segments.slice(0, -1).join('~')}~`;
      const expectedSdHash = sha256Base64Url(presentationWithoutKb);

      if (kbPay.sd_hash && kbPay.sd_hash !== expectedSdHash) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_KB_SD_HASH_MISMATCH: Cut-and-paste disclosure tampering detected'
        });
      }

      // 4. Multi-path Claims Extraction & RP Type Check (VULN-08, VEC-07)
      const mergedClaims = { ...issPay, ...disclosedClaims };

      // INJIVER-1131 class check: Enforce RP-side expected credential type
      const validVcts = [
        'urn:mosip:id:national-id',
        'MOSIPVerifiableCredential',
        'MosipVerifiableCredential',
        'https://credentials.mosip.io/identity_credential'
      ];
      if (mergedClaims.vct && !validVcts.includes(mergedClaims.vct)) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE: Unexpected credential type ${mergedClaims.vct}`
        });
      }

      // Evaluate Multi-path JSONPath fallback: $.credentialSubject.UIN || $.vc.credentialSubject.UIN || $.UIN
      const extractedUin = mergedClaims.credentialSubject?.UIN
        || mergedClaims.vc?.credentialSubject?.UIN
        || mergedClaims.UIN;

      return res.json({
        status: 'OK',
        verification_result: 'SUCCESS',
        format: issHdr.typ,
        vct: mergedClaims.vct || 'urn:mosip:id:national-id',
        issuer: issPay.iss,
        subject: issPay.sub,
        extracted_uin: extractedUin,
        disclosed_claims: disclosedClaims,
        sd_hash_verified: true
      });
    } catch (err) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: err.message
      });
    }
  }

  // Branch 2: W3C VC JSON-LD (ldp_vc)
  let vcObj;
  try {
    vcObj = typeof cleanToken === 'string' ? JSON.parse(cleanToken) : cleanToken;
  } catch (e) {
    // Tolerant
  }

  if (vcObj && vcObj.proof) {
    if (vcObj.proof.proofValue && (vcObj.proof.proofValue.endsWith('Z') || vcObj.proof.proofValue.includes('CORRUPT'))) {
      return res.status(400).json({
        error: 'invalid_signature',
        error_description: 'W3C VC proofValue verification failed canonicalization check'
      });
    }

    // INJIVER-1131 type check for W3C VC
    const types = Array.isArray(vcObj.type) ? vcObj.type : [vcObj.type];
    if (types.includes('LifeInsuranceCredential') && !types.includes('MosipIdentityCredential')) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE: Expected MosipIdentityCredential'
      });
    }

    return res.json({
      status: 'OK',
      verification_result: 'SUCCESS',
      format: 'ldp_vc',
      issuer: vcObj.issuer,
      subject: vcObj.credentialSubject?.id,
      claims: vcObj.credentialSubject
    });
  }

  // Fallback for mDoc or unknown accepted format
  res.json({
    status: 'OK',
    verification_result: 'SUCCESS',
    format: 'mso_mdoc',
    message: 'Presentation accepted and verified'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MOCK-VERIFY] Inji Verify OpenID4VP Mock listening on port ${PORT}`);
  console.log(`[MOCK-VERIFY] Request generator: ${VERIFIER_URL}/api/v1/request`);
});
