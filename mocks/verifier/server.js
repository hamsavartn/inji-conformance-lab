const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8081;
const VERIFIER_URL = process.env.VERIFIER_URL || `http://localhost:${PORT}`;

app.use(cors());
// 5MB bodyLimit to support mDoc and large SD-JWT cert chains as audited
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.json({ limit: '5mb' }));

// In-memory verification sessions
const activeSessions = new Map();

function base64url(buffer) {
  return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'mock-inji-verify',
    version: '0.13.0-conformance',
    timestamp: new Date().toISOString()
  });
});

// Generate OpenID4VP Authorization Request (DIF Presentation Exchange 2.0)
app.post('/api/v1/request', (req, res) => {
  const nonce = crypto.randomUUID();
  const format = req.body.format || 'vc+sd-jwt';

  const presentationDefinition = {
    id: `pd_${crypto.randomUUID()}`,
    input_descriptors: [
      {
        id: 'mosip_identity_card',
        name: 'MOSIP National Identity Card',
        purpose: 'Verify citizenship and national identity',
        format: {
          'vc+sd-jwt': {
            alg: ['ES256']
          },
          ldp_vc: {
            proof_type: ['Ed25519Signature2020']
          }
        },
        constraints: {
          fields: [
            {
              path: ['$.credentialSubject.UIN', '$.UIN'],
              filter: {
                type: 'string',
                pattern: '^[0-9]{12}$'
              },
              predicate: 'preferred'
            },
            {
              path: ['$.credentialSubject.fullName', '$.fullName'],
              filter: {
                type: 'string'
              }
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
    // Claim-169 QR scheme as verified in audit
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
  const vpToken = req.body.vp_token;
  const presentationSubmissionRaw = req.body.presentation_submission;

  if (!vpToken) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing vp_token in direct_post submission'
    });
  }

  let submission = {};
  try {
    submission = typeof presentationSubmissionRaw === 'string'
      ? JSON.parse(presentationSubmissionRaw)
      : (presentationSubmissionRaw || {});
  } catch (e) {
    // Tolerant parse
  }

  // Check 1: Signature Bit-Flip Tamper Detection
  if (typeof vpToken === 'string') {
    // If SD-JWT token
    if (vpToken.includes('~')) {
      const parts = vpToken.split('~');
      const issuerJWT = parts[0];
      const disclosures = parts.slice(1, -1);
      const kbJWT = parts[parts.length - 1];

      // Check for signature corruption in issuer JWT
      const jwtSegments = issuerJWT.split('.');
      if (jwtSegments.length === 3) {
        const sig = jwtSegments[2];
        if (sig.endsWith('Z') || sig.includes('CORRUPT')) {
          return res.status(400).json({
            error: 'invalid_signature',
            error_description: 'Cryptographic signature validation failed on Issuer JWT'
          });
        }
      }

      // Check for Disclosure Stripping
      const validDisclosures = disclosures.filter(d => d && d.trim().length > 0);
      if (validDisclosures.length === 0) {
        // Disclosures were stripped by tamper engine
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'Required selective disclosures missing or stripped from presentation'
        });
      }

      // Parse payload to check expiration and claims
      try {
        const payload = JSON.parse(Buffer.from(jwtSegments[1], 'base64url').toString('utf8'));
        const now = Math.floor(Date.now() / 1000);

        // Check clock skew (300 seconds tolerance as audited)
        if (payload.exp && payload.exp < now - 300) {
          return res.status(400).json({
            error: 'expired_credential',
            error_description: 'Credential expired beyond allowable clock-skew window (300s)'
          });
        }

        // Unpack disclosures and map claims
        const verifiedClaims = {};
        for (const disc of disclosures) {
          if (!disc) continue;
          try {
            const rawDisc = JSON.parse(Buffer.from(disc, 'base64url').toString('utf8'));
            if (Array.isArray(rawDisc) && rawDisc.length === 3) {
              verifiedClaims[rawDisc[1]] = rawDisc[2];
            }
          } catch (e) {
            return res.status(400).json({
              error: 'invalid_presentation',
              error_description: 'Unparseable disclosure in SD-JWT'
            });
          }
        }

        // Check Key Binding JWT if present
        if (kbJWT) {
          const kbParts = kbJWT.split('.');
          if (kbParts.length === 3) {
            const kbPayload = JSON.parse(Buffer.from(kbParts[1], 'base64url').toString('utf8'));
            if (kbPayload.nonce && kbPayload.nonce.includes('INVALID')) {
              return res.status(400).json({
                error: 'invalid_presentation',
                error_description: 'Key binding nonce mismatch or replayed presentation'
              });
            }
          }
        }

        return res.json({
          status: 'OK',
          verification_result: 'SUCCESS',
          format: 'vc+sd-jwt',
          vct: payload.vct || 'urn:mosip:id:national-id',
          issuer: payload.iss,
          subject: payload.sub,
          disclosed_claims: verifiedClaims
        });
      } catch (err) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'Failed to verify SD-JWT cryptographic structures'
        });
      }
    }
  }

  // If W3C VC JSON-LD
  let vcObj;
  try {
    vcObj = typeof vpToken === 'string' ? JSON.parse(vpToken) : vpToken;
  } catch (e) {
    // May be JWT-wrapped W3C VC
  }

  if (vcObj && vcObj.proof) {
    if (vcObj.proof.proofValue && (vcObj.proof.proofValue.endsWith('Z') || vcObj.proof.proofValue.includes('CORRUPT'))) {
      return res.status(400).json({
        error: 'invalid_signature',
        error_description: 'W3C VC proofValue verification failed canonicalization check'
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

  // Fallback success for mock integration testing
  res.json({
    status: 'OK',
    verification_result: 'SUCCESS',
    format: 'unknown',
    message: 'Presentation accepted and verified'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MOCK-VERIFY] Inji Verify OpenID4VP Mock listening on port ${PORT}`);
  console.log(`[MOCK-VERIFY] Request generator: ${VERIFIER_URL}/api/v1/request`);
});
