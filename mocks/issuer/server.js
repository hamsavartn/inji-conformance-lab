const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const ISSUER_URL = process.env.ISSUER_URL || `http://localhost:${PORT}`;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory replay prevention & session store
const validPreAuthCodes = new Map([
  ['demo-pre-auth-code-12345', { subject: '123456789012', createdAt: Date.now() }]
]);
const activeCNonces = new Map();

// Helper: base64url encode/decode
function base64url(buffer) {
  return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

// Generate ephemeral EC keypair for ES256 signing
let issuerKeyPair;
try {
  issuerKeyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
} catch (e) {
  console.error('Failed to generate EC keypair:', e);
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'mock-inji-certify',
    version: '0.11.0-conformance',
    timestamp: new Date().toISOString()
  });
});

// OpenID4VCI Draft 13 Metadata Endpoint
app.get('/.well-known/openid-credential-issuer', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.json({
    credential_issuer: ISSUER_URL,
    authorization_server: ISSUER_URL,
    credential_endpoint: `${ISSUER_URL}/credential`,
    token_endpoint: `${ISSUER_URL}/token`,
    display: [
      {
        name: 'MOSIP Collab Conformance Mock Issuer',
        locale: 'en-US',
        logo: {
          url: 'https://mosip.io/assets/images/logo.png',
          alt_text: 'MOSIP Identity Logo'
        }
      }
    ],
    credentials_supported: [
      {
        id: 'MosipIdentityCredential_ldp_vc',
        format: 'ldp_vc',
        types: ['VerifiableCredential', 'MosipIdentityCredential'],
        cryptographic_binding_methods_supported: ['did:key', 'did:jwk'],
        cryptographic_suites_supported: ['Ed25519Signature2020', 'ES256'],
        display: [
          {
            name: 'MOSIP National Identity Card (W3C JSON-LD)',
            locale: 'en-US',
            background_color: '#1a365d',
            text_color: '#ffffff'
          }
        ],
        credential_definition: {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/suites/ed25519-2020/v1'
          ],
          type: ['VerifiableCredential', 'MosipIdentityCredential'],
          credentialSubject: {
            UIN: { display: [{ name: 'National Identity Number', locale: 'en-US' }] },
            fullName: { display: [{ name: 'Full Name', locale: 'en-US' }] },
            gender: { display: [{ name: 'Gender', locale: 'en-US' }] },
            dob: { display: [{ name: 'Date of Birth', locale: 'en-US' }] }
          }
        }
      },
      {
        id: 'MosipIdentitySDJWTCredential',
        format: 'vc+sd-jwt',
        vct: 'urn:mosip:id:national-id',
        cryptographic_binding_methods_supported: ['jwk'],
        cryptographic_suites_supported: ['ES256'],
        display: [
          {
            name: 'MOSIP National Identity Card (SD-JWT VC)',
            locale: 'en-US',
            background_color: '#064e3b',
            text_color: '#ffffff'
          }
        ],
        claims: {
          UIN: { mandatory: true, display: [{ name: 'National Identity Number' }] },
          fullName: { mandatory: true, display: [{ name: 'Full Name' }] },
          dob: { mandatory: false, display: [{ name: 'Date of Birth' }] },
          gender: { mandatory: false, display: [{ name: 'Gender' }] }
        }
      },
      {
        id: 'org.iso.18013.5.1.mDL',
        format: 'mso_mdoc',
        doctype: 'org.iso.18013.5.1.mDL',
        cryptographic_binding_methods_supported: ['cose_key'],
        cryptographic_suites_supported: ['ES256']
      }
    ]
  });
});

// OAuth 2.0 Authorization Server Discovery
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: ISSUER_URL,
    token_endpoint: `${ISSUER_URL}/token`,
    token_endpoint_auth_methods_supported: ['none'],
    grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    dpop_signing_alg_values_supported: ['ES256']
  });
});

// Credential Offer Generator
app.get('/credential-offer', (req, res) => {
  const code = 'pre-auth-' + crypto.randomUUID();
  validPreAuthCodes.set(code, {
    subject: req.query.uin || '987654321098',
    createdAt: Date.now()
  });

  const offer = {
    credential_issuer: ISSUER_URL,
    credentials: ['MosipIdentitySDJWTCredential', 'MosipIdentityCredential_ldp_vc'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': code,
        user_pin_required: false
      }
    }
  };

  res.json({
    credential_offer: offer,
    credential_offer_uri: `${ISSUER_URL}/offers/${code}`,
    qr_payload: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(`${ISSUER_URL}/offers/${code}`)}`
  });
});

app.get('/offers/:code', (req, res) => {
  const session = validPreAuthCodes.get(req.params.code);
  if (!session) {
    return res.status(404).json({ error: 'invalid_offer', error_description: 'Offer expired or invalid' });
  }

  res.json({
    credential_issuer: ISSUER_URL,
    credentials: ['MosipIdentitySDJWTCredential', 'MosipIdentityCredential_ldp_vc'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': req.params.code,
        user_pin_required: false
      }
    }
  });
});

// OpenID4VCI Token Endpoint
app.post('/token', (req, res) => {
  const grantType = req.body.grant_type;
  const preAuthCode = req.body['pre-authorized_code'] || req.body.pre_authorized_code;

  if (grantType !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only urn:ietf:params:oauth:grant-type:pre-authorized_code is supported'
    });
  }

  if (!preAuthCode || !validPreAuthCodes.has(preAuthCode)) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'The pre-authorized_code is invalid or has expired'
    });
  }

  // Consume pre-auth code (single use)
  const session = validPreAuthCodes.get(preAuthCode);
  validPreAuthCodes.delete(preAuthCode);

  // Generate dynamic c_nonce
  const cNonce = crypto.randomBytes(16).toString('hex');
  const accessToken = 'injicert_at_' + crypto.randomUUID();
  activeCNonces.set(cNonce, {
    accessToken,
    subject: session.subject,
    createdAt: Date.now()
  });

  // Check if DPoP was supplied
  const dpopHeader = req.headers['dpop'];
  const tokenType = dpopHeader ? 'DPoP' : 'Bearer';

  res.json({
    access_token: accessToken,
    token_type: tokenType,
    expires_in: 3600,
    c_nonce: cNonce,
    c_nonce_expires_in: 300
  });
});

// Helper: build pure ES256 JWT
function signJWT(header, payload, privateKey) {
  const encHeader = base64url(Buffer.from(JSON.stringify(header)));
  const encPayload = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${encHeader}.${encPayload}`;
  const sign = crypto.createSign('SHA256');
  sign.update(signingInput);
  sign.end();
  const signature = sign.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${base64url(signature)}`;
}

// OpenID4VCI /credential Endpoint
app.post('/credential', (req, res) => {
  // Validate Authorization header
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Missing Authorization header' });
  }

  // Check Draft 13 strict singular proof object (Jackson parser rule)
  if (req.body.proofs && !req.body.proof) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Draft 13 mandates singular proof object. Received Draft 14 proofs key.'
    });
  }

  const proof = req.body.proof;
  if (!proof || proof.proof_type !== 'jwt' || !proof.jwt) {
    return res.status(400).json({
      error: 'invalid_proof',
      error_description: 'A valid proof object with proof_type: jwt is mandatory'
    });
  }

  // Parse proof JWT header & payload
  const proofParts = proof.jwt.split('.');
  if (proofParts.length !== 3) {
    return res.status(400).json({ error: 'invalid_proof', error_description: 'Malformed proof JWT' });
  }

  let proofPayload;
  try {
    proofPayload = JSON.parse(Buffer.from(proofParts[1], 'base64url').toString('utf8'));
  } catch (e) {
    return res.status(400).json({ error: 'invalid_proof', error_description: 'Unparseable proof JWT payload' });
  }

  // Nonce validation
  if (!proofPayload.nonce || !activeCNonces.has(proofPayload.nonce)) {
    return res.status(400).json({
      error: 'invalid_proof',
      error_description: 'c_nonce is missing, invalid, or expired'
    });
  }

  const session = activeCNonces.get(proofPayload.nonce);
  activeCNonces.delete(proofPayload.nonce); // Replay prevention

  const format = req.body.format || 'vc+sd-jwt';

  if (format === 'vc+sd-jwt') {
    // Generate SD-JWT with salted disclosures
    // Object disclosure: [salt, claim_name, claim_value]
    const salt1 = base64url(crypto.randomBytes(16));
    const salt2 = base64url(crypto.randomBytes(16));
    const salt3 = base64url(crypto.randomBytes(16));
    const salt4 = base64url(crypto.randomBytes(16));

    const discUIN = base64url(Buffer.from(JSON.stringify([salt1, 'UIN', session.subject || '123456789012'])));
    const discName = base64url(Buffer.from(JSON.stringify([salt2, 'fullName', 'Aarav Kumar'])));
    const discGender = base64url(Buffer.from(JSON.stringify([salt3, 'gender', 'Male'])));
    const discDOB = base64url(Buffer.from(JSON.stringify([salt4, 'dob', '1995-08-15'])));

    const hashUIN = base64url(sha256(discUIN));
    const hashName = base64url(sha256(discName));
    const hashGender = base64url(sha256(discGender));
    const hashDOB = base64url(sha256(discDOB));

    const issuerHeader = { alg: 'ES256', typ: 'vc+sd-jwt' };
    const now = Math.floor(Date.now() / 1000);
    const issuerPayload = {
      iss: ISSUER_URL,
      sub: proofPayload.iss || 'did:jwk:holder-key-1',
      iat: now,
      nbf: now,
      exp: now + 31536000,
      vct: 'urn:mosip:id:national-id',
      _sd: [hashUIN, hashName, hashGender, hashDOB],
      _sd_alg: 'sha-256',
      cnf: {
        jwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'f83OJ3D2xFMTbKEAPH2Pe706SUO2wFbUqWJaJ2_WOYk',
          y: 'x_daQau3qTNm25W465oSUJUNfrL52N8bNw2160E_Cno'
        }
      }
    };

    const issuerJWT = signJWT(issuerHeader, issuerPayload, issuerKeyPair.privateKey);
    const sdjwtToken = `${issuerJWT}~${discUIN}~${discName}~${discGender}~${discDOB}~`;

    return res.json({
      format: 'vc+sd-jwt',
      credential: sdjwtToken,
      c_nonce: crypto.randomBytes(16).toString('hex'),
      c_nonce_expires_in: 300
    });
  }

  if (format === 'ldp_vc') {
    // Generate W3C VC JSON-LD
    const vc = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ],
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: ['VerifiableCredential', 'MosipIdentityCredential'],
      issuer: ISSUER_URL,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: proofPayload.iss || 'did:key:z6MkhaXgBZDvotDkL5257faiztiCEsJQFbB1jAhpU9g12345',
        UIN: session.subject || '123456789012',
        fullName: 'Aarav Kumar',
        gender: 'Male',
        dob: '1995-08-15'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${ISSUER_URL}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: 'z' + base64url(crypto.randomBytes(64))
      }
    };

    return res.json({
      format: 'ldp_vc',
      credential: vc,
      c_nonce: crypto.randomBytes(16).toString('hex'),
      c_nonce_expires_in: 300
    });
  }

  res.status(400).json({ error: 'unsupported_format', error_description: `Format ${format} not supported` });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MOCK-CERTIFY] Inji Certify OpenID4VCI Mock listening on port ${PORT}`);
  console.log(`[MOCK-CERTIFY] Discovery: ${ISSUER_URL}/.well-known/openid-credential-issuer`);
});
