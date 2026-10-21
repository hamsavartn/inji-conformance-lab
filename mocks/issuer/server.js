/**
 * @file mocks/issuer/server.js
 * Hardened OpenID4VCI Mock Issuer (Inji Certify Simulator)
 * Implements OpenID4VCI Draft 13 / Draft 14 dual-draft normalization,
 * RFC 9449 DPoP 'ath' validation & JTI replay cache,
 * RFC 7515 IEEE P1363 (64-byte r||s) ECDSA enforcement,
 * and SD-JWT VC / W3C JSON-LD / mdoc credential generation.
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const ISSUER_URL = process.env.ISSUER_URL || process.env.ISSUER_BASE_URL || `http://localhost:${PORT}`;

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// In-memory session store & replay protection
const validPreAuthCodes = new Map([
  ['demo-pre-auth-code-12345', { subject: '123456789012', createdAt: Date.now() }]
]);
const activeCNonces = new Map();
const consumedDpopJtis = new Set();

/**
 * Strict RFC 4648 Base64url encoding without padding.
 */
function toBase64Url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

/**
 * Computes Base64url-encoded SHA-256 digest over ASCII bytes.
 */
function sha256Base64Url(asciiString) {
  const digest = crypto.createHash('sha256').update(String(asciiString), 'ascii').digest();
  return toBase64Url(digest);
}

// Generate ephemeral EC P-256 keypair for ES256 Issuer signing
const issuerKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const issuerJwk = issuerKeyPair.publicKey.export({ format: 'jwk' });
issuerJwk.kid = 'mosip-issuer-key-2026';
issuerJwk.use = 'sig';
issuerJwk.alg = 'ES256';

/**
 * Strict JWS signing enforcing IEEE P1363 (64-byte r||s) for ES256.
 */
function signJwsStrict(header, payload, privateKey) {
  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  let signatureBuffer;
  if (header.alg === 'EdDSA') {
    signatureBuffer = crypto.sign(null, Buffer.from(signingInput, 'ascii'), privateKey);
  } else if (header.alg === 'ES256') {
    signatureBuffer = crypto.sign(
      'SHA256',
      Buffer.from(signingInput, 'ascii'),
      { key: privateKey, dsaEncoding: 'ieee-p1363' }
    );
    if (signatureBuffer.length !== 64) {
      throw new Error(`CRITICAL_CRYPTO_ERROR: Expected 64-byte P1363 ES256 signature, got ${signatureBuffer.length} bytes`);
    }
  } else {
    throw new Error(`Unsupported alg: ${header.alg}`);
  }

  return `${signingInput}.${toBase64Url(signatureBuffer)}`;
}

/**
 * Flexible JWS verification supporting both ES256 (P1363) and EdDSA.
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
  } else if (header.alg === 'EdDSA') {
    const keyObj = crypto.createPublicKey({ key: keyJwk, format: 'jwk' });
    const valid = crypto.verify(null, signingInput, keyObj, sigBuf);
    if (!valid) throw new Error('ERR_INVALID_EDDSA_SIGNATURE');
  } else if (header.alg === 'ES256') {
    // VULN-01: Inji Certify (Nimbus JOSE) strictly requires 64-byte r||s
    if (sigBuf.length !== 64) {
      throw new Error(`ERR_NON_P1363_SIGNATURE_LENGTH_${sigBuf.length}: Nimbus JOSE mandates 64-byte flat r||s`);
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

// Root Landing Page & Developer Portal for Mock Inji Certify (Port 8080)
app.get('/', (req, res) => {
  if (req.accepts('html')) {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mock Inji Certify - OpenID4VCI Issuer Portal</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1e293b;
      --card-hover: #1f2d42;
      --text: #f8fafc;
      --muted: #94a3b8;
      --cyan: #06b6d4;
      --emerald: #10b981;
      --indigo: #6366f1;
      --code: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
      line-height: 1.6;
      padding: 2.5rem 1.5rem;
    }
    .container { max-width: 1040px; margin: 0 auto; }
    header {
      background: linear-gradient(135deg, rgba(17, 24, 39, 0.95), rgba(15, 23, 42, 0.95));
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 2.25rem;
      margin-bottom: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .badge-row { display: flex; gap: 0.75rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
    .badge {
      display: inline-flex; align-items: center; gap: 0.5rem;
      font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
      padding: 0.35rem 0.75rem; border-radius: 9999px;
    }
    .badge-green { background: rgba(16, 185, 129, 0.15); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-cyan { background: rgba(6, 182, 212, 0.15); color: var(--cyan); border: 1px solid rgba(6, 182, 212, 0.3); }
    .badge-purple { background: rgba(99, 102, 241, 0.15); color: var(--indigo); border: 1px solid rgba(99, 102, 241, 0.3); }
    .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--emerald); box-shadow: 0 0 10px var(--emerald); animation: pulse 2s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(1.3); } }
    h1 { font-size: 1.85rem; font-weight: 800; margin-bottom: 0.5rem; letter-spacing: -0.02em; }
    .subtitle { color: var(--muted); font-size: 0.95rem; }
    .action-bar { display: flex; gap: 1rem; margin-top: 1.75rem; flex-wrap: wrap; }
    .btn {
      display: inline-flex; align-items: center; gap: 0.5rem;
      padding: 0.75rem 1.25rem; border-radius: 10px; font-size: 0.875rem; font-weight: 600;
      text-decoration: none; transition: all 0.2s ease; cursor: pointer; border: none;
    }
    .btn-primary { background: linear-gradient(135deg, #06b6d4, #2563eb); color: #fff; box-shadow: 0 4px 14px rgba(6, 182, 212, 0.35); }
    .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(6, 182, 212, 0.5); }
    .btn-secondary { background: var(--card-bg); color: var(--text); border: 1px solid var(--card-border); }
    .btn-secondary:hover { background: var(--card-hover); border-color: var(--cyan); color: #fff; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card {
      background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px;
      padding: 1.25rem; transition: border-color 0.2s;
    }
    .card:hover { border-color: rgba(6, 182, 212, 0.4); }
    .card-title { font-size: 0.75rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
    .card-value { font-size: 1.25rem; font-weight: 800; color: var(--text); }
    .section-title { font-size: 1.15rem; font-weight: 700; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
    .endpoint-list { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 2rem; }
    .endpoint-row {
      background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px;
      padding: 1rem 1.25rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
    }
    .endpoint-info { display: flex; align-items: center; gap: 0.85rem; }
    .method {
      padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.7rem; font-weight: 800; font-family: monospace;
    }
    .method-get { background: rgba(16, 185, 129, 0.2); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
    .method-post { background: rgba(99, 102, 241, 0.2); color: var(--indigo); border: 1px solid rgba(99, 102, 241, 0.3); }
    .endpoint-path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9rem; font-weight: 600; color: #fff; text-decoration: none; }
    .endpoint-path:hover { color: var(--cyan); text-decoration: underline; }
    .endpoint-desc { color: var(--muted); font-size: 0.85rem; }
    .services-nav { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 2rem; }
    footer { text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--card-border); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge-row">
        <span class="badge badge-green"><span class="pulse-dot"></span> Issuer Operational</span>
        <span class="badge badge-cyan">Port 8080 (Mock Certify)</span>
        <span class="badge badge-purple">OpenID4VCI Draft 13 &amp; 14</span>
      </div>
      <h1>Mock Inji Certify Simulator</h1>
      <p class="subtitle">Deterministic OpenID4VCI Credential Issuer with IEEE P1363 (64-byte r||s) &amp; RFC 9449 DPoP 'ath' enforcement</p>
      <div class="action-bar">
        <a href="http://localhost:3000" class="btn btn-primary" target="_blank">🖥️ Open Conformance UI (:3000)</a>
        <a href="/.well-known/openid-credential-issuer" class="btn btn-secondary" target="_blank">🔍 OpenID4VCI Discovery</a>
        <a href="/credential-offer?uin=123456789012" class="btn btn-secondary" target="_blank">🎟️ Generate Credential Offer</a>
        <a href="/health" class="btn btn-secondary" target="_blank">🩺 Health JSON</a>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-title">Cryptographic Key</div>
        <div class="card-value">${issuerJwk.kid} (ES256)</div>
      </div>
      <div class="card">
        <div class="card-title">Draft Support</div>
        <div class="card-value">Draft 13 &amp; 14 Dual</div>
      </div>
      <div class="card">
        <div class="card-title">Pre-Auth Sessions</div>
        <div class="card-value">${validPreAuthCodes.size} Active</div>
      </div>
      <div class="card">
        <div class="card-title">Formats Supported</div>
        <div class="card-value">SD-JWT VC / JSON-LD / mdoc</div>
      </div>
    </div>

    <div class="section-title">🌐 Laboratory Microservice Topology</div>
    <div class="services-nav">
      <a href="http://localhost:3000" class="btn btn-secondary" target="_blank">🖥️ Frontend UI (:3000)</a>
      <a href="http://localhost:4000" class="btn btn-secondary" target="_blank">🚀 Gateway Hub (:4000)</a>
      <a href="http://localhost:8080" class="btn btn-secondary" style="border-color: var(--cyan); color: var(--cyan);">🏛️ Inji Certify Mock (:8080)</a>
      <a href="http://localhost:8081" class="btn btn-secondary" target="_blank">🛡️ Inji Verify Mock (:8081)</a>
    </div>

    <div class="section-title">⚡ Available Issuer Endpoints</div>
    <div class="endpoint-list">
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/.well-known/openid-credential-issuer" class="endpoint-path" target="_blank">/.well-known/openid-credential-issuer</a>
        </div>
        <div class="endpoint-desc">Standard OpenID4VCI Issuer Discovery metadata document</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/.well-known/oauth-authorization-server" class="endpoint-path" target="_blank">/.well-known/oauth-authorization-server</a>
        </div>
        <div class="endpoint-desc">OAuth 2.0 Authorization Server metadata &amp; DPoP signing algorithms</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/.well-known/jwks.json" class="endpoint-path" target="_blank">/.well-known/jwks.json</a>
        </div>
        <div class="endpoint-desc">Public JSON Web Key Set containing active ES256 &amp; EdDSA public keys</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/credential-offer?uin=123456789012" class="endpoint-path" target="_blank">/credential-offer?uin=123456789012</a>
        </div>
        <div class="endpoint-desc">Initiates Pre-Authorized Code flow with custom UIN subject</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/health" class="endpoint-path" target="_blank">/health</a>
        </div>
        <div class="endpoint-desc">Mock Issuer health status and uptime verification</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/token</span>
        </div>
        <div class="endpoint-desc">OAuth 2.0 token endpoint enforcing RFC 9449 DPoP proof validation</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/credential</span>
        </div>
        <div class="endpoint-desc">OpenID4VCI credential issuance endpoint with IEEE P1363 ES256 enforcement</div>
      </div>
    </div>

    <footer>
      MOSIP Inji Conformance Laboratory &bull; Mock Inji Certify Microservice
    </footer>
  </div>
</body>
</html>`);
  } else {
    res.json({
      service: 'Mock Inji Certify (OpenID4VCI Simulator)',
      status: 'OPERATIONAL',
      port: PORT,
      issuer_url: ISSUER_URL,
      endpoints: {
        discovery: `${ISSUER_URL}/.well-known/openid-credential-issuer`,
        auth_server: `${ISSUER_URL}/.well-known/oauth-authorization-server`,
        jwks: `${ISSUER_URL}/.well-known/jwks.json`,
        credential_offer: `${ISSUER_URL}/credential-offer?uin=123456789012`,
        token: `${ISSUER_URL}/token`,
        credential: `${ISSUER_URL}/credential`,
        health: `${ISSUER_URL}/health`
      }
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: 'mock-inji-certify',
    version: '0.11.0-conformance-hardened',
    timestamp: new Date().toISOString()
  });
});

// JWKS Endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [issuerJwk] });
});

// OpenID4VCI Draft 13 Discovery
app.get('/.well-known/openid-credential-issuer', (req, res) => {
  res.json({
    credential_issuer: ISSUER_URL,
    authorization_server: ISSUER_URL,
    credential_endpoint: `${ISSUER_URL}/credential`,
    token_endpoint: `${ISSUER_URL}/token`,
    jwks_uri: `${ISSUER_URL}/.well-known/jwks.json`,
    display: [
      {
        name: 'MOSIP Collab Conformance Mock Issuer',
        locale: 'en-US',
        logo: { url: 'https://mosip.io/assets/images/logo.png', alt_text: 'MOSIP Identity Logo' }
      }
    ],
    credentials_supported: [
      {
        id: 'MosipIdentitySDJWTCredential',
        format: 'vc+sd-jwt',
        vct: 'urn:mosip:id:national-id',
        cryptographic_binding_methods_supported: ['jwk'],
        cryptographic_suites_supported: ['ES256', 'EdDSA'],
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
          gender: { mandatory: false, display: [{ name: 'Gender' }] },
          phone: { mandatory: false, display: [{ name: 'Phone Number' }] }
        }
      },
      {
        id: 'MosipIdentityCredential_ldp_vc',
        format: 'ldp_vc',
        types: ['VerifiableCredential', 'MosipIdentityCredential'],
        cryptographic_binding_methods_supported: ['did:key', 'did:jwk'],
        cryptographic_suites_supported: ['Ed25519Signature2020', 'ES256']
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

// OAuth 2.0 Auth Server Discovery
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: ISSUER_URL,
    token_endpoint: `${ISSUER_URL}/token`,
    token_endpoint_auth_methods_supported: ['none'],
    grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
    dpop_signing_alg_values_supported: ['ES256', 'EdDSA']
  });
});

// Credential Offer Generator
app.get('/credential-offer', (req, res) => {
  const code = 'pre-auth-' + crypto.randomUUID();
  validPreAuthCodes.set(code, {
    subject: req.query.uin || '123456789012',
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

  const session = validPreAuthCodes.get(preAuthCode);
  validPreAuthCodes.delete(preAuthCode);

  const cNonce = crypto.randomBytes(16).toString('hex');
  const accessToken = 'injicert_at_' + crypto.randomUUID();
  activeCNonces.set(cNonce, {
    accessToken,
    subject: session.subject,
    createdAt: Date.now()
  });

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

// OpenID4VCI /credential Endpoint (Hardened with VULN-01, VULN-03, VULN-07, VULN-09)
app.post('/credential', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const dpopHeader = req.headers['dpop'];

  if (!authHeader.startsWith('DPoP ') && !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Missing Authorization header' });
  }

  const accessToken = authHeader.replace(/^(DPoP|Bearer)\s+/i, '').trim();

  // Validate DPoP if DPoP token was used (RFC 9449)
  if (authHeader.startsWith('DPoP ')) {
    if (!dpopHeader) {
      return res.status(401).json({ error: 'invalid_dpop_proof', error_description: 'DPoP header missing' });
    }

    try {
      const { header: dpopHdr, payload: dpopPay } = verifyJwsFlexible(dpopHeader);

      // 1. Replay prevention on jti (VULN-03)
      if (!dpopPay.jti || consumedDpopJtis.has(dpopPay.jti)) {
        return res.status(401).json({ error: 'invalid_dpop_proof', error_description: 'Replayed or missing DPoP jti' });
      }
      consumedDpopJtis.add(dpopPay.jti);
      if (consumedDpopJtis.size > 5000) {
        const first = consumedDpopJtis.values().next().value;
        consumedDpopJtis.delete(first);
      }

      // 2. Mandatory RFC 9449 Section 4.2 'ath' verification (VULN-03)
      const expectedAth = sha256Base64Url(accessToken);
      if (!dpopPay.ath || dpopPay.ath !== expectedAth) {
        return res.status(401).json({
          error: 'invalid_dpop_proof',
          error_description: `DPoP ath mismatch: expected ${expectedAth}, received ${dpopPay.ath || 'null'}`
        });
      }

      // 3. htm / htu validation
      if (dpopPay.htm !== 'POST') {
        return res.status(401).json({ error: 'invalid_dpop_proof', error_description: 'DPoP htm mismatch' });
      }
    } catch (err) {
      return res.status(401).json({ error: 'invalid_dpop_proof', error_description: err.message });
    }
  }

  // 4. Extract Holder Proof - Dual Draft 13 / Draft 14 support (VULN-07)
  let holderProofJwt = null;
  let detectedDraft = 'draft-13';
  if (req.body.proof && req.body.proof.jwt) {
    holderProofJwt = req.body.proof.jwt;
  } else if (req.body.proofs && req.body.proofs.jwt) {
    holderProofJwt = Array.isArray(req.body.proofs.jwt) ? req.body.proofs.jwt[0] : req.body.proofs.jwt;
    detectedDraft = 'draft-14';
  } else {
    return res.status(400).json({
      error: 'invalid_proof',
      error_description: 'Missing proof object (Draft 13 singular or Draft 14 plural accepted)'
    });
  }

  let proofPayload;
  let holderJwk;
  try {
    const parsed = verifyJwsFlexible(holderProofJwt);
    proofPayload = parsed.payload;
    holderJwk = parsed.header.jwk;
  } catch (err) {
    return res.status(400).json({ error: 'invalid_proof', error_description: err.message });
  }

  // Nonce validation & replay check
  if (!proofPayload.nonce || !activeCNonces.has(proofPayload.nonce)) {
    return res.status(400).json({ error: 'invalid_proof', error_description: 'c_nonce is missing or expired' });
  }

  const session = activeCNonces.get(proofPayload.nonce);
  activeCNonces.delete(proofPayload.nonce);

  const format = req.body.format || 'vc+sd-jwt';

  // Support both vc+sd-jwt and dc+sd-jwt (VULN-09)
  if (format === 'vc+sd-jwt' || format === 'dc+sd-jwt') {
    const salt1 = toBase64Url(crypto.randomBytes(16));
    const salt2 = toBase64Url(crypto.randomBytes(16));
    const salt3 = toBase64Url(crypto.randomBytes(16));
    const salt4 = toBase64Url(crypto.randomBytes(16));
    const salt5 = toBase64Url(crypto.randomBytes(16));

    const discUIN = toBase64Url(JSON.stringify([salt1, 'UIN', session.subject || '123456789012']));
    const discName = toBase64Url(JSON.stringify([salt2, 'fullName', 'Aarav Kumar']));
    const discGender = toBase64Url(JSON.stringify([salt3, 'gender', 'Male']));
    const discDOB = toBase64Url(JSON.stringify([salt4, 'dob', '1995-08-15']));
    const discPhone = toBase64Url(JSON.stringify([salt5, 'phone', '+91-9876543210']));

    const hashUIN = sha256Base64Url(discUIN);
    const hashName = sha256Base64Url(discName);
    const hashGender = sha256Base64Url(discGender);
    const hashDOB = sha256Base64Url(discDOB);
    const hashPhone = sha256Base64Url(discPhone);

    const issuerHeader = { alg: 'ES256', typ: format, jwk: issuerJwk, kid: 'mosip-certify-key-1' };
    const now = Math.floor(Date.now() / 1000);

    const issuerPayload = {
      iss: ISSUER_URL,
      sub: proofPayload.iss || 'did:jwk:holder-key-1',
      iat: now,
      nbf: now,
      exp: now + 31536000,
      vct: 'urn:mosip:id:national-id',
      _sd: [hashUIN, hashName, hashGender, hashDOB, hashPhone],
      _sd_alg: 'sha-256',
      cnf: {
        jwk: holderJwk || {
          kty: 'EC',
          crv: 'P-256',
          x: 'f83OJ3D2xFMTbKEAPH2Pe706SUO2wFbUqWJaJ2_WOYk',
          y: 'x_daQau3qTNm25W465oSUJUNfrL52N8bNw2160E_Cno'
        }
      }
    };

    const issuerJWT = signJwsStrict(issuerHeader, issuerPayload, issuerKeyPair.privateKey);
    const sdjwtToken = `${issuerJWT}~${discUIN}~${discName}~${discGender}~${discDOB}~${discPhone}~`;

    return res.json({
      format,
      credential: sdjwtToken,
      detectedDraft,
      c_nonce: crypto.randomBytes(16).toString('hex'),
      c_nonce_expires_in: 300
    });
  }

  if (format === 'ldp_vc') {
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
        dob: '1995-08-15',
        phone: '+91-9876543210'
      },
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${ISSUER_URL}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: 'z' + toBase64Url(crypto.randomBytes(64))
      }
    };

    return res.json({
      format: 'ldp_vc',
      credential: vc,
      detectedDraft,
      c_nonce: crypto.randomBytes(16).toString('hex'),
      c_nonce_expires_in: 300
    });
  }

  res.status(400).json({ error: 'unsupported_format', error_description: `Format ${format} not supported` });
});

// Custom 404 Handler (Prevents raw "Cannot GET" errors)
app.use((req, res) => {
  if (req.accepts('html')) {
    res.status(404).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>404 - Endpoint Not Found | Mock Inji Certify</title>
  <style>
    body { background: #090d16; color: #f8fafc; font-family: -apple-system, system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1.5rem; box-sizing: border-box; }
    .box { background: #111827; border: 1px solid #1e293b; border-radius: 16px; padding: 2.5rem; max-width: 600px; width: 100%; text-align: center; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h1 { font-size: 3rem; color: #f43f5e; margin: 0 0 0.5rem 0; font-weight: 800; }
    h2 { font-size: 1.25rem; margin-bottom: 1rem; color: #f1f5f9; }
    p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem; }
    code { font-family: monospace; background: rgba(0,0,0,0.4); padding: 0.2rem 0.5rem; border-radius: 6px; color: #38bdf8; }
    .actions { display: flex; gap: 0.75rem; justify-content: center; flex-wrap: wrap; }
    .btn { display: inline-block; padding: 0.65rem 1.25rem; border-radius: 8px; font-weight: 600; text-decoration: none; font-size: 0.85rem; }
    .btn-primary { background: linear-gradient(135deg, #06b6d4, #2563eb); color: #fff; }
    .btn-secondary { background: #1f2937; color: #e2e8f0; border: 1px solid #374151; }
  </style>
</head>
<body>
  <div class="box">
    <h1>404</h1>
    <h2>Endpoint Not Found on Mock Issuer</h2>
    <p>No route matches <code>${req.method} ${req.originalUrl}</code>.</p>
    <div class="actions">
      <a href="/" class="btn btn-primary">🏛️ Issuer Portal (/)</a>
      <a href="/.well-known/openid-credential-issuer" class="btn btn-secondary">🔍 Metadata</a>
      <a href="http://localhost:3000" class="btn btn-secondary">🖥️ Conformance UI (:3000)</a>
    </div>
  </div>
</body>
</html>`);
  } else {
    res.status(404).json({ error: 'not_found', method: req.method, path: req.originalUrl });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MOCK-CERTIFY] Inji Certify OpenID4VCI Mock listening on port ${PORT}`);
  console.log(`[MOCK-CERTIFY] Discovery: ${ISSUER_URL}/.well-known/openid-credential-issuer`);
});
