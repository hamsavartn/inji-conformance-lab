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
const { decode: cborDecode, encode: cborEncode } = require('cbor-x');

const app = express();
const PORT = process.env.PORT || 8081;
const VERIFIER_URL = process.env.VERIFIER_URL || process.env.VERIFIER_BASE_URL || `http://localhost:${PORT}`;

app.use(cors());

// Concurrency semaphore on large payload ingestion to prevent V8 heap OOM (VULN-05, VULN-11)
let activeLargeUploads = 0;
const MAX_CONCURRENT_UPLOADS = 4;
app.use('/direct_post', (req, res, next) => {
  const contentLen = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLen > 5 * 1024 * 1024) {
    return res.status(413).json({
      type: 'https://mosip.io/errors/http/payload-too-large',
      title: 'Payload Too Large',
      status: 413,
      code: 'ERR_BUFFER_OVERFLOW_BLOCKED'
    });
  }
  if (contentLen > 256 * 1024) {
    if (activeLargeUploads >= MAX_CONCURRENT_UPLOADS) {
      return res.status(429).json({ error: 'too_many_requests', detail: 'Concurrent large payload limit reached' });
    }
    activeLargeUploads++;
    res.on('close', () => { activeLargeUploads = Math.max(0, activeLargeUploads - 1); });
  }
  next();
});
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false, limit: '5mb', parameterLimit: 100 }));

// In-memory verification sessions
const activeSessions = new Map();
const CLOCK_SKEW_TOLERANCE_SEC = 300; // 5 minutes per RFC 7519 / FAPI 2.0
const SESSION_TTL_MS = 300000;
const SESSION_SWEEP_INTERVAL_MS = 60000;
const SESSION_MAP_HARD_CAP = 5000;

// Periodic sweep so abandoned sessions cannot grow the map without bound
const sessionSweeper = setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [nonce, session] of activeSessions) {
    if (session.createdAt < cutoff) activeSessions.delete(nonce);
  }
}, SESSION_SWEEP_INTERVAL_MS);
if (typeof sessionSweeper.unref === 'function') sessionSweeper.unref();

// Trusted Issuer Registry & Key Cache (draft-ietf-oauth-sd-jwt-vc §3.5 / §4)
const TRUSTED_ISSUERS = new Set([
  'http://localhost:8080',
  'http://127.0.0.1:8080',
  'http://mock-certify:8080',
  'https://injicertify-mock.collab.mosip.net',
  'https://api.collab.mosip.net/v1/mimoto'
]);
if (process.env.ISSUER_URL) {
  TRUSTED_ISSUERS.add(process.env.ISSUER_URL.replace(/\/+$/, ''));
}
if (process.env.MOCK_CERTIFY_URL) {
  TRUSTED_ISSUERS.add(process.env.MOCK_CERTIFY_URL.replace(/\/+$/, ''));
}

const issuerJwksCache = new Map();

async function resolveTrustedIssuerJwk(iss, kid) {
  if (!iss) {
    throw new Error('ERR_MISSING_ISSUER: Credential payload missing iss claim');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(iss);
  } catch (e) {
    throw new Error(`ERR_MALFORMED_ISSUER_URL: '${iss}' is not a valid URL`);
  }

  // Prevent userinfo injection (@) SSRF tricks (e.g. http://localhost:8080@evil.attacker.example)
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error(`ERR_UNTRUSTED_ISSUER: URL userinfo (@) syntax rejected in iss '${iss}'`);
  }

  // Strict canonical origin + pathname matching against TRUSTED_ISSUERS
  const canonicalPath = (parsedUrl.pathname && parsedUrl.pathname !== '/')
    ? parsedUrl.pathname.replace(/\/+$/, '')
    : '';
  const normalizedIss = `${parsedUrl.origin}${canonicalPath}`;
  if (!TRUSTED_ISSUERS.has(normalizedIss)) {
    throw new Error(`ERR_UNTRUSTED_ISSUER: Issuer '${iss}' is not in the trusted registry`);
  }

  // Check in-memory cache
  const cached = issuerJwksCache.get(normalizedIss);
  if (cached && (Date.now() - cached.fetchedAt < 60000)) {
    if (kid) {
      const match = cached.keys.find(k => k.kid === kid);
      if (!match) {
        throw new Error(`ERR_ISSUER_KID_NOT_FOUND: Key ID '${kid}' not found in trusted issuer JWKS`);
      }
      return match;
    }
    if (cached.keys.length > 0) return cached.keys[0];
  }

  // Fetch from issuer /.well-known/jwks.json
  try {
    const jwksUrl = `${normalizedIss}/.well-known/jwks.json`;
    const res = await fetch(jwksUrl, { signal: AbortSignal.timeout(2500) });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.keys) && data.keys.length > 0) {
        issuerJwksCache.set(normalizedIss, { keys: data.keys, fetchedAt: Date.now() });
        if (kid) {
          const match = data.keys.find(k => k.kid === kid);
          if (!match) {
            throw new Error(`ERR_ISSUER_KID_NOT_FOUND: Key ID '${kid}' not found in trusted issuer JWKS`);
          }
          return match;
        }
        return data.keys[0];
      }
    }
  } catch (e) {
    if (e.message.includes('ERR_ISSUER_KID_NOT_FOUND')) throw e;
    if (cached && cached.keys.length > 0) {
      if (kid) {
        const match = cached.keys.find(k => k.kid === kid);
        if (!match) {
          throw new Error(`ERR_ISSUER_KID_NOT_FOUND: Key ID '${kid}' not found in trusted issuer JWKS`);
        }
        return match;
      }
      return cached.keys[0];
    }
  }

  throw new Error(`ERR_UNTRUSTED_ISSUER_KEY: Unable to resolve valid signing key for trusted issuer '${iss}'`);
}

// Cryptographic Curve Order & Normalization Constants (VULN-01)
const P256_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
const P256_HALF_ORDER = P256_ORDER / 2n;

function normalizeLowS(sBuffer, componentByteLength = 32) {
  let sVal = BigInt('0x' + (sBuffer.length > 0 ? sBuffer.toString('hex') : '0'));
  if (sVal > P256_HALF_ORDER) {
    sVal = P256_ORDER - sVal;
  }
  let sHex = sVal.toString(16);
  if (sHex.length % 2 !== 0) sHex = '0' + sHex;
  const rawS = Buffer.from(sHex, 'hex');
  if (rawS.length > componentByteLength) {
    throw new Error('ERR_SCALAR_OVERFLOW_AFTER_NORMALIZATION');
  }
  const paddedS = Buffer.alloc(componentByteLength, 0);
  rawS.copy(paddedS, componentByteLength - rawS.length);
  return paddedS;
}

function convertDerToP1363(derSig, componentByteLength = 32) {
  const buf = Buffer.isBuffer(derSig) ? derSig : Buffer.from(derSig);
  if (buf.length < 8 || buf[0] !== 0x30) {
    throw new Error('ERR_ASN1_DER_INVALID_SEQUENCE_TAG');
  }
  let offset = 1;
  let seqLen = buf[offset++];
  if (seqLen & 0x80) {
    const nBytes = seqLen & 0x7f;
    if (nBytes !== 1 || offset >= buf.length) throw new Error('ERR_ASN1_DER_INVALID_LENGTH');
    seqLen = buf[offset++];
  }
  if (offset + seqLen !== buf.length) {
    throw new Error('ERR_ASN1_DER_LENGTH_MISMATCH');
  }
  const readInt = () => {
    if (offset + 2 > buf.length || buf[offset++] !== 0x02) {
      throw new Error('ERR_ASN1_DER_EXPECTED_INTEGER_TAG');
    }
    const len = buf[offset++];
    if (len <= 0 || offset + len > buf.length) {
      throw new Error('ERR_ASN1_DER_INTEGER_OUT_OF_BOUNDS');
    }
    let intSlice = buf.subarray(offset, offset + len);
    offset += len;
    while (intSlice.length > 0 && intSlice[0] === 0x00) {
      intSlice = intSlice.subarray(1);
    }
    if (intSlice.length > componentByteLength) {
      throw new Error('ERR_ASN1_DER_SCALAR_OVERFLOW');
    }
    return intSlice;
  };
  const r = readInt();
  const sRaw = readInt();
  if (offset !== buf.length) {
    throw new Error('ERR_ASN1_DER_TRAILING_GARBAGE');
  }
  const rPadded = Buffer.alloc(componentByteLength, 0);
  r.copy(rPadded, componentByteLength - r.length);
  const sNormalized = normalizeLowS(sRaw, componentByteLength);
  return Buffer.concat([rPadded, sNormalized]);
}

/**
 * Deterministic JSON Canonicalization & W3C LD-Proof Input Hasher (VULN-09).
 */
function canonicalizeJsonDeterministic(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalizeJsonDeterministic).join(',')}]`;
  const sortedKeys = Object.keys(value).sort();
  return `{${sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJsonDeterministic(value[k])}`).join(',')}}`;
}

function computeLdpSigningInput(vcDocument, proofOptions) {
  const docClone = { ...vcDocument };
  delete docClone.proof;
  const proofClone = { ...proofOptions };
  delete proofClone.proofValue;
  delete proofClone.jws;
  const proofHash = crypto.createHash('sha256').update(canonicalizeJsonDeterministic(proofClone), 'utf8').digest();
  const docHash = crypto.createHash('sha256').update(canonicalizeJsonDeterministic(docClone), 'utf8').digest();
  return Buffer.concat([proofHash, docHash]);
}

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
 * Requires explicit trusted public key; never trusts unauthenticated header.jwk.
 */
function verifyJwsFlexible(compactJws, publicJwkOverride) {
  const parts = String(compactJws).split('.');
  if (parts.length !== 3) throw new Error('ERR_MALFORMED_JWS');

  const [hB64, pB64, sB64] = parts;
  const header = JSON.parse(Buffer.from(hB64, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(pB64, 'base64url').toString('utf8'));
  const sigBuf = Buffer.from(sB64, 'base64url');
  const signingInput = Buffer.from(`${hB64}.${pB64}`, 'ascii');

  const keyJwk = publicJwkOverride;
  if (!keyJwk && header.alg !== 'none') {
    throw new Error('ERR_UNTRUSTED_KEY: No trusted public key provided for verification');
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

// Root Landing Page & Developer Portal for Mock Inji Verify (Port 8081)
app.get('/', (req, res) => {
  if (req.accepts('html')) {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mock Inji Verify - OpenID4VP Verifier Portal</title>
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
        <span class="badge badge-green"><span class="pulse-dot"></span> Verifier Operational</span>
        <span class="badge badge-cyan">Port 8081 (Mock Verify)</span>
        <span class="badge badge-purple">OpenID4VP Draft 21-23</span>
      </div>
      <h1>Mock Inji Verify Simulator</h1>
      <p class="subtitle">Deterministic OpenID4VP Relying Party Simulator with RFC 9901 sd_hash &amp; DIF PE 2.0 multi-path validation</p>
      <div class="action-bar">
        <a href="http://localhost:3000" class="btn btn-primary" target="_blank">🖥️ Open Conformance UI (:3000)</a>
        <a href="/api/v1/request" class="btn btn-secondary" target="_blank">📋 Generate Auth Request</a>
        <a href="/health" class="btn btn-secondary" target="_blank">🩺 Health JSON</a>
      </div>
    </header>

    <div class="grid">
      <div class="card">
        <div class="card-title">Verification Spec</div>
        <div class="card-value">OpenID4VP Draft 23</div>
      </div>
      <div class="card">
        <div class="card-title">sd_hash Validation</div>
        <div class="card-value">RFC 9901 Active</div>
      </div>
      <div class="card">
        <div class="card-title">Active Sessions</div>
        <div class="card-value">${activeSessions.size} Pending</div>
      </div>
      <div class="card">
        <div class="card-title">Skew Tolerance</div>
        <div class="card-value">±300s (FAPI 2.0)</div>
      </div>
    </div>

    <div class="section-title">🌐 Laboratory Microservice Topology</div>
    <div class="services-nav">
      <a href="http://localhost:3000" class="btn btn-secondary" target="_blank">🖥️ Frontend UI (:3000)</a>
      <a href="http://localhost:4000" class="btn btn-secondary" target="_blank">🚀 Gateway Hub (:4000)</a>
      <a href="http://localhost:8080" class="btn btn-secondary" target="_blank">🏛️ Inji Certify Mock (:8080)</a>
      <a href="http://localhost:8081" class="btn btn-secondary" style="border-color: var(--cyan); color: var(--cyan);">🛡️ Inji Verify Mock (:8081)</a>
    </div>

    <div class="section-title">⚡ Available Verifier Endpoints</div>
    <div class="endpoint-list">
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/health" class="endpoint-path" target="_blank">/health</a>
        </div>
        <div class="endpoint-desc">Verifier health status, capabilities and version info</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-get">GET</span>
          <a href="/api/v1/request" class="endpoint-path" target="_blank">/api/v1/request</a>
        </div>
        <div class="endpoint-desc">Generates sample OpenID4VP Authorization Request with DIF PE 2.0 Presentation Definition</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/api/v1/request</span>
        </div>
        <div class="endpoint-desc">Parameterized Authorization Request generator supporting format selection</div>
      </div>
      <div class="endpoint-row">
        <div class="endpoint-info">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/direct_post</span>
        </div>
        <div class="endpoint-desc">OpenID4VP direct_post submission endpoint with RFC 9901 sd_hash &amp; IEEE P1363 validation</div>
      </div>
    </div>

    <footer>
      MOSIP Inji Conformance Laboratory &bull; Mock Inji Verify Microservice
    </footer>
  </div>
</body>
</html>`);
  } else {
    res.json({
      service: 'Mock Inji Verify (OpenID4VP Simulator)',
      status: 'OPERATIONAL',
      port: PORT,
      verifier_url: VERIFIER_URL,
      endpoints: {
        health: `${VERIFIER_URL}/health`,
        auth_request: `${VERIFIER_URL}/api/v1/request`,
        direct_post: `${VERIFIER_URL}/direct_post`
      }
    });
  }
});

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
function generateAuthRequestHandler(req, res) {
  const nonce = crypto.randomUUID();
  const format = (req.body && req.body.format) || (req.query && req.query.format) || 'vc+sd-jwt';

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
  if (activeSessions.size >= SESSION_MAP_HARD_CAP) {
    const oldest = activeSessions.keys().next().value;
    if (oldest !== undefined) activeSessions.delete(oldest);
  }
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
}

app.post('/api/v1/request', generateAuthRequestHandler);
app.get('/api/v1/request', generateAuthRequestHandler);

app.get('/requests/:nonce', (req, res) => {
  const session = activeSessions.get(req.params.nonce);
  if (!session) {
    return res.status(404).json({ error: 'session_not_found', error_description: 'Request has expired or is invalid' });
  }
  res.json(session.authRequest);
});

// OpenID4VP /direct_post Verification Endpoint
// DIF PE 2.0 field constraints declared by our authorization request: the verifier
// requires UIN (12-digit national ID pattern) and fullName in every presentation.
const REQUIRED_PRESENTED_CLAIMS = [
  { name: 'UIN', paths: ['credentialSubject.UIN', 'vc.credentialSubject.UIN', 'UIN'], pattern: /^[0-9]{12}$/ },
  { name: 'fullName', paths: ['credentialSubject.fullName', 'vc.credentialSubject.fullName', 'fullName'], pattern: null }
];

function resolveClaimPath(claims, dotPath) {
  let cursor = claims;
  for (const segment of dotPath.split('.')) {
    if (cursor === null || typeof cursor !== 'object' || !(segment in cursor)) return undefined;
    cursor = cursor[segment];
  }
  return cursor;
}

function findMissingRequiredClaims(mergedClaims) {
  const missing = [];
  for (const req of REQUIRED_PRESENTED_CLAIMS) {
    let value;
    for (const p of req.paths) {
      value = resolveClaimPath(mergedClaims, p);
      if (value !== undefined) break;
    }
    if (value === undefined || value === null || value === '') {
      missing.push(`${req.name} (not disclosed)`);
    } else if (req.pattern && !req.pattern.test(String(value))) {
      missing.push(`${req.name} (fails requested format ${req.pattern})`);
    }
  }
  return missing;
}

app.post('/direct_post', async (req, res) => {
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
      const tokenStr = String(cleanToken);
      const lastTildeIdx = tokenStr.lastIndexOf('~');
      if (lastTildeIdx <= 0) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_SD_JWT_INVALID_FORMAT_NO_TILDE'
        });
      }

      const exactSignedPrefix = tokenStr.slice(0, lastTildeIdx + 1);
      const kbJwt = tokenStr.slice(lastTildeIdx + 1);
      if (!kbJwt) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MISSING_KEY_BINDING_JWT: Holder key binding proof required'
        });
      }

      const prefixParts = tokenStr.slice(0, lastTildeIdx).split('~');
      const issuerJwt = prefixParts[0];
      const disclosures = prefixParts.slice(1);

      // RFC 9901 §4: Reject any empty disclosure segment caused by consecutive '~~' (VULN-02)
      for (const d of disclosures) {
        if (d.length === 0) {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: 'ERR_SD_JWT_EMPTY_DISCLOSURE_SEGMENT: Empty disclosure segment prohibited by RFC 9901'
          });
        }
      }

      // 1. Resolve Issuer Key from Trust Registry & Verify Issuer-Signed JWT Header & Payload (VULN-09)
      const parts = String(issuerJwt).split('.');
      if (parts.length !== 3) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MALFORMED_ISSUER_JWT'
        });
      }

      let unverifiedHdr, unverifiedPay;
      try {
        unverifiedHdr = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        unverifiedPay = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      } catch (e) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_INVALID_ISSUER_JWT_JSON'
        });
      }

      const trustedIssuerJwk = await resolveTrustedIssuerJwk(unverifiedPay.iss, unverifiedHdr.kid);
      const { header: issHdr, payload: issPay } = verifyJwsFlexible(issuerJwt, trustedIssuerJwk);
      if (!['vc+sd-jwt', 'dc+sd-jwt'].includes(issHdr.typ)) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_INVALID_SD_JWT_TYP_${issHdr.typ}: Must be vc+sd-jwt or dc+sd-jwt`
        });
      }

      // RFC 9901 _sd_alg check (VULN-02)
      if (issPay._sd_alg && issPay._sd_alg !== 'sha-256') {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_UNSUPPORTED_SD_ALG_${issPay._sd_alg}: Only sha-256 is supported`
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

        // VEC-04: Unbound Disclosure rejection
        if (!uniqueSdSet.has(digest)) {
          return res.status(400).json({
            error: 'invalid_presentation',
            error_description: `ERR_UNBOUND_DISCLOSURE_DIGEST: Disclosure digest ${digest} not bound by issuer _sd`
          });
        }

        disclosedClaims[claimName] = claimValue;
      }

      // 3. Mandatory Key Binding JWT (kb+jwt) & 'sd_hash' Verification (VULN-02, VEC-03)
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

      // Stateful Session Nonce Verification & Replay Protection (FINDING-03)
      if (!kbPay.nonce) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'ERR_MISSING_SESSION_NONCE: Key binding JWT must declare session nonce'
        });
      }

      // RFC 9901 §5.3: kb+jwt audience MUST match the verifier's client_id (checked before
      // any session state mutation so a bad audience never consumes the verifier nonce)
      const audienceOk = Array.isArray(kbPay.aud)
        ? kbPay.aud.includes(VERIFIER_URL)
        : kbPay.aud === VERIFIER_URL;
      if (!audienceOk) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_KB_JWT_AUD_MISMATCH: Key binding JWT audience '${kbPay.aud}' does not match this verifier's client_id '${VERIFIER_URL}'`
        });
      }

      const session = activeSessions.get(kbPay.nonce);
      if (!session) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_UNKNOWN_OR_EXPIRED_SESSION_NONCE: Presentation nonce is unknown or has expired'
        });
      }

      if (session.status === 'CONSUMED' || session.status === 'PROCESSING') {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_NONCE_ALREADY_CONSUMED: Presentation nonce has already been consumed (replay detected)'
        });
      }

      if (Date.now() - session.createdAt > 300000) {
        activeSessions.delete(kbPay.nonce);
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_UNKNOWN_OR_EXPIRED_SESSION_NONCE: Presentation session has timed out'
        });
      }

      session.status = 'PROCESSING';

      if (kbPay.iat !== undefined && Math.abs(now - kbPay.iat) > CLOCK_SKEW_TOLERANCE_SEC) {
        session.status = 'PENDING';
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_KB_JWT_IAT_OUTSIDE_SKEW_WINDOW'
        });
      }

      // RFC 9901 §5.2: sd_hash is a REQUIRED claim of the Key Binding JWT. A kb+jwt
      // without it is not bound to this specific presentation and must fail closed.
      if (!kbPay.sd_hash || typeof kbPay.sd_hash !== 'string') {
        session.status = 'PENDING';
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MISSING_SD_HASH: Key binding JWT must declare the sd_hash claim (RFC 9901 §5.2)'
        });
      }

      // RFC 9901 Exact sd_hash calculation over exactSignedPrefix
      const expectedSdHash = sha256Base64Url(exactSignedPrefix);

      if (kbPay.sd_hash !== expectedSdHash) {
        session.status = 'PENDING';
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
        session.status = 'PENDING';
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE: Unexpected credential type ${mergedClaims.vct}`
        });
      }

      // Evaluate Multi-path JSONPath fallback: $.credentialSubject.UIN || $.vc.credentialSubject.UIN || $.UIN
      const extractedUin = mergedClaims.credentialSubject?.UIN
        || mergedClaims.vc?.credentialSubject?.UIN
        || mergedClaims.UIN;

      // DIF PE 2.0 §6 / OpenID4VP: requested presentation fields (UIN + fullName) must be
      // disclosed and satisfy the input_descriptors filter constraints
      const missingRequired = findMissingRequiredClaims(mergedClaims);
      if (missingRequired.length > 0) {
        session.status = 'PENDING';
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_REQUIRED_CLAIM_NOT_DISCLOSED: Presentation does not satisfy the requested input_descriptors: ${missingRequired.join('; ')}`
        });
      }

      // Mark session as successfully consumed to prevent replay attacks
      session.status = 'CONSUMED';
      session.consumedAt = Date.now();

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
    // Expiration check (VULN-09)
    if (vcObj.expirationDate) {
      const expTime = new Date(vcObj.expirationDate).getTime();
      if (!isNaN(expTime) && (Date.now() - CLOCK_SKEW_TOLERANCE_SEC * 1000) > expTime) {
        return res.status(400).json({
          error: 'expired_credential',
          error_description: 'ERR_CREDENTIAL_EXPIRED: W3C VC has expired beyond allowable clock skew'
        });
      }
    }

    // INJIVER-1131 type check for W3C VC
    const types = Array.isArray(vcObj.type) ? vcObj.type : [vcObj.type];
    if (types.includes('LifeInsuranceCredential') && !types.includes('MosipIdentityCredential')) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE: Expected MosipIdentityCredential'
      });
    }

    // Cryptographic Ed25519 signature verification (fail-closed: a missing trusted key or
    // missing proofValue is a rejection, never a silent bypass)
    if (!vcObj.proof.proofValue && !vcObj.proof.jws) {
      return res.status(400).json({
        error: 'invalid_signature',
        error_description: 'ERR_MISSING_LDP_PROOF_VALUE: W3C VC proof carries no proofValue/jws to verify'
      });
    }
    if (vcObj.proof.proofValue) {
      try {
        const rawProof = vcObj.proof.proofValue.startsWith('z') ? vcObj.proof.proofValue.slice(1) : vcObj.proof.proofValue;
        const sigBuffer = Buffer.from(rawProof, 'base64url');
        const issuerBase = String(vcObj.issuer || 'http://localhost:8080').replace(/\/+$/, '');
        await resolveTrustedIssuerJwk(issuerBase);
        const cached = issuerJwksCache.get(issuerBase);
        const edKey = cached?.keys?.find(k => k.crv === 'Ed25519' || k.kty === 'OKP');
        if (!edKey) {
          return res.status(400).json({
            error: 'invalid_signature',
            error_description: `ERR_UNTRUSTED_ISSUER_KEY: Trusted issuer '${issuerBase}' publishes no Ed25519 verification key; refusing to verify ldp_vc proof`
          });
        }
        const keyObj = crypto.createPublicKey({ key: edKey, format: 'jwk' });
        const signingInput = computeLdpSigningInput(vcObj, vcObj.proof);
        const valid = crypto.verify(null, signingInput, keyObj, sigBuffer);
        if (!valid) {
          return res.status(400).json({
            error: 'invalid_signature',
            error_description: 'ERR_INVALID_ED25519_PROOF_SIGNATURE: W3C VC Ed25519 signature verification failed'
          });
        }
      } catch (err) {
        return res.status(400).json({
          error: 'invalid_signature',
          error_description: `ERR_ED25519_VERIFICATION_FAILED: ${err.message}`
        });
      }
    }

    // Session Nonce & Replay Enforcement for ldp_vc presentations
    let ldpSubmissionObj = null;
    try {
      if (presentationSubmissionRaw) {
        ldpSubmissionObj = typeof presentationSubmissionRaw === 'string' ? JSON.parse(presentationSubmissionRaw) : presentationSubmissionRaw;
      }
    } catch (e) {}

    const ldpNonce = req.body.nonce || req.query?.nonce || ldpSubmissionObj?.nonce || vcObj.proof?.challenge || vcObj.proof?.nonce;
    if (!ldpNonce) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_MISSING_SESSION_NONCE: W3C VC presentation requires a valid session nonce'
      });
    }

    const session = activeSessions.get(ldpNonce);
    if (!session) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_UNKNOWN_OR_EXPIRED_SESSION_NONCE: Presentation nonce is unknown or has expired'
      });
    }
      if (session.status === 'CONSUMED' || session.status === 'PROCESSING') {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_NONCE_ALREADY_CONSUMED: Presentation nonce has already been consumed (replay detected)'
        });
      }
      if (Date.now() - session.createdAt > 300000) {
        activeSessions.delete(ldpNonce);
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_UNKNOWN_OR_EXPIRED_SESSION_NONCE: Presentation session has timed out'
        });
      }

      // DIF PE 2.0: requested fields (UIN + fullName) must be present in the W3C VC too
      const ldpMissing = findMissingRequiredClaims(vcObj);
      if (ldpMissing.length > 0) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_REQUIRED_CLAIM_NOT_DISCLOSED: Presentation does not satisfy the requested input_descriptors: ${ldpMissing.join('; ')}`
        });
      }

      session.status = 'CONSUMED';
      session.consumedAt = Date.now();

    return res.json({
      status: 'OK',
      verification_result: 'SUCCESS',
      format: 'ldp_vc',
      issuer: vcObj.issuer,
      subject: vcObj.credentialSubject?.id,
      claims: vcObj.credentialSubject
    });
  }

  // Branch 3: ISO/IEC 18013-5 mdoc (CBOR Tag 24)
  let mdocObj = null;
  let rawCborBuffer = null;
  try {
    if (Buffer.isBuffer(cleanToken)) {
      rawCborBuffer = cleanToken;
    } else if (typeof cleanToken === 'string') {
      try {
        rawCborBuffer = Buffer.from(cleanToken, 'base64url');
      } catch (e) {
        rawCborBuffer = Buffer.from(cleanToken, 'utf8');
      }
    }
    if (rawCborBuffer && rawCborBuffer.length > 0) {
      mdocObj = cborDecode(rawCborBuffer);
    }
  } catch (e) {
    // Not valid CBOR
  }

  if (mdocObj && (mdocObj.docType === 'org.iso.18013.5.1.mDL' || (Array.isArray(mdocObj.documents) && mdocObj.documents[0]?.docType === 'org.iso.18013.5.1.mDL'))) {
    const doc = mdocObj.docType ? mdocObj : mdocObj.documents[0];
    const issuerSigned = doc.issuerSigned;
    if (!issuerSigned || !issuerSigned.issuerAuth) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_MALFORMED_MDOC: Missing issuerSigned or issuerAuth COSE_Sign1 structure'
      });
    }

    const issuerAuth = issuerSigned.issuerAuth;
    if (!Array.isArray(issuerAuth) || issuerAuth.length !== 4) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_MALFORMED_COSE_SIGN1: Expected 4-element COSE_Sign1 array'
      });
    }

    const [protectedHeadersBytes, unprotectedHeaders, payloadTag24, signatureBytes] = issuerAuth;
    const msoBytes = (payloadTag24 && payloadTag24.value) ? payloadTag24.value : payloadTag24;

    try {
      const trustedIssuerJwk = await resolveTrustedIssuerJwk('http://localhost:8080', 'mosip-issuer-key-2026');
      const sigStructure = ['Signature1', protectedHeadersBytes, Buffer.alloc(0), msoBytes];
      const toBeSigned = cborEncode(sigStructure);
      const keyObj = crypto.createPublicKey({ key: trustedIssuerJwk, format: 'jwk' });
      const valid = crypto.verify(
        'SHA256',
        toBeSigned,
        { key: keyObj, dsaEncoding: 'ieee-p1363' },
        signatureBytes
      );
      if (!valid) {
        return res.status(400).json({
          error: 'invalid_signature',
          error_description: 'ERR_INVALID_MDOC_SIGNATURE: COSE_Sign1 signature verification failed'
        });
      }
    } catch (err) {
      return res.status(400).json({
        error: 'invalid_signature',
        error_description: `ERR_MDOC_VERIFICATION_FAILED: ${err.message}`
      });
    }

    // Decode MobileSecurityObject to verify valueDigests against disclosed nameSpaces
    let msoObj;
    try {
      msoObj = cborDecode(msoBytes);
    } catch (e) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_MALFORMED_MSO: Unable to decode MobileSecurityObject'
      });
    }

    const expectedNamespaceDigests = msoObj?.valueDigests?.['org.iso.18013.5.1'];
    if (!expectedNamespaceDigests) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_MALFORMED_MSO: Missing org.iso.18013.5.1 in valueDigests'
      });
    }

    // Verify cryptographic SHA-256 hash for every attribute in nameSpaces (ISO/IEC 18013-5 §9.1.2.4)
    const extractedClaims = {};
    const items = issuerSigned.nameSpaces?.['org.iso.18013.5.1'] || [];
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_EMPTY_MDOC_NAMESPACES: No IssuerSignedItem elements found'
      });
    }

    for (const itemTag of items) {
      const rawItemBytes = (itemTag && itemTag.value) ? itemTag.value : (Buffer.isBuffer(itemTag) ? itemTag : cborEncode(itemTag));
      const computedDigest = crypto.createHash('sha256').update(rawItemBytes).digest();

      let itemObj;
      try {
        itemObj = (itemTag && itemTag.value) ? cborDecode(itemTag.value) : itemTag;
      } catch (e) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MALFORMED_ISSUER_SIGNED_ITEM: Cannot decode Tag 24 item'
        });
      }

      if (!itemObj || typeof itemObj.digestID !== 'number' || !Number.isInteger(itemObj.digestID)) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: 'ERR_MALFORMED_ISSUER_SIGNED_ITEM: Missing or non-integer digestID in IssuerSignedItem'
        });
      }

      let expectedDigest = expectedNamespaceDigests instanceof Map
        ? expectedNamespaceDigests.get(itemObj.digestID)
        : (expectedNamespaceDigests[itemObj.digestID] || expectedNamespaceDigests[String(itemObj.digestID)]);

      if (!expectedDigest) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_UNBOUND_MDOC_DIGEST: Digest ID ${itemObj.digestID} not bound in MSO valueDigests`
        });
      }

      const expectedBuf = Buffer.isBuffer(expectedDigest) ? expectedDigest : Buffer.from(expectedDigest);
      if (!computedDigest.equals(expectedBuf)) {
        return res.status(400).json({
          error: 'invalid_presentation',
          error_description: `ERR_MDOC_DIGEST_MISMATCH: Attribute '${itemObj.elementIdentifier}' does not match MSO valueDigest (tampering detected)`
        });
      }

      if (itemObj.elementIdentifier) {
        extractedClaims[itemObj.elementIdentifier] = itemObj.elementValue;
      }
    }

    // Session Nonce & Replay Enforcement for mso_mdoc presentations (Fail-Closed)
    let submissionObj = null;
    try {
      if (presentationSubmissionRaw) {
        submissionObj = typeof presentationSubmissionRaw === 'string' ? JSON.parse(presentationSubmissionRaw) : presentationSubmissionRaw;
      }
    } catch (e) {}

    const mdocNonce = req.body.nonce || req.query?.nonce || submissionObj?.nonce;
    if (!mdocNonce) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_MISSING_SESSION_NONCE: mso_mdoc presentation requires a valid session nonce'
      });
    }

    const session = activeSessions.get(mdocNonce);
    if (!session) {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_UNKNOWN_OR_EXPIRED_SESSION_NONCE: Presentation nonce is unknown or has expired'
      });
    }
    if (session.status === 'CONSUMED' || session.status === 'PROCESSING') {
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_NONCE_ALREADY_CONSUMED: Presentation nonce has already been consumed (replay detected)'
      });
    }
    if (Date.now() - session.createdAt > 300000) {
      activeSessions.delete(mdocNonce);
      return res.status(400).json({
        error: 'invalid_presentation',
        error_description: 'ERR_UNKNOWN_OR_EXPIRED_SESSION_NONCE: Presentation session has timed out'
      });
    }
    session.status = 'CONSUMED';
    session.consumedAt = Date.now();

    return res.json({
      status: 'OK',
      verification_result: 'SUCCESS',
      format: 'mso_mdoc',
      doctype: doc.docType,
      issuer: 'http://localhost:8080',
      claims: extractedClaims
    });
  }

  // Universal Fallback: Reject any unparseable or unsupported payload with HTTP 400
  return res.status(400).json({
    error: 'invalid_presentation',
    error_description: 'ERR_UNSUPPORTED_OR_MALFORMED_VP_TOKEN: Presentation payload does not match any supported format (vc+sd-jwt, dc+sd-jwt, ldp_vc, mso_mdoc)'
  });
});

// Custom 404 Handler (Prevents raw "Cannot GET" errors)
app.use((req, res) => {
  if (req.accepts('html')) {
    res.status(404).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>404 - Endpoint Not Found | Mock Inji Verify</title>
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
    <h2>Endpoint Not Found on Mock Verifier</h2>
    <p>No route matches <code>${req.method} ${req.originalUrl}</code>.</p>
    <div class="actions">
      <a href="/" class="btn btn-primary">🛡️ Verifier Portal (/)</a>
      <a href="/api/v1/request" class="btn btn-secondary">📋 Auth Request</a>
      <a href="http://localhost:3000" class="btn btn-secondary">🖥️ Conformance UI (:3000)</a>
    </div>
  </div>
</body>
</html>`);
  } else {
    res.status(404).json({ error: 'not_found', method: req.method, path: req.originalUrl });
  }
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[MOCK-VERIFY] Inji Verify OpenID4VP Mock listening on port ${PORT}`);
    console.log(`[MOCK-VERIFY] Request generator: ${VERIFIER_URL}/api/v1/request`);
  });
}

module.exports = { app, resolveTrustedIssuerJwk };
