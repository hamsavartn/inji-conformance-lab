/**
 * @file scripts/test_security_regression.js
 * Independent adversarial security regression suite (auditor-written).
 * Exercises genuine attacker-controlled flows with real cryptographic keys:
 *  SEC-01  Issuer /credential must reject unknown access tokens (401 invalid_token)
 *  SEC-02  kb+jwt without mandatory sd_hash must be rejected (RFC 9901 §5.2)
 *  SEC-03  kb+jwt with wrong audience must be rejected (RFC 9901 §5.3)
 *  SEC-04  Presentation missing verifier-required claims (UIN/fullName) must be rejected (DIF PE 2.0)
 *  SEC-05  Disclosed UIN violating the requested 12-digit pattern must be rejected
 *  SEC-06  Tampered ldp_vc Ed25519 proofValue must fail genuine signature verification
 *  SEC-07  verify-result trace_blob persisted to /api/v1/history must be PII-redacted
 *  SEC-08  Genuine single-use SD-JWT nonce replay must be rejected (ERR_NONCE_ALREADY_CONSUMED)
 *  SEC-09  Genuine single-use ldp_vc nonce replay must be rejected
 *  SEC-10  DPoP proof with wrong htm must be rejected at /token (RFC 9449 §4.2)
 *
 * Exits nonzero if any check fails.
 */

const crypto = require('crypto');

const BFF = 'http://localhost:4000';
const ISS = 'http://localhost:8080';
const VER = 'http://localhost:8081';

const results = [];
function assertCheck(id, description, passed, details = '') {
  results.push({ id, passed });
  const mark = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`[${id}] ${mark}: ${description}${details ? ` (${details})` : ''}`);
}

const b64u = (input) => Buffer.from(input).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
const sha256b64u = (s) => crypto.createHash('sha256').update(s, 'ascii').digest('base64url');

// Attacker/auditor-controlled wallet keypair (holder binding target)
const walletKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const walletJwk = walletKeys.publicKey.export({ format: 'jwk' });

function signEs256(header, payload, privateKey) {
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;
  const sig = crypto.sign('SHA256', Buffer.from(signingInput, 'ascii'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${signingInput}.${sig.toString('base64url')}`;
}

function dpopProof({ httpMethod, httpUrl, accessToken }) {
  const parsed = new URL(httpUrl);
  return signEs256(
    { typ: 'dpop+jwt', alg: 'ES256', jwk: walletJwk },
    {
      jti: crypto.randomUUID(),
      htm: httpMethod.toUpperCase(),
      htu: `${parsed.origin}${parsed.pathname}`,
      iat: now(),
      ...(accessToken ? { ath: sha256b64u(accessToken) } : {})
    },
    walletKeys.privateKey
  );
}

async function requestToken({ grantTypeHtm = 'POST' } = {}) {
  const offer = await fetch(`${ISS}/credential-offer?uin=123456789012`).then(r => r.json());
  const code = offer.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const dpop = signEs256(
    { typ: 'dpop+jwt', alg: 'ES256', jwk: walletJwk },
    { jti: crypto.randomUUID(), htm: grantTypeHtm.toUpperCase(), htu: `${ISS}/token`, iat: now() },
    walletKeys.privateKey
  );
  const tokenRes = await fetch(`${ISS}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: dpop },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': code
    }).toString()
  });
  return { status: tokenRes.status, body: await tokenRes.json() };
}

async function requestCredential({ accessToken, cNonce }) {
  const proof = signEs256(
    { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: walletJwk },
    { iss: 'did:jwk:audit-probe', aud: ISS, iat: now(), nonce: cNonce },
    walletKeys.privateKey
  );
  const dpop = dpopProof({ httpMethod: 'POST', httpUrl: `${ISS}/credential`, accessToken });
  const res = await fetch(`${ISS}/credential`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${accessToken}`, DPoP: dpop },
    body: JSON.stringify({ format: 'vc+sd-jwt', proof: { proof_type: 'jwt', jwt: proof } })
  });
  return { status: res.status, body: await res.json() };
}

/** Build an SD-JWT presentation from an issued token with the selected disclosure claim names. */
function buildPresentation({ issuedToken, claimNames, kbPayload }) {
  const parts = issuedToken.split('~');
  const issuerJwt = parts[0];
  const disclosures = parts.slice(1).filter(Boolean);
  const selected = disclosures.filter(d => {
    try {
      const dec = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
      return claimNames.includes(dec[1]);
    } catch (e) { return false; }
  });
  const prefix = `${issuerJwt}~${selected.join('~')}~`;
  const kb = signEs256({ typ: 'kb+jwt', alg: 'ES256' }, kbPayload(prefix), walletKeys.privateKey);
  return `${prefix}${kb}`;
}

async function getVerifierNonce() {
  const r = await fetch(`${VER}/api/v1/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ format: 'vc+sd-jwt' })
  }).then(r => r.json());
  return r.nonce;
}

async function directPost(vpToken, nonce) {
  const bodyParams = { vp_token: vpToken, presentation_submission: JSON.stringify({ id: 'sub_audit', definition_id: 'mosip_identity_card', descriptor_map: [{ id: 'mosip_identity_card', format: 'vc+sd-jwt', path: '$' }] }) };
  if (nonce) bodyParams.nonce = nonce;
  const res = await fetch(`${VER}/direct_post`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(bodyParams).toString()
  });
  return { status: res.status, body: await res.json() };
}

async function main() {
  try { await fetch(`${BFF}/api/v1/health`, { signal: AbortSignal.timeout(800) }); }
  catch (e) {
    console.error('[FATAL] Services are not running on 4000/8080/8081. Start them first (node scripts/start_local.js).');
    process.exit(2);
  }
  console.log('================================================================');
  console.log('   SECURITY REGRESSION SUITE (Auditor Adversarial Probes)      ');
  console.log('================================================================\n');

  // ---------------------------------------------------------------- SEC-01
  try {
    const tok = await requestToken();
    const forged = await requestCredential({ accessToken: 'FORGED_UNKNOWN_TOKEN_000', cNonce: tok.body.c_nonce });
    assertCheck('SEC-01', 'Issuer /credential rejects unknown/forged access token', forged.status === 401, `HTTP ${forged.status} ${forged.body.error || 'OK(DEFECT)'}`);
  } catch (e) { assertCheck('SEC-01', 'Issuer /credential rejects unknown access token', false, e.message); }

  // ---------------------------------------------------------------- SEC-10
  try {
    const badHtm = await requestToken({ grantTypeHtm: 'GET' });
    assertCheck('SEC-10', 'Issuer /token rejects DPoP proof with htm != POST', badHtm.status === 400 && badHtm.body.error === 'invalid_dpop_proof', `HTTP ${badHtm.status} ${badHtm.body.error || 'token issued (DEFECT)'}`);
  } catch (e) { assertCheck('SEC-10', 'Issuer /token rejects DPoP wrong htm', false, e.message); }

  // ---------------------------------------------------------------- SEC-02
  try {
    const tok = await requestToken();
    const cred = await requestCredential({ accessToken: tok.body.access_token, cNonce: tok.body.c_nonce });
    const nonce = await getVerifierNonce();
    const vp = buildPresentation({
      issuedToken: cred.body.credential,
      claimNames: ['UIN', 'fullName'],
      kbPayload: (prefix) => ({ iat: now(), aud: VER, nonce }) // sd_hash deliberately omitted
    });
    const res = await directPost(vp);
    assertCheck('SEC-02', 'kb+jwt without sd_hash rejected (RFC 9901 §5.2 mandatory)', res.status === 400, `HTTP ${res.status} ${res.body.error_description || 'SUCCESS(DEFECT)'}`);
  } catch (e) { assertCheck('SEC-02', 'kb+jwt without sd_hash rejected', false, e.message); }

  // ---------------------------------------------------------------- SEC-03
  try {
    const tok = await requestToken();
    const cred = await requestCredential({ accessToken: tok.body.access_token, cNonce: tok.body.c_nonce });
    const nonce = await getVerifierNonce();
    const vp = buildPresentation({
      issuedToken: cred.body.credential,
      claimNames: ['UIN', 'fullName'],
      kbPayload: (prefix) => ({ iat: now(), aud: 'https://evil.attacker.example', nonce, sd_hash: sha256b64u(prefix) })
    });
    const res = await directPost(vp);
    assertCheck('SEC-03', 'kb+jwt with foreign audience rejected (RFC 9901 §5.3)', res.status === 400, `HTTP ${res.status} ${res.body.error_description || 'SUCCESS(DEFECT)'}`);
  } catch (e) { assertCheck('SEC-03', 'kb+jwt with wrong audience rejected', false, e.message); }

  // ---------------------------------------------------------------- SEC-04
  try {
    const tok = await requestToken();
    const cred = await requestCredential({ accessToken: tok.body.access_token, cNonce: tok.body.c_nonce });
    const nonce = await getVerifierNonce();
    const vp = buildPresentation({
      issuedToken: cred.body.credential,
      claimNames: ['gender'], // verifier requested UIN + fullName; wallet withholds both
      kbPayload: (prefix) => ({ iat: now(), aud: VER, nonce, sd_hash: sha256b64u(prefix) })
    });
    const res = await directPost(vp);
    assertCheck('SEC-04', 'Presentation missing requested claims (UIN/fullName) rejected (DIF PE 2.0)', res.status === 400, `HTTP ${res.status} ${res.body.error_description || 'SUCCESS(DEFECT)'}`);
  } catch (e) { assertCheck('SEC-04', 'Presentation missing required claims rejected', false, e.message); }

  // ---------------------------------------------------------------- SEC-05
  try {
    const offer = await fetch(`${ISS}/credential-offer?uin=NOT-A-UIN`).then(r => r.json());
    const code = offer.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
    const dpop = dpopProof({ httpMethod: 'POST', httpUrl: `${ISS}/token` });
    const tokRes = await fetch(`${ISS}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: dpop },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }).toString()
    }).then(r => r.json());
    const cred = await requestCredential({ accessToken: tokRes.access_token, cNonce: tokRes.c_nonce });
    const nonce = await getVerifierNonce();
    const vp = buildPresentation({
      issuedToken: cred.body.credential,
      claimNames: ['UIN', 'fullName'],
      kbPayload: (prefix) => ({ iat: now(), aud: VER, nonce, sd_hash: sha256b64u(prefix) })
    });
    const res = await directPost(vp);
    assertCheck('SEC-05', 'Disclosed UIN violating requested ^[0-9]{12}$ pattern rejected', res.status === 400, `HTTP ${res.status} ${res.body.error_description || `extracted_uin=${res.body.extracted_uin} (DEFECT)`}`);
  } catch (e) { assertCheck('SEC-05', 'UIN pattern violation rejected', false, e.message); }

  // ---------------------------------------------------------------- SEC-06
  try {
    const proof = signEs256(
      { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: walletJwk },
      { iss: 'did:jwk:audit-probe', aud: ISS, iat: now(), nonce: (await requestToken()).body.c_nonce },
      walletKeys.privateKey
    );
    // fresh token for this flow (avoid nonce reuse)
    const tok = await requestToken();
    const credRes = await fetch(`${ISS}/credential`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${tok.body.access_token}`, DPoP: dpopProof({ httpMethod: 'POST', httpUrl: `${ISS}/credential`, accessToken: tok.body.access_token }) },
      body: JSON.stringify({ format: 'ldp_vc', proof: { proof_type: 'jwt', jwt: signEs256({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: walletJwk }, { iss: 'did:jwk:audit-probe', aud: ISS, iat: now(), nonce: tok.body.c_nonce }, walletKeys.privateKey) } })
    }).then(r => r.json());

    const vc = credRes.credential;
    const idx = Math.floor(vc.proof.proofValue.length / 2);
    const mutated = vc.proof.proofValue[idx] === 'A' ? 'B' : 'A';
    vc.proof.proofValue = vc.proof.proofValue.slice(0, idx) + mutated + vc.proof.proofValue.slice(idx + 1);

    const nonce = await getVerifierNonce();
    const res = await directPost(JSON.stringify(vc), nonce);
    assertCheck('SEC-06', 'Tampered ldp_vc Ed25519 proof fails genuine signature verification', res.status === 400 && /signature/i.test(res.body.error + res.body.error_description), `HTTP ${res.status} ${res.body.error_description || 'SUCCESS(DEFECT)'}`);
  } catch (e) { assertCheck('SEC-06', 'Tampered ldp_vc proof rejected', false, e.message); }

  // ---------------------------------------------------------------- SEC-07
  try {
    // Drive one full happy-path verify through the BFF, then inspect persisted history
    const issueRes = await fetch(`${BFF}/api/v1/orchestrate/issue`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerType: 'mock-vci', credentialFormat: 'vc+sd-jwt' })
    }).then(r => r.json());
    await fetch(`${BFF}/api/v1/orchestrate/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifierType: 'mock-vp', credential: issueRes.credential, format: 'vc+sd-jwt' })
    });
    const history = await fetch(`${BFF}/api/v1/history`).then(r => r.json());
    const latest = history.runs[0];
    const blob = JSON.stringify(latest || {});
    const leaksUin = blob.includes('123456789012') || blob.includes('Aarav Kumar') || blob.includes('9876543210');
    assertCheck('SEC-07', 'History trace_blob is PII-redacted (no UIN / name / phone)', !leaksUin, leaksUin ? 'PII FOUND IN trace_blob (DEFECT)' : 'redacted');
  } catch (e) { assertCheck('SEC-07', 'History PII redaction', false, e.message); }

  // ---------------------------------------------------------------- SEC-08
  try {
    const tok = await requestToken();
    const cred = await requestCredential({ accessToken: tok.body.access_token, cNonce: tok.body.c_nonce });
    const nonce = await getVerifierNonce();
    const vp = buildPresentation({
      issuedToken: cred.body.credential,
      claimNames: ['UIN', 'fullName'],
      kbPayload: (prefix) => ({ iat: now(), aud: VER, nonce, sd_hash: sha256b64u(prefix) })
    });
    const first = await directPost(vp);
    const replay = await directPost(vp);
    assertCheck('SEC-08', 'SD-JWT replay of consumed nonce rejected', first.status === 200 && replay.status === 400 && /ALREADY_CONSUMED/.test(replay.body.error_description || ''), `1st: HTTP ${first.status}, 2nd: HTTP ${replay.status} ${replay.body.error_description || ''}`);
  } catch (e) { assertCheck('SEC-08', 'SD-JWT replay rejected', false, e.message); }

  // ---------------------------------------------------------------- SEC-09
  try {
    const tok = await requestToken();
    const credRes = await fetch(`${ISS}/credential`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${tok.body.access_token}`, DPoP: dpopProof({ httpMethod: 'POST', httpUrl: `${ISS}/credential`, accessToken: tok.body.access_token }) },
      body: JSON.stringify({ format: 'ldp_vc', proof: { proof_type: 'jwt', jwt: signEs256({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: walletJwk }, { iss: 'did:jwk:audit-probe', aud: ISS, iat: now(), nonce: tok.body.c_nonce }, walletKeys.privateKey) } })
    }).then(r => r.json());
    const nonce = await getVerifierNonce();
    const body = new URLSearchParams({ vp_token: JSON.stringify(credRes.credential), nonce, presentation_submission: JSON.stringify({ id: 'sub', nonce }) }).toString();
    const first = await fetch(`${VER}/direct_post`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }).then(async r => ({ status: r.status, body: await r.json() }));
    const replay = await fetch(`${VER}/direct_post`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }).then(async r => ({ status: r.status, body: await r.json() }));
    assertCheck('SEC-09', 'ldp_vc replay of consumed nonce rejected', first.status === 200 && replay.status === 400 && /ALREADY_CONSUMED/.test(replay.body.error_description || ''), `1st: HTTP ${first.status}, 2nd: HTTP ${replay.status} ${replay.body.error_description || ''}`);
  } catch (e) { assertCheck('SEC-09', 'ldp_vc replay rejected', false, e.message); }

  // ---------------------------------------------------------------- Summary
  const total = results.length;
  const passed = results.filter(r => r.passed).length;
  console.log('\n================================================================');
  console.log(`   SECURITY REGRESSION RESULTS: ${passed}/${total} PASSED`);
  console.log('================================================================');
  // Drain the event loop before exiting so that fetch() keep-alive TCP sockets
  // can close gracefully on Windows (prevents libuv UV_HANDLE_CLOSING assertion).
  const exitCode = passed === total ? 0 : 1;
  setTimeout(() => process.exit(exitCode), 100);
}

main().catch(err => { console.error('Uncaught error:', err); process.exit(2); });
