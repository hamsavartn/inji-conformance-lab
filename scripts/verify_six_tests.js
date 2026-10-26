/**
 * scripts/verify_six_tests.js
 * Executes tests 2, 3, and 4 from the Zero-Trust Audit prompt against live in-process servers.
 */

async function main() {
  try {
    const checkLive = await fetch('http://localhost:4000/api/v1/health', { signal: AbortSignal.timeout(500) });
    if (checkLive.ok) {
      console.log('[INIT] Connecting to live running microservices (4000/8080/8081)...');
    }
  } catch (e) {
    console.log('[INIT] Starting in-process test servers...');
    const issuerApp = require('../mocks/issuer/server.js');
    const verifierApp = require('../mocks/verifier/server.js');
    const backendApp = require('../backend/server.js');
    issuerApp.app.listen(8080);
    verifierApp.app.listen(8081);
    backendApp.server.listen(4000);
    await new Promise(r => setTimeout(r, 1500));
  }

  console.log('\n===============================================================');
  console.log('TEST 2: Garbage / Unrecognized Format Rejection (Issue 4)');
  console.log('===============================================================');
  const garbageRes = await fetch('http://localhost:8081/direct_post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      vp_token: 'unrecognized_garbage_payload_12345',
      presentation_submission: '{}'
    }).toString()
  });
  console.log('Garbage Payload Status (expect 400):', garbageRes.status);
  console.log('Garbage Payload Response Body:', await garbageRes.text());

  console.log('\n===============================================================');
  console.log('TEST 3: Session Nonce Enforcement & Replay Protection (Issue 1)');
  console.log('===============================================================');
  const reqRes = await fetch('http://localhost:8081/api/v1/request').then(r => r.json());
  console.log('Issued Nonce:', reqRes.nonce);

  const issueRes = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ issuerType: 'mock-vci', format: 'vc+sd-jwt' })
  }).then(r => r.json());

  const vp1 = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: issueRes.credential, nonce: reqRes.nonce, verifierType: 'mock-verify' })
  });
  console.log('First submission status (expect 200):', vp1.status);
  const vp1Body = await vp1.json();
  console.log('First submission result:', vp1Body.result?.status, vp1Body.result?.verification_result);

  const vp2 = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: issueRes.credential, nonce: reqRes.nonce, verifierType: 'mock-verify' })
  });
  console.log('Replay submission status (expect 400):', vp2.status);
  const vp2Body = await vp2.json();
  console.log('Replay submission error:', vp2Body.result?.error, vp2Body.result?.error_description);

  const vpForgedNonce = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: issueRes.credential, nonce: 'unissued-nonce-99999', verifierType: 'mock-verify' })
  });
  console.log('Forged nonce status (expect 400):', vpForgedNonce.status);
  const vpForgedBody = await vpForgedNonce.json();
  console.log('Forged nonce error:', vpForgedBody.result?.error, vpForgedBody.result?.error_description);

  console.log('\n===============================================================');
  console.log('TEST 4: Untrusted Self-Signed Issuer Key Rejection (Issue 2)');
  console.log('===============================================================');
  const crypto = require('crypto');
  const rogue = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rogueJwk = rogue.publicKey.export({ format: 'jwk' });
  const b64u = (b) => Buffer.from(b).toString('base64url');
  const hdr = b64u(JSON.stringify({ alg: 'ES256', typ: 'vc+sd-jwt', jwk: rogueJwk }));
  const pay = b64u(JSON.stringify({ iss: 'https://rogue.example', vct: 'MOSIPVerifiableCredential', UIN: '1234567890', cnf: { jwk: rogueJwk } }));
  const sig = crypto.sign('SHA256', Buffer.from(`${hdr}.${pay}`), { key: rogue.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const sdJwt = `${hdr}.${pay}.${sig}~`;
  const sdHash = crypto.createHash('sha256').update(sdJwt, 'ascii').digest('base64url');
  const reqRes4 = await fetch('http://localhost:8081/api/v1/request').then(r => r.json());
  const kbHdr = b64u(JSON.stringify({ alg: 'ES256', typ: 'kb+jwt' }));
  const kbPay = b64u(JSON.stringify({ iat: Math.floor(Date.now() / 1000), aud: 'http://localhost:8081', nonce: reqRes4.nonce, sd_hash: sdHash }));
  const kbSig = crypto.sign('SHA256', Buffer.from(`${kbHdr}.${kbPay}`), { key: rogue.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');

  const res4 = await fetch('http://localhost:8081/direct_post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ vp_token: `${sdJwt}${kbHdr}.${kbPay}.${kbSig}`, presentation_submission: '{}' }).toString()
  });
  console.log('Rogue self-signed Issuer JWT status (expect 400/401):', res4.status, await res4.text());

  process.exit(0);
}

main().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
