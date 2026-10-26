/**
 * @file scripts/test_mdoc_tamper_and_replay.js
 * ISO/IEC 18013-5 mso_mdoc adversarial suite: attribute tampering, deleted digestID,
 * omitted session nonce, and single-use replay defense. Fail-closed: exits 1 on any
 * assertion that does not match the expected rejection.
 */

const { decode, encode } = require('../mocks/verifier/node_modules/cbor-x');

const results = [];
function assertCheck(id, description, passed, details = '') {
  results.push({ id, passed });
  const mark = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`[${id}] ${mark}: ${description}${details ? ` (${details})` : ''}`);
}

async function main() {
  console.log('[INIT] Connecting to running microservices (4000, 8080, 8081)...');
  try {
    await fetch('http://localhost:4000/api/v1/health', { signal: AbortSignal.timeout(800) });
  } catch (e) {
    console.error('[FATAL] Services are not running. Start them first (node scripts/start_local.js).');
    process.exit(2);
  }

  // Issue a valid mso_mdoc credential
  const issueRes = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ issuerType: 'mock-vci', credentialFormat: 'mso_mdoc' })
  }).then(r => r.json());
  if (!issueRes.credential) {
    console.error('[FATAL] mdoc issuance failed:', issueRes);
    process.exit(2);
  }
  const rawBuf = Buffer.from(issueRes.credential, 'base64url');

  console.log('\n--- 1. mso_mdoc Rejection When Session Nonce is Omitted ---');
  const resNoNonce = await fetch('http://localhost:8081/direct_post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ vp_token: issueRes.credential, presentation_submission: '{}' })
  });
  const bodyNoNonce = await resNoNonce.json();
  assertCheck('MDOC-01', 'Omitted session nonce rejected', resNoNonce.status === 400 && /ERR_MISSING_SESSION_NONCE/.test(bodyNoNonce.error_description || ''), `HTTP ${resNoNonce.status} ${bodyNoNonce.error_description || ''}`);

  console.log('\n--- 2. mso_mdoc Attribute Tampering Rejection ---');
  const reqResTamper = await fetch('http://localhost:8081/api/v1/request').then(r => r.json());
  const mdoc = decode(rawBuf);
  const nsItems = mdoc.issuerSigned.nameSpaces['org.iso.18013.5.1'];
  const tamperedItem = decode(nsItems[3].value || nsItems[3]);
  tamperedItem.elementValue = 'FORGED_UIN_0000000000';
  nsItems[3].value = encode(tamperedItem);
  const tamperedCred = Buffer.from(encode(mdoc)).toString('base64url');

  const resTamper = await fetch('http://localhost:8081/direct_post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      vp_token: tamperedCred,
      nonce: reqResTamper.nonce,
      presentation_submission: JSON.stringify({ id: 'sub_tamper', nonce: reqResTamper.nonce })
    })
  });
  const bodyTamper = await resTamper.json();
  assertCheck('MDOC-02', 'Tampered attribute rejected via MSO valueDigest mismatch', resTamper.status === 400 && /ERR_MDOC_DIGEST_MISMATCH/.test(bodyTamper.error_description || ''), `HTTP ${resTamper.status} ${bodyTamper.error_description || ''}`);

  console.log('\n--- 3. mso_mdoc Deleted digestID Rejection ---');
  const reqResDel = await fetch('http://localhost:8081/api/v1/request').then(r => r.json());
  const mdocDel = decode(rawBuf);
  const nsItemsDel = mdocDel.issuerSigned.nameSpaces['org.iso.18013.5.1'];
  const itemDel = decode(nsItemsDel[0].value || nsItemsDel[0]);
  delete itemDel.digestID;
  itemDel.elementValue = 'BYPASS_ATTEMPT';
  nsItemsDel[0].value = encode(itemDel);
  const delDigestCred = Buffer.from(encode(mdocDel)).toString('base64url');

  const resDel = await fetch('http://localhost:8081/direct_post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      vp_token: delDigestCred,
      nonce: reqResDel.nonce,
      presentation_submission: JSON.stringify({ id: 'sub_del', nonce: reqResDel.nonce })
    })
  });
  const bodyDel = await resDel.json();
  assertCheck('MDOC-03', 'Deleted/non-integer digestID rejected', resDel.status === 400 && /ERR_MALFORMED_ISSUER_SIGNED_ITEM|ERR_MDOC_DIGEST_MISMATCH|ERR_UNBOUND_MDOC_DIGEST/.test(bodyDel.error_description || ''), `HTTP ${resDel.status} ${bodyDel.error_description || ''}`);

  console.log('\n--- 4. mso_mdoc Replay Protection with Valid Nonce ---');
  const reqRes = await fetch('http://localhost:8081/api/v1/request').then(r => r.json());
  const validMdocCred = issueRes.credential;
  const replayBody = new URLSearchParams({
    vp_token: validMdocCred,
    nonce: reqRes.nonce,
    presentation_submission: JSON.stringify({ id: 'sub_mdoc', nonce: reqRes.nonce })
  }).toString();
  const postHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' };

  const res1 = await fetch('http://localhost:8081/direct_post', { method: 'POST', headers: postHeaders, body: replayBody });
  const body1 = await res1.json();
  const res2 = await fetch('http://localhost:8081/direct_post', { method: 'POST', headers: postHeaders, body: replayBody });
  const body2 = await res2.json();
  assertCheck('MDOC-04', 'Single-use nonce replay defense', res1.status === 200 && res2.status === 400 && /ERR_NONCE_ALREADY_CONSUMED/.test(body2.error_description || ''), `1st: HTTP ${res1.status} (${body1.verification_result}), replay: HTTP ${res2.status} ${body2.error_description || ''}`);

  console.log('\n================================================================');
  const passed = results.filter(r => r.passed).length;
  console.log(`   MDOC ADVERSARIAL RESULTS: ${passed}/${results.length} PASSED`);
  console.log('================================================================');
  // Drain the event loop before exiting so that fetch() keep-alive TCP sockets
  // can close gracefully on Windows. Without this, Node triggers a libuv
  // UV_HANDLE_CLOSING assertion in src\win\async.c:94 and exits with code 1
  // even when all assertions passed.
  const exitCode = passed === results.length ? 0 : 1;
  setTimeout(() => process.exit(exitCode), 100);
}

main().catch(err => {
  console.error(err);
  process.exit(2);
});
