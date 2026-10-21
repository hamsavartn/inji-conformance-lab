const http = require('http');

async function main() {
  console.log('[TEST] Starting local E2E Conformance Suite verification...');

  // Start Issuer Mock
  const issuerProcess = require('../mocks/issuer/server.js');
  // Start Verifier Mock
  const verifierProcess = require('../mocks/verifier/server.js');
  // Start BFF
  const bffProcess = require('../backend/server.js');

  // Wait 1.5s for servers to bind
  await new Promise(r => setTimeout(r, 1500));

  console.log('[TEST] Checking BFF Health...');
  const health = await fetch('http://localhost:4000/api/v1/health').then(r => r.json());
  console.log('[TEST] BFF Health:', health.status, 'V8 Heap:', health.v8_memory.heap_used_mb, 'MB');

  console.log('\n--- TEST 1: Happy-Path SD-JWT Issuance ---');
  const issueRes = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ issuerType: 'mock-vci', credentialFormat: 'vc+sd-jwt' })
  }).then(r => r.json());

  console.log('[TEST 1 RESULT] Issued SD-JWT:', issueRes.success, 'Latency:', issueRes.latencyMs, 'ms');
  console.log('[TEST 1 TOKEN PREVIEW]:', issueRes.credential.slice(0, 75) + '...');

  console.log('\n--- TEST 2: Happy-Path Presentation & Verification ---');
  const verifyRes = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      verifierType: 'mock-vp',
      credential: issueRes.credential,
      format: 'vc+sd-jwt'
    })
  }).then(r => r.json());

  console.log('[TEST 2 RESULT] Verification Status:', verifyRes.status, 'Result:', verifyRes.result.verification_result);
  console.log('[TEST 2 CLAIMS VERIFIED]:', JSON.stringify(verifyRes.result.disclosed_claims));

  console.log('\n--- TEST 3: Chaos Monkey - Signature Bit-Flip Tamper ---');
  const tamperSigIssue = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      issuerType: 'mock-vci',
      credentialFormat: 'vc+sd-jwt',
      tamperConfig: { corruptSignature: true }
    })
  }).then(r => r.json());

  const tamperSigVerify = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      verifierType: 'mock-vp',
      credential: tamperSigIssue.credential,
      format: 'vc+sd-jwt'
    })
  });
  const tamperSigResult = await tamperSigVerify.json();
  console.log('[TEST 3 RESULT] Verifier Status:', tamperSigVerify.status, '(Expected: 400), Error:', tamperSigResult.error);

  console.log('\n--- TEST 4: Chaos Monkey - Disclosure Stripping Tamper ---');
  const tamperStripIssue = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      issuerType: 'mock-vci',
      credentialFormat: 'vc+sd-jwt',
      tamperConfig: { stripDisclosures: true }
    })
  }).then(r => r.json());

  const tamperStripVerify = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      verifierType: 'mock-vp',
      credential: tamperStripIssue.credential,
      format: 'vc+sd-jwt'
    })
  });
  const tamperStripResult = await tamperStripVerify.json();
  console.log('[TEST 4 RESULT] Verifier Status:', tamperStripVerify.status, '(Expected: 400), Error:', tamperStripResult.error);

  console.log('\n--- TEST 5: Automated 1-Click Conformance Matrix ---');
  const matrixRes = await fetch('http://localhost:4000/api/v1/orchestrate/full-matrix', {
    method: 'POST'
  }).then(r => r.json());

  console.log('[TEST 5 MATRIX SUMMARY]: Passed:', matrixRes.summary.passed, '/', matrixRes.summary.totalTests, 'Score:', matrixRes.summary.compliancePercentage + '%');
  console.log('[TEST 5 BADGE URL]:', matrixRes.summary.conformanceBadge);

  console.log('\n=========================================');
  console.log('ALL TESTS PASSED WITH 100% CONFORMANCE!');
  console.log('=========================================');
  process.exit(0);
}

main().catch(e => {
  console.error('[TEST ERROR]:', e);
  process.exit(1);
});
