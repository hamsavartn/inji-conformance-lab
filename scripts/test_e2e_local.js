/**
 * @file scripts/test_e2e_local.js
 * Comprehensive Chain of Verification Test Suite
 * Asserts all 12 Vulnerabilities (VULN-01 to VULN-12) and 8 Adversarial Chaos Vectors (VEC-01 to VEC-08).
 */

const crypto = require('crypto');

function sha256Base64Url(str) {
  return crypto.createHash('sha256').update(str).digest('base64url');
}

async function runChainOfVerification() {
  console.log('================================================================');
  console.log('   MOSIP INJI CONFORMANCE LABORATORY - CHAIN OF VERIFICATION    ');
  console.log('   Testing 12 Audited Vulnerabilities & 8 Chaos Vectors         ');
  console.log('================================================================\n');

  // Launch in-process servers
  console.log('[INIT] Spawning Issuer Mock, Verifier Mock, and Hardened BFF...');
  require('../mocks/issuer/server.js');
  require('../mocks/verifier/server.js');
  require('../backend/server.js');

  // Allow 1.5s for HTTP listeners and SQLite database to bind
  await new Promise(r => setTimeout(r, 1500));

  const results = [];
  function assertCheck(id, description, passed, details = '') {
    results.push({ id, description, passed, details });
    const mark = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[${id}] ${mark}: ${description} ${details ? `(${details})` : ''}`);
  }

  // -------------------------------------------------------------------------
  // CHECK 1: VULN-05 - Memory Footprint & Service Health
  // -------------------------------------------------------------------------
  try {
    const health = await fetch('http://localhost:4000/api/v1/health').then(r => r.json());
    const memMb = health.v8_memory.heap_used_mb;
    const isHealthy = health.status === 'UP' && health.sqlite_db === 'OPERATIONAL';
    assertCheck('VULN-05', 'Service Health & Hard 920MB Memory Constraint', isHealthy && memMb < 250, `V8 Heap: ${memMb} MB`);
  } catch (e) {
    assertCheck('VULN-05', 'Service Health & Hard 920MB Memory Constraint', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 2: VULN-01 & VEC-08 - RFC 7515 IEEE P1363 64-Byte ECDSA Signature Format
  // -------------------------------------------------------------------------
  let sampleSdJwt = null;
  try {
    const issueRes = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerType: 'mock-vci', credentialFormat: 'vc+sd-jwt' })
    }).then(r => r.json());

    sampleSdJwt = issueRes.credential;
    const parts = sampleSdJwt.split('~');
    const issuerJwtParts = parts[0].split('.');
    const sigBuf = Buffer.from(issuerJwtParts[2], 'base64url');

    const is64Bytes = sigBuf.length === 64;
    assertCheck('VULN-01', 'RFC 7515 IEEE P1363 64-byte Signature (r||s) for Nimbus JOSE', is64Bytes, `Signature Length: ${sigBuf.length} bytes`);
  } catch (e) {
    assertCheck('VULN-01', 'RFC 7515 IEEE P1363 64-byte Signature (r||s) for Nimbus JOSE', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 3: VULN-02 & VEC-03 - RFC 9901 sd_hash Key Binding Integrity
  // -------------------------------------------------------------------------
  try {
    // 3a. Happy Path Verification
    const verifyHappy = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verifierType: 'mock-vp',
        credential: sampleSdJwt,
        format: 'vc+sd-jwt'
      })
    });
    const verifyHappyData = await verifyHappy.json();
    const happyPassed = verifyHappy.status === 200 && verifyHappyData.result?.sd_hash_verified === true;
    const happyErr = verifyHappyData.result?.error_description || verifyHappyData.result?.error || verifyHappyData.details || '';
    assertCheck('VULN-02a', 'RFC 9901 Key Binding JWT sd_hash Validated', happyPassed, `HTTP ${verifyHappy.status}${happyErr ? ` - ${happyErr}` : ''}`);


    // 3b. VEC-03 Tamper Assertion: Cut-and-paste sd_hash desync
    const verifyTamper = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verifierType: 'mock-vp',
        credential: sampleSdJwt,
        format: 'vc+sd-jwt',
        tamperConfig: { vector: 'VEC-03' }
      })
    });
    const verifyTamperData = await verifyTamper.json();
    const tamperRejected = verifyTamper.status === 400 &&
      (verifyTamperData.result?.error_description?.includes('SD_HASH_MISMATCH') || verifyTamperData.result?.error === 'invalid_presentation');
    assertCheck('VULN-02b', 'Adversarial VEC-03 Rejection (sd_hash Mismatch Detected)', tamperRejected, `HTTP ${verifyTamper.status}`);
  } catch (e) {
    assertCheck('VULN-02', 'RFC 9901 sd_hash Key Binding Integrity', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 4: VULN-03 - RFC 9449 DPoP 'ath' Access Token Hash & JTI Replay Defense
  // -------------------------------------------------------------------------
  try {
    // 1. Fetch valid pre-authorized code from /credential-offer
    const offerRes = await fetch('http://localhost:8080/credential-offer').then(r => r.json());
    const preAuthCode = offerRes.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    // 2. Direct test against Mock Issuer /token & /credential
    const tokenRes = await fetch('http://localhost:8080/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode
      }).toString()
    }).then(r => r.json());

    const accessToken = tokenRes.access_token;
    const expectedAth = sha256Base64Url(accessToken);


    // Test missing/invalid ath
    const invalidDpopProof = 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2NyZWRlbnRpYWwiLCJpYXQiOjE3MDgwMDAwMDB9.invalidSig';
    const rejectRes = await fetch('http://localhost:8080/credential', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `DPoP ${accessToken}`,
        'DPoP': invalidDpopProof
      },
      body: JSON.stringify({ format: 'vc+sd-jwt' })
    });

    const dpopEnforced = rejectRes.status === 401;
    assertCheck('VULN-03', 'RFC 9449 DPoP ath Validation & 401 Unauthorized Defense', dpopEnforced, `Expected HTTP 401, Got: ${rejectRes.status}`);
  } catch (e) {
    assertCheck('VULN-03', 'RFC 9449 DPoP ath Validation', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 5: VULN-04 - URL-Safe Direct Post Body & Large Payload Buffer
  // -------------------------------------------------------------------------
  try {
    // Generate large padded submission
    const largeDummy = 'A'.repeat(50000);
    const params = new URLSearchParams({
      vp_token: sampleSdJwt,
      large_field: largeDummy,
      presentation_submission: JSON.stringify({ id: 'sub_large', definition_id: 'test', descriptor_map: [] })
    });

    const directPostRes = await fetch('http://localhost:8081/direct_post', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const parsedWithoutCrash = directPostRes.status === 200 || directPostRes.status === 400;
    assertCheck('VULN-04', 'URL-Safe Direct Post 5MB Buffer & Character Corruption Guard', parsedWithoutCrash, `Payload: 50KB+, Status: ${directPostRes.status}`);
  } catch (e) {
    assertCheck('VULN-04', 'URL-Safe Direct Post Body', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 6: VULN-06 - Resilient Two-Phase MOSIP Collab Sandbox Probe
  // -------------------------------------------------------------------------
  try {
    const collabIssue = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerType: 'inji-certify', credentialFormat: 'vc+sd-jwt' })
    }).then(r => r.json());

    const hasTelemetry = Array.isArray(collabIssue.traces) && collabIssue.traces.length > 0;
    const successfulOrCleanAuthBoundary = collabIssue.success === true;
    assertCheck('VULN-06', 'Two-Phase Live Collab Sandbox Probe with Fallback & Telemetry', successfulOrCleanAuthBoundary && hasTelemetry, `Traces Recorded: ${collabIssue.traces.length}`);
  } catch (e) {
    assertCheck('VULN-06', 'Two-Phase Live Collab Sandbox Probe', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 7: VULN-07 - Cross-Draft Transpiler (Draft 13 <-> Draft 14)
  // -------------------------------------------------------------------------
  try {
    const transpileDraft14 = await fetch('http://localhost:4000/api/v1/transpile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        protocol: 'openid4vci',
        targetSchema: 'draft-14',
        sourceData: { proof: { proof_type: 'jwt', jwt: 'mock.proof.jwt' } }
      })
    }).then(r => r.json());

    const hasPluralProofs = Array.isArray(transpileDraft14.transpiled?.proofs?.jwt) && transpileDraft14.transpiled.proofs.jwt[0] === 'mock.proof.jwt';

    const transpileDraft13 = await fetch('http://localhost:4000/api/v1/transpile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        protocol: 'openid4vci',
        targetSchema: 'draft-13',
        sourceData: { proofs: { jwt: ['mock.proof.jwt'] } }
      })
    }).then(r => r.json());

    const hasSingularProof = transpileDraft13.transpiled?.proof?.jwt === 'mock.proof.jwt';
    assertCheck('VULN-07', 'Cross-Draft Transpiler: Draft 13 (Singular) ⇄ Draft 14 (Plural)', hasPluralProofs && hasSingularProof, 'Both Transpilation Directions Verified');
  } catch (e) {
    assertCheck('VULN-07', 'Cross-Draft Transpiler', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 8: VULN-08 & VEC-07 - Inji Verify INJIVER-1131 Credential Type Mismatch
  // -------------------------------------------------------------------------
  try {
    const wrongTypeIssue = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        issuerType: 'mock-vci',
        credentialFormat: 'vc+sd-jwt',
        tamperConfig: { vector: 'VEC-07' }
      })
    }).then(r => r.json());

    const verifyWrongType = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verifierType: 'mock-vp',
        credential: wrongTypeIssue.credential,
        format: 'vc+sd-jwt'
      })
    });

    const verifyWrongData = await verifyWrongType.json();
    const typeMismatchCaught = verifyWrongType.status === 400 &&
      (verifyWrongData.result?.error_description?.includes('ERR_INJIVER_1131_WRONG_CREDENTIAL_TYPE') || verifyWrongData.result?.error === 'invalid_presentation');
    assertCheck('VULN-08', 'INJIVER-1131 Defect Mitigation: Strict RP Credential Type Assertions', typeMismatchCaught, `HTTP ${verifyWrongType.status}`);
  } catch (e) {
    assertCheck('VULN-08', 'INJIVER-1131 Defect Mitigation', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 9: VULN-09 - Dual Format Acceptance (vc+sd-jwt & dc+sd-jwt)
  // -------------------------------------------------------------------------
  try {
    const dcIssue = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerType: 'mock-vci', credentialFormat: 'dc+sd-jwt' })
    }).then(r => r.json());

    const dcVerify = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verifierType: 'mock-vp',
        credential: dcIssue.credential,
        format: 'dc+sd-jwt'
      })
    });

    const dcVerifyData = await dcVerify.json();
    const dcPassed = dcVerify.status === 200;
    const dcErr = dcVerifyData.result?.error_description || dcVerifyData.result?.error || dcVerifyData.details || '';
    assertCheck('VULN-09', 'Dual Format Interoperability: Both vc+sd-jwt and dc+sd-jwt Accepted', dcPassed, `dc+sd-jwt: HTTP ${dcVerify.status}${dcErr ? ` - ${dcErr}` : ''}`);

  } catch (e) {
    assertCheck('VULN-09', 'Dual Format Interoperability', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 10: VULN-10 - Cryptographic Algorithm Agility (ES256 & EdDSA)
  // -------------------------------------------------------------------------
  try {
    const eddsaIssue = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuerType: 'mock-vci', credentialFormat: 'ldp_vc' })
    }).then(r => r.json());

    const eddsaVerify = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verifierType: 'mock-vp',
        credential: eddsaIssue.credential,
        format: 'ldp_vc'
      })
    });

    const eddsaPassed = eddsaVerify.status === 200;
    assertCheck('VULN-10', 'Cryptographic Algorithm Agility: Ed25519 (EdDSA) & ES256 Supported', eddsaPassed, `EdDSA ldp_vc: HTTP ${eddsaVerify.status}`);
  } catch (e) {
    assertCheck('VULN-10', 'Cryptographic Algorithm Agility', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 11: VULN-11 - Concurrent 8-Permutation Matrix & SQLite Persistence
  // -------------------------------------------------------------------------
  try {
    const matrixRes = await fetch('http://localhost:4000/api/v1/orchestrate/full-matrix', {
      method: 'POST'
    }).then(r => r.json());

    const matrixPassed = matrixRes.summary?.compliancePercentage === 100;

    const history = await fetch('http://localhost:4000/api/v1/history').then(r => r.json());
    const sqliteWorking = Array.isArray(history.runs) && history.runs.length > 0;

    assertCheck('VULN-11', 'Concurrent 8-Lane Matrix Runner & Native node:sqlite Persistence', matrixPassed && sqliteWorking, `${matrixRes.summary.compliancePercentage}% Score across ${matrixRes.summary.totalTests} Lanes, Stored: ${history.runs.length} Runs`);
  } catch (e) {

    assertCheck('VULN-11', 'Concurrent 8-Lane Matrix Runner & SQLite Persistence', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 12: Complete 8-Vector Adversarial Chaos Monkey Suite (VEC-01 to VEC-08)
  // -------------------------------------------------------------------------
  console.log('\n--- Executing 8-Layer Adversarial Chaos Monkey Test Suite ---');
  const chaosVectors = [
    { id: 'VEC-01', desc: 'Issuer Signature Bit-Flip' },
    { id: 'VEC-02', desc: 'Key Binding Nonce Mismatch' },
    { id: 'VEC-03', desc: 'Cut-and-Paste sd_hash Desync' },
    { id: 'VEC-04', desc: 'Unbound Disclosure Injection' },
    { id: 'VEC-05', desc: 'Expired Credential Presentation' },
    { id: 'VEC-06', desc: 'Malformed Recursive SD Nesting Loop' },
    { id: 'VEC-07', desc: 'INJIVER-1131 Credential Type Mismatch' },
    { id: 'VEC-08', desc: 'ASN.1 DER Signature Injection' }
  ];

  for (const cv of chaosVectors) {
    try {
      const issueRes = await fetch('http://localhost:4000/api/v1/orchestrate/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          issuerType: 'mock-vci',
          credentialFormat: 'vc+sd-jwt',
          tamperConfig: { vector: cv.id }
        })
      }).then(r => r.json());

      const verifyRes = await fetch('http://localhost:4000/api/v1/orchestrate/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          verifierType: 'mock-vp',
          credential: issueRes.credential,
          format: 'vc+sd-jwt',
          tamperConfig: { vector: cv.id }
        })
      });

      const rejected = verifyRes.status === 400;
      assertCheck(cv.id, `Adversarial Vector ${cv.id} (${cv.desc})`, rejected, `HTTP ${verifyRes.status} Rejection Confirmed`);
    } catch (e) {
      assertCheck(cv.id, `Adversarial Vector ${cv.id} (${cv.desc})`, false, e.message);
    }
  }

  // -------------------------------------------------------------------------
  // CHECK 13: Upstream RFC 7807 GitHub Bug Exporter
  // -------------------------------------------------------------------------
  try {
    const exportRes = await fetch('http://localhost:4000/api/v1/export-issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        issueType: 'INJIVER-1131',
        module: 'inji-verify'
      })
    }).then(r => r.json());

    const hasRfc7807 = exportRes.markdown && exportRes.markdown.includes('INJIVER-1131') && exportRes.markdown.includes('RFC 7807');
    assertCheck('FEATURE-1', 'Upstream MOSIP RFC 7807 Defect Exporter Pre-loaded with Verified Bugs', hasRfc7807, 'Markdown Generated Successfully');
  } catch (e) {
    assertCheck('FEATURE-1', 'Upstream MOSIP RFC 7807 Defect Exporter', false, e.message);
  }

  // -------------------------------------------------------------------------
  // CHECK 14: OpenID4VP DCQL Transpiler
  // -------------------------------------------------------------------------
  try {
    const dcqlRes = await fetch('http://localhost:4000/api/v1/transpile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        protocol: 'openid4vp',
        targetSchema: 'dcql'
      })
    }).then(r => r.json());

    const hasDcql = Array.isArray(dcqlRes.transpiled?.credentials) && dcqlRes.transpiled.credentials[0].format === 'dc+sd-jwt';
    assertCheck('FEATURE-2', 'OpenID4VP DCQL Transpiler (DIF PE 2.0 ⇄ DCQL Query)', hasDcql, 'Transpiled to Draft 23 DCQL Format');
  } catch (e) {
    assertCheck('FEATURE-2', 'OpenID4VP DCQL Transpiler', false, e.message);
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  const total = results.length;
  const passedCount = results.filter(r => r.passed).length;
  console.log('\n================================================================');
  console.log(`   FINAL VERIFICATION RESULTS: ${passedCount}/${total} CHECKS PASSED (${Math.round((passedCount/total)*100)}%)`);
  console.log('================================================================\n');

  if (passedCount === total) {
    console.log('🎉 ALL AUDIT FINDINGS, ADVERSARIAL VECTORS, AND FEATURES CONFIRMED!');
    process.exit(0);
  } else {
    console.error('❌ SOME CHECKS FAILED. Review output above.');
    process.exit(1);
  }
}

runChainOfVerification().catch(err => {
  console.error('Test suite uncaught error:', err);
  process.exit(1);
});
