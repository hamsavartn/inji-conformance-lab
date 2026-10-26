/**
 * @file scripts/start_production.js
 * Unified Cloud Production Entrypoint for MOSIP Inji Conformance Laboratory
 * Designed for single-container Railway, Render, Fly.io, and Cloud deployments.
 * 
 * Topology:
 * - Internal Port 8080: Mock Inji Certify (OpenID4VCI Issuer)
 * - Internal Port 8081: Mock Inji Verify (OpenID4VP Relying Party)
 * - Public Port ($PORT || 4000): Hardened BFF Orchestrator + Static React UI SPA + WebSocket Telemetry
 */

const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

const ROOT_DIR = path.resolve(__dirname, '..');
const PUBLIC_PORT = process.env.PORT || '4000';

console.log('================================================================');
console.log('  MOSIP INJI CONFORMANCE LABORATORY - CLOUD PRODUCTION RUNNER   ');
console.log('  Target Public Port: ' + PUBLIC_PORT);
console.log('================================================================\n');

const children = [];

function startProcess(name, cmd, args, envOverrides = {}) {
  const child = spawn(cmd, args, {
    cwd: ROOT_DIR,
    env: { ...process.env, ...envOverrides },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout.on('data', data => {
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line.trim()) console.log(`[${name}] ${line}`);
    });
  });

  child.stderr.on('data', data => {
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line.trim()) console.error(`[${name}] [ERR] ${line}`);
    });
  });

  child.on('exit', (code, signal) => {
    console.log(`[${name}] Exited with code=${code} signal=${signal}`);
  });

  children.push({ name, process: child });
  return child;
}

// 1. Launch Mock Inji Certify on internal port 8080
startProcess('CERTIFY-8080', process.execPath, [path.join(ROOT_DIR, 'mocks/issuer/server.js')], {
  PORT: '8080',
  ISSUER_URL: process.env.ISSUER_URL || 'http://localhost:8080'
});

// 2. Launch Mock Inji Verify on internal port 8081
startProcess('VERIFY-8081', process.execPath, [path.join(ROOT_DIR, 'mocks/verifier/server.js')], {
  PORT: '8081',
  VERIFIER_URL: process.env.VERIFIER_URL || 'http://localhost:8081'
});

// 3. Launch BFF Gateway Hub on public port
startProcess('BFF-GATEWAY', process.execPath, [path.join(ROOT_DIR, 'backend/server.js')], {
  PORT: PUBLIC_PORT,
  MOCK_CERTIFY_URL: 'http://localhost:8080',
  MOCK_VERIFY_URL: 'http://localhost:8081'
});

// Graceful termination handler
function cleanup() {
  console.log('\n[PRODUCTION-RUNNER] Received shutdown signal. Terminating child services...');
  children.forEach(({ name, process: p }) => {
    try {
      p.kill('SIGTERM');
    } catch (e) {
      p.kill('SIGKILL');
    }
  });
  process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
