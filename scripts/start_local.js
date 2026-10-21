/**
 * @file scripts/start_local.js
 * Zero-Docker Native Local Orchestrator for MOSIP Inji Conformance Laboratory
 * Launches all 4 microservices simultaneously in-process or via lightweight child processes:
 * 1. Mock Inji Certify (port 8080)
 * 2. Mock Inji Verify (port 8081)
 * 3. Inji Conformance BFF Gateway (port 4000)
 * 4. Inji Conformance Web UI (port 3000)
 */

const { spawn } = require('child_process');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

const SERVICES = [
  {
    name: 'CERTIFY-8080',
    color: '\x1b[36m', // Cyan
    cmd: process.execPath,
    args: [path.join(ROOT_DIR, 'mocks/issuer/server.js')],
    cwd: ROOT_DIR
  },
  {
    name: 'VERIFY-8081 ',
    color: '\x1b[32m', // Green
    cmd: process.execPath,
    args: [path.join(ROOT_DIR, 'mocks/verifier/server.js')],
    cwd: ROOT_DIR
  },
  {
    name: 'BFF-HUB-4000',
    color: '\x1b[35m', // Magenta
    cmd: process.execPath,
    args: [path.join(ROOT_DIR, 'backend/server.js')],
    cwd: ROOT_DIR
  },
  {
    name: 'FRONTEND-UI ',
    color: '\x1b[33m', // Yellow
    cmd: process.platform === 'win32' ? 'npm.cmd' : 'npm',
    args: ['--prefix', path.join(ROOT_DIR, 'frontend'), 'run', 'dev', '--', '--port', '3000', '--host'],
    cwd: ROOT_DIR
  }
];

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

console.log(`${BOLD}================================================================${RESET}`);
console.log(`${BOLD}  MOSIP INJI CONFORMANCE LABORATORY - LOCAL ENVIRONMENT STARTER  ${RESET}`);
console.log(`${BOLD}  Starting all 4 microservices concurrently (Zero Docker required) ${RESET}`);
console.log(`${BOLD}================================================================${RESET}\n`);

const spawnedChildren = [];

SERVICES.forEach(svc => {
  const child = spawn(svc.cmd, svc.args, {
    cwd: svc.cwd,
    env: { ...process.env, PORT: svc.name.includes('8080') ? '8080' : svc.name.includes('8081') ? '8081' : svc.name.includes('4000') ? '4000' : '3000' },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout.on('data', data => {
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line.trim()) console.log(`${svc.color}[${svc.name}]${RESET} ${line}`);
    });
  });

  child.stderr.on('data', data => {
    const lines = data.toString().trim().split('\n');
    lines.forEach(line => {
      if (line.trim()) console.error(`${svc.color}[${svc.name}]${RESET} \x1b[31m${line}${RESET}`);
    });
  });

  child.on('close', code => {
    console.log(`${svc.color}[${svc.name}]${RESET} Process exited with code ${code}`);
  });

  spawnedChildren.push(child);
});

// Print service dashboard table
setTimeout(() => {
  console.log(`\n${BOLD}--- ALL CONFORMANCE LABORATORY SERVICES READY ---${RESET}`);
  console.log(`  🌐  \x1b[33mFrontend UI Dashboard:\x1b[0m     http://localhost:3000`);
  console.log(`  🚀  \x1b[35mConformance BFF Hub:\x1b[0m       http://localhost:4000`);
  console.log(`  📡  \x1b[35mTelemetry WebSocket:\x1b[0m       ws://localhost:4000/telemetry`);
  console.log(`  🏛️   \x1b[36mMock Inji Certify:\x1b[0m         http://localhost:8080`);
  console.log(`  🛡️   \x1b[32mMock Inji Verify:\x1b[0m          http://localhost:8081`);
  console.log(`${BOLD}------------------------------------------------${RESET}`);
  console.log(`Press Ctrl+C to terminate all services gracefully.\n`);
}, 3000);

// Graceful termination
function cleanup() {
  console.log(`\nShutting down all Conformance Laboratory microservices...`);
  spawnedChildren.forEach(c => {
    try {
      c.kill('SIGTERM');
    } catch (e) {}
  });
  process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
