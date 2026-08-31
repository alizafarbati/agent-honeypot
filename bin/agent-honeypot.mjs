#!/usr/bin/env node
// agent-honeypot CLI — single entry point for common operations.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url)); // bin/
const REPO = resolve(ROOT, '..');
const SERVER = existsSync(resolve(REPO, 'dist/surface/mcpservers/finance-warehouse/mcp_server.js'))
  ? resolve(REPO, 'dist/surface/mcpservers/finance-warehouse/mcp_server.js')
  : null;

const HELP = `agent-honeypot — defensive honeypot for LLM agents

Usage:
  agent-honeypot serve     Run the MCP honeypot server on stdio (build first if dist missing)
  agent-honeypot dash      Start the dashboard (default http://127.0.0.1:9079)
  agent-honeypot seed [n]  Write n synthetic sessions to the capture store (default 4)
  agent-honeypot report    Generate a Markdown + JSON report from captured sessions
  agent-honeypot test      Run the full test suite
  agent-honeypot build     Compile the MCP surface (tsc)
  agent-honeypot doctor    Check environment and file health
  agent-honeypot help      Show this help

Environment: see .env.example for optional integrations (NATS, SIEM, MISP, LLM, OTLP).`;

function run(cmd, args) {
  const child = spawn(cmd, args, { stdio: 'inherit', cwd: REPO });
  child.on('exit', (code) => process.exit(code ?? 0));
}

function doctor() {
  const checks = [];
  // ok=false is a hard failure; ok=true with detail is informational (absent files on
  // a fresh clone are expected, not errors).
  const check = (name, ok, detail = '', hardFail = true) => checks.push({ name, ok, detail, hardFail });

  check('node >= 20', Number(process.version.slice(1).split('.')[0]) >= 20, process.version);
  check('dependencies installed', existsSync(resolve(REPO, 'node_modules/@modelcontextprotocol/sdk')), 'run npm install');
  const built = SERVER !== null;
  check('build present (dist/)', built, built ? SERVER : 'run npm run build (needed for `serve`)');

  void readFileSync; // retained for future checks
  import('../capture/paths.mjs').then(({ PATHS, ensureDataDir }) => {
    ensureDataDir();
    check('data dir writable', existsSync(PATHS.dataDir), PATHS.dataDir);
    const hasSessions = existsSync(PATHS.sessions);
    check('sessions.jsonl present', hasSessions, hasSessions ? PATHS.sessions : 'absent on fresh clone - run `agent-honeypot seed 4`', false);
    const hasLedger = existsSync(PATHS.ledger);
    check('audit ledger present', hasLedger, hasLedger ? PATHS.ledger : 'absent until first appendLedger()', false);

    console.log('\nagent-honeypot doctor\n--------------------');
    for (const c of checks) {
      const tag = c.ok ? ' OK ' : c.hardFail ? 'FAIL' : 'WARN';
      console.log(`${tag}  ${c.name}${c.detail ? ' - ' + c.detail : ''}`);
    }
    const fails = checks.filter((c) => !c.ok && c.hardFail).length;
    console.log(`\n${checks.length - fails}/${checks.length} checks passed${fails ? ' (' + fails + ' failing)' : ''}`);
    process.exit(fails ? 1 : 0);
  });
}

const [, , command, ...rest] = process.argv;

switch (command) {
  case 'serve':
    if (!SERVER) {
      console.error('dist/ not found — run `agent-honeypot build` first.');
      process.exit(1);
    }
    run(process.execPath, [SERVER]);
    break;
  case 'dash':
    run(process.execPath, [resolve(REPO, 'control/dash/server.mjs')]);
    break;
  case 'seed':
    run(process.execPath, [resolve(REPO, 'scripts/seed.mjs'), ...(rest.length ? rest : [])]);
    break;
  case 'report':
    run(process.execPath, [resolve(REPO, 'control/report/generator.mjs')]);
    break;
  case 'test':
    run(process.execPath, ['--test', 'tests/core.test.mjs', 'tests/evolution.test.mjs', 'tests/analytics_hardening.test.mjs', 'tests/security.test.mjs', 'tests/integration.test.mjs']);
    break;
  case 'build':
    run('npx', ['tsc']);
    break;
  case 'doctor':
    doctor();
    break;
  case 'help':
  case '--help':
  case '-h':
  default:
    console.log(HELP);
    break;
}
