#!/usr/bin/env node
// agent-honeypot CLI — single entry point for all operations.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url)); // bin/
const REPO = resolve(ROOT, '..');

// Honeypot servers: finance-warehouse (TS -> dist), hr-portal (plain .mjs).
const SERVERS = {
  'finance-warehouse': resolve(REPO, 'dist/surface/mcpservers/finance-warehouse/mcp_server.js'),
  'hr-portal': resolve(REPO, 'surface/mcpservers/hr-portal/mcp_server.mjs'),
};

const HELP = `agent-honeypot — defensive honeypot for LLM agents

Usage:
  agent-honeypot serve [name]       Run an MCP honeypot on stdio.
                                    name: finance-warehouse (default) | hr-portal
                                    (or set AGENT_HONEYPOT_SERVER=name)
  agent-honeypot dash               Start the dashboard (default http://127.0.0.1:9079)
  agent-honeypot seed [n]           Write n synthetic sessions (default 4)
  agent-honeypot report            Generate a Markdown + JSON report
  agent-honeypot analyze            Full pipeline: fingerprints, clusters,
                                    anomaly scan, STIX for high/critical sessions
  agent-honeypot watch              Run the evolution engine over escapes
                                    (promotes validated lures to shadow only;
                                    promotion to live is always human)
  agent-honeypot honeydocs [n]      Generate n synthetic honeydocs with embedded
                                    canary ladders (default 3) -> data/honeydocs/
  agent-honeypot test               Run the full test suite
  agent-honeypot build              Compile the MCP surface (tsc)
  agent-honeypot doctor             Check environment and file health
  agent-honeypot help               Show this help

Environment: see .env.example for optional integrations (NATS, SIEM, MISP, LLM, OTLP).`;

function run(cmd, args) {
  const child = spawn(cmd, args, { stdio: 'inherit', cwd: REPO });
  child.on('exit', (code) => process.exit(code ?? 0));
}

function resolveServer(nameArg) {
  const key = nameArg ?? process.env.AGENT_HONEYPOT_SERVER ?? 'finance-warehouse';
  const target = SERVERS[key];
  if (!target) {
    console.error(`Unknown server "${key}". Available: ${Object.keys(SERVERS).join(', ')}`);
    process.exit(1);
  }
  if (!existsSync(target)) {
    console.error(`Server not built: ${target}\nRun \`agent-honeypot build\` first (needed for finance-warehouse).`);
    process.exit(1);
  }
  return target;
}

function doctor() {
  const checks = [];
  // hardFail=true -> missing is an error; hardFail=false -> informational.
  const check = (name, ok, detail = '', hardFail = true) => checks.push({ name, ok, detail, hardFail });

  check('node >= 20', Number(process.version.slice(1).split('.')[0]) >= 20, process.version);
  check('dependencies installed', existsSync(resolve(REPO, 'node_modules/@modelcontextprotocol/sdk')), 'run npm install');
  const fwBuilt = existsSync(SERVERS['finance-warehouse']);
  check('finance-warehouse build (dist/)', fwBuilt, fwBuilt ? SERVERS['finance-warehouse'] : 'run npm run build (needed for finance-warehouse serve)');
  check('hr-portal present (.mjs, no build)', existsSync(SERVERS['hr-portal']), SERVERS['hr-portal']);

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
    run(process.execPath, [resolveServer(rest[0])]);
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
  case 'analyze':
    run(process.execPath, [resolve(REPO, 'scripts/analyze.mjs')]);
    break;
  case 'watch':
    run(process.execPath, [resolve(REPO, 'scripts/watch.mjs')]);
    break;
  case 'honeydocs':
    run(process.execPath, [resolve(REPO, 'scripts/gen-honeydocs.mjs'), ...(rest.length ? rest : [])]);
    break;
  case 'test':
    run(process.execPath, ['--test', 'tests/core.test.mjs', 'tests/evolution.test.mjs', 'tests/analytics_hardening.test.mjs', 'tests/security.test.mjs', 'tests/integration.test.mjs', 'tests/hr-portal.test.mjs', 'tests/pipeline.test.mjs']);
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
