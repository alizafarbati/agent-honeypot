#!/usr/bin/env node
/**
 * v0.2.1 hardening verification — proves each fix behaves as intended.
 * Run: node tests/v021_hardening_verify.mjs
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..');
const FINANCE = resolve(REPO, 'dist/surface/mcpservers/finance-warehouse/mcp_server.js');
const DATA = resolve(REPO, 'data', 'sessions.jsonl');

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ✓ ${name}${extra ? ' — ' + extra : ''}`); }
  else { fail++; console.log(`  ✗ ${name}${extra ? ' — ' + extra : ''}`); }
};

function lastSessionOf(fn) {
  const evs = readFileSync(DATA, 'utf8').trim().split('\n').map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const filtered = fn ? evs.filter(fn) : evs;
  return filtered[filtered.length - 1];
}

async function withFinance(run) {
  const transport = new StdioClientTransport({ command: 'node', args: [FINANCE] });
  const client = new Client({ name: 'v021-verify', version: '1.0.0' });
  await client.connect(transport);
  try { return await run(client); } finally { await client.close().catch(() => {}); }
}

console.log('v0.2.1 HARDENING VERIFICATION\n==============================\n');

// ---- F2: session IDs are crypto-random (16 hex = 128 bits) ------------------
await withFinance(async (c) => {
  const sid = (await c.listTools()) && lastSessionOf(e => e.lane === 'STATE_MACHINE' || e.lane === 'FINANCE_WH_DB')?.session_id;
  const m = /^sess-[a-z0-9]+-[a-f0-9]{16}$/.test(sid ?? '');
  ok('F2: crypto-random session ID (16 hex chars)', m, String(sid));
});

// ---- F8: malformed pagination token rejected, ladder not reset --------------
await withFinance(async (c) => {
  // Get a valid page-1 token first
  const r1 = await c.callTool({ name: 'db_query', arguments: { query: 'SELECT 1', context: 'legit short ctx' } });
  const tok = r1.structuredContent?.pagination_token;
  ok('F8a: valid token issued', Boolean(tok));

  // Malformed token -> isError, no page advance
  const bad = await c.callTool({ name: 'db_query', arguments: { query: 'SELECT 1', context: 'legit short ctx', pagination_token: 'garbage-token!!!' } });
  ok('F8b: malformed token rejected with isError', bad.isError === true);

  // Tampered token (valid base64 of wrong payload)
  const tampered = Buffer.from('pg:999').toString('base64url');
  const bad2 = await c.callTool({ name: 'db_query', arguments: { query: 'SELECT 1', context: 'legit short ctx', pagination_token: tampered } });
  const page = bad2.structuredContent?.page;
  ok('F8c: tampered pg:999 capped at page 12', bad2.isError !== true && page === 12, `page=${page}`);
});

// ---- F9: empty/oversized args rejected by schema ----------------------------
await withFinance(async (c) => {
  const empty = await c.callTool({ name: 'db_query', arguments: { query: '', context: '' } }).catch(e => ({ error: e }));
  ok('F9a: empty query/context rejected by schema', empty.isError === true || Boolean(empty.error));
  const huge = await c.callTool({ name: 'db_query', arguments: { query: 'SELECT 1', context: 'x'.repeat(10000) } }).catch(e => ({ error: e }));
  ok('F9b: 10KB context rejected by schema (max 4096)', huge.isError === true || Boolean(huge.error));
});

// ---- F5: full 64-hex digests persisted --------------------------------------
{
  const ev = lastSessionOf(e => e.args_digest);
  ok('F5: args_digest is full 64-hex SHA-256', /^[a-f0-9]{64}$/.test(ev?.args_digest ?? ''), String(ev?.args_digest).slice(0, 16) + '…');
}

// ---- adaptive thresholds: 20-char never baits, 100-char always baits --------
await withFinance(async (c) => {
  const short = 's'.repeat(20);
  await c.callTool({ name: 'db_query', arguments: { query: 'SELECT 1', context: short } });
  const eShort = lastSessionOf(e => e.lane === 'FINANCE_WH_DB' && e.context_chars === 20);
  ok('ADAPT: 20-char context never takes bait', eShort?.took_bait === false);

  // The server intentionally injects ~3% 429 errors; retry until a real
  // TOOL_CALL lands (same pattern as the integration test's fidelity retry).
  const long = 'l'.repeat(100);
  for (let attempt = 0; attempt < 10; attempt++) {
    await c.callTool({ name: 'db_query', arguments: { query: 'SELECT 1', context: long } });
    const eLong = lastSessionOf(e => e.lane === 'FINANCE_WH_DB' && e.context_chars === 100 && e.event_type === 'TOOL_CALL');
    if (eLong) {
      ok('ADAPT: 100-char context always takes bait', eLong.took_bait === true);
      return;
    }
  }
  ok('ADAPT: 100-char context always takes bait', false, 'all 10 attempts hit error injection');
});

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
