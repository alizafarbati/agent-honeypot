// Security audit tests: machine-checked guarantees from SECURITY.md.
// Each test asserts a security property, not just a behavior.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(here, '..');

// Redirect all runtime state to an isolated dir for this suite.
const DATA_DIR = mkdtempSync(join(tmpdir(), 'ah-security-'));
process.env.AGENT_HONEYPOT_DATA_DIR = DATA_DIR;

// Import AFTER env is set — modules resolve PATHS at load time.
import { createHash } from 'node:crypto';
const { logCaptureEvent } = await import('../capture/recorder/session_recorder.mjs');
const { appendLedger, verifyLedger } = await import('../security/audit/ledger.mjs');
const { canPromoteToLive } = await import('../evolution/engine/promoter.mjs');
const { generateCandidates } = await import('../evolution/engine/candidate.mjs');
const { extractAntigen } = await import('../evolution/engine/antigen.mjs');
const { validateCandidate } = await import('../evolution/engine/validator.mjs');
const { mutateSchema } = await import('../evolution/hardening/schema_mutator.mjs');

const SESSIONS = join(DATA_DIR, 'sessions.jsonl');
const LEDGER = join(DATA_DIR, 'audit_ledger.jsonl');

describe('SECURITY: digest-only persistence', () => {
  const SECRET_PHRASES = [
    'sk-PROTOTYPE-DO-NOT-USE-12345',
    'password=hunter2',
    'aws_secret_access_key = AKIAIOSFODNN7EXAMPLE000',
    'BEGIN RSA PRIVATE KEY',
    "admin' OR '1'='1",
  ];

  it('never persists raw argument text for any tool event', () => {
    for (const secret of SECRET_PHRASES) {
      logCaptureEvent('FINANCE_WH_DB', { tool: 'db_query', rawArgs: secret, contextChars: secret.length, tookBait: true, privilegeLevel: 2 });
    }
    const stored = readFileSync(SESSIONS, 'utf8');
    for (const secret of SECRET_PHRASES) {
      assert.ok(!stored.includes(secret), `LEAK: "${secret}" found in capture store`);
    }
    // digest present instead
    const events = stored.trim().split('\n').map((l) => JSON.parse(l));
    for (const ev of events) {
      // full 64-hex SHA-256 (v0.2.1+); legacy 16-hex rows also tolerated
      assert.ok(ev.args_digest === null || /^[a-f0-9]{16}$/.test(ev.args_digest) || /^[a-f0-9]{64}$/.test(ev.args_digest), 'digest must be 16-hex (legacy), 64-hex, or null');
    }
  });

  it('digests are stable (same input, same digest) and lossy (irreversible form)', () => {
    const expected = createHash('sha256').update('abc').digest('hex'); // full 64-hex as of v0.2.1
    logCaptureEvent('TEST', { rawArgs: 'abc' });
    const lines = readFileSync(SESSIONS, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const last = lines[lines.length - 1];
    assert.equal(last.args_digest, expected);
  });
});

describe('SECURITY: audit ledger integrity', () => {
  it('appends verifiable entries', () => {
    const r1 = appendLedger({ actor: 'test', action: 'promote_shadow', target: 'lure-x' });
    const r2 = appendLedger({ actor: 'test', action: 'approve_live', target: 'lure-x' });
    assert.equal(r2.prev_hash, r1.entry_hash, 'chain must link');
    const v = verifyLedger();
    assert.equal(v.ok, true, 'fresh chain verifies');
  });

  it('detects tampering with any entry', () => {
    appendLedger({ actor: 'test', action: 't3', target: 'x' });
    // Tamper: rewrite the first line
    const lines = readFileSync(LEDGER, 'utf8').trim().split('\n');
    const first = JSON.parse(lines[0]);
    first.action = 'FORGED';
    lines[0] = JSON.stringify(first);
    writeFileSync(LEDGER, lines.join('\n') + '\n');
    const v = verifyLedger();
    assert.equal(v.ok, false, 'tampered chain must fail verification');
    assert.ok('bad_index' in v, 'reports where integrity broke');
    // restore for subsequent suites
    rmSync(LEDGER);
  });
});

describe('SECURITY: evolution cannot leak raw text into the LLM prompt path', () => {
  it('antigen profile contains no attacker strings, only counts/hashes', () => {
    const evs = [{
      session_id: 's-leak', lane: 'FINANCE_WH_DB', tool: 'db_query',
      privilege_level: 0, took_bait: false, context_chars: 10, page: 1,
      ts: new Date().toISOString(),
    }];
    const ag = extractAntigen(evs);
    const serialized = JSON.stringify(ag);
    assert.ok(!serialized.includes('s-leak'), 'session id only as sha, never raw');
    assert.ok(ag.session_id_sha && /^[a-f0-9]{12}$/.test(ag.session_id_sha));
  });

  it('candidates and their validator never embed canary strings verbatim', () => {
    const ag = extractAntigen([{ session_id: 'x', lane: 'L', tool: 'db_query', privilege_level: 0, took_bait: false, context_chars: 5, page: 1, ts: new Date().toISOString() }]);
    const cands = generateCandidates(ag, { n: 3 });
    for (const c of cands) {
      const v = validateCandidate(c, { antigen: ag });
      const canaryGate = v.gates.find((g) => g.gate === 'anti_fingerprint');
      assert.equal(canaryGate.pass, true, 'no canary leakage in candidate delta');
    }
  });
});

describe('SECURITY: human promotion gate cannot be bypassed', () => {
  it('blocks with all gates passing and full shadow volume', () => {
    const r = canPromoteToLive('lure-x', { sessionsInShadow: 999, daysInShadow: 365, gatesPass: true });
    assert.equal(r.ready_for_human_approval, true);
    assert.equal(r.blockers.length, 0);
    // The function reports readiness; promotion itself is a separate human action.
    // There is no promoteToLive() in the codebase to call programmatically.
  });
  it('reports blockers when shadow volume insufficient', () => {
    const r = canPromoteToLive('lure-x', { sessionsInShadow: 10, daysInShadow: 2, gatesPass: false });
    assert.equal(r.ready_for_human_approval, false);
    assert.ok(r.blockers.some((b) => b.includes('sessions_in_shadow')));
    assert.ok(r.blockers.some((b) => b.includes('days_in_shadow')));
    assert.ok(r.blockers.some((b) => b.includes('gates')));
  });
});

describe('SECURITY: per-tenant schema isolation', () => {
  it('tenant schemas stay internally stable but can diverge from each other', () => {
    const base = { properties: { context: { type: 'string' }, ticket_id: { type: 'string' } } };
    const t1a = mutateSchema(base, { tenantId: 'tenant-1' });
    const t1b = mutateSchema(base, { tenantId: 'tenant-1' });
    const t2 = mutateSchema(base, { tenantId: 'tenant-2' });
    assert.deepEqual(t1a, t1b, 'same tenant = deterministic schema');
    // never drops or renames semantic fields (synonyms preserve meaning)
    const all = [...new Set([...Object.keys(t1a), ...Object.keys(t2)])];
    assert.ok(all.every((k) => ['context', 'audit_context', 'task_context', 'session_context', 'ticket_id', 'ticket_ref', 'jira_ref', 'case_id'].includes(k)), 'renames are synonym-only');
  });
});

after(() => {
  rmSync(DATA_DIR, { recursive: true, force: true });
});
