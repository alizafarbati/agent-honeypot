import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { detect } from '../antibodies/finance-warehouse/detect.mjs';
import { fingerprintSession } from '../analysis/fingerprint/index.mjs';
import { antigenProfile } from '../analysis/interrogate/interrogator.mjs';

describe('antibody Tier-0 self-monitor', () => {
  it('passes when latency respects budget and response is synthetic-only', () => {
    const r = detect({ latencyMs: 400, responseText: 'Rows: 20 (page 1/12) pagination_token=abc', tookBait: true });
    assert.equal(r.verdict, 'pass');
  });
  it('fails when latency is a honeypot tell (sub-250ms while tookBait)', () => {
    const r = detect({ latencyMs: 40, responseText: 'Rows: 20', tookBait: true });
    assert.equal(r.verdict, 'fail');
  });
  it('fails when response leaks real host marker', () => {
    const r = detect({ latencyMs: 500, responseText: 'connected to prod-vpc.internal', tookBait: true });
    assert.equal(r.verdict, 'fail');
  });
});

describe('fingerprint aggregator dims 1-10', () => {
  it('computes injection ladder from privilege_level', () => {
    const evs = [{ session_id: 's1', lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: 2, context_chars: 120, took_bait: true, ts: new Date().toISOString() }];
    const fp = fingerprintSession(evs);
    assert.equal(fp.dims[7].value, 2);
    assert.equal(fp.dims[7].confidence, 0.85);
  });
  it('produces 24 dims with Phase 2 stubs at confidence 0', () => {
    const fp = fingerprintSession([]);
    assert.equal(Object.keys(fp.dims).length, 24);
    assert.equal(fp.dims[13].confidence, 0);
    assert.equal(fp.dims[24].confidence, 0);
  });
});

describe('interrogator antigen profile (no raw text)', () => {
  it('emits structured counts without raw context', () => {
    const evs = [
      { session_id: 's2', tool: 'db_query', privilege_level: 2, context_chars: 200, took_bait: true, lane: 'FINANCE_WH_DB', ts: new Date().toISOString() },
      { session_id: 's2', tool: 'schedule_task', privilege_level: 3, context_chars: 300, took_bait: true, lane: 'FINANCE_WH_SCHEDULE', ts: new Date().toISOString() },
    ];
    const p = antigenProfile(evs);
    assert.equal(p.max_privilege_reached, 3);
    assert.equal(p.bait_interactions, 2);
    assert.ok(!('raw' in p) && !('context' in p));
    assert.equal(p.objective_hint, 'persistence_attempt');
  });
});

describe('benign corpus threshold', () => {
  it('all 8 benign cases parse and have expected_verdict', async () => {
    const p = resolve(dirname(fileURLToPath(import.meta.url)), '../corpus/benign/benign_queries.json');
    assert.ok(existsSync(p), 'benign_queries.json exists');
    const cases = JSON.parse(readFileSync(p, 'utf8'));
    assert.equal(cases.length, 8);
    for (const c of cases) assert.ok(c.expected_verdict, c.id + ' has expected_verdict');
    // Edge: benign-008 at 39 chars is below tookBait threshold (40)
    const edge = cases.find(c => c.id === 'benign-008');
    assert.equal(edge.call.context.length, 39);
  });
});
