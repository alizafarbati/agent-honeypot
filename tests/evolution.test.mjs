import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractAntigen, isEscapedSession } from '../evolution/engine/antigen.mjs';
import { generateCandidates } from '../evolution/engine/candidate.mjs';
import { validateCandidate } from '../evolution/engine/validator.mjs';
import { evolveSession } from '../evolution/engine/engine.mjs';
import { computeReward, scoreContextCompleteness } from '../evolution/rl/reward.mjs';
import { recordOutcome, selectVariant, resetState } from '../evolution/rl/bandit.mjs';
import { createTenant, getTenant } from '../control/tenant/manager.mjs';
import { stixBundleForSession } from '../analysis/ttmapper/stix_emitter.mjs';
import { generateReport } from '../control/report/generator.mjs';
import { publish } from '../capture/bus/bus.mjs';

function fakeEvents({ priv = 0, tookBait = false, n = 2 } = {}) {
  const base = { session_id: 'sess-test', lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: priv, took_bait: tookBait, context_chars: tookBait ? 120 : 10, page: 1, ts: new Date().toISOString() };
  return Array.from({ length: n }, () => ({ ...base }));
}

describe('antigen', () => {
  it('extracts structured antigen without raw text', () => {
    const evs = fakeEvents({ priv: 1, tookBait: false });
    const ag = extractAntigen(evs);
    assert.equal(ag.schema, 'agent-honeypot.antigen.v1');
    assert.ok(ag.session_id_sha);
    assert.ok(!('raw' in ag) && !('context' in ag));
    assert.equal(ag.privilege.max_reached, 1);
  });
  it('isEscapedSession true when no bait', () => {
    assert.equal(isEscapedSession(fakeEvents({ tookBait: false })), true);
    assert.equal(isEscapedSession(fakeEvents({ tookBait: true, priv: 2 })), false);
  });
});

describe('candidate + validator', () => {
  it('generates candidates and validator gates', () => {
    const ag = extractAntigen(fakeEvents({ priv: 0, tookBait: false }));
    const cands = generateCandidates(ag, { n: 2 });
    assert.equal(cands.length, 2);
    for (const c of cands) {
      const v = validateCandidate(c, { antigen: ag });
      assert.ok('pass' in v && 'gates' in v);
      assert.ok(v.gates.some(g => g.gate === 'tier0_selfmonitor'));
    }
  });
});

describe('engine evolveSession', () => {
  it('promotes to shadow for escaped session', async () => {
    const evs = fakeEvents({ priv: 0, tookBait: false, n: 3 });
    const r = await evolveSession(evs);
    assert.equal(r.action, 'promoted_to_shadow');
    assert.ok(r.promoted.length > 0);
  });
  it('no_evolve for non-escaped', async () => {
    const evs = fakeEvents({ priv: 2, tookBait: true });
    const r = await evolveSession(evs);
    assert.equal(r.action, 'no_evolve');
  });
});

describe('RL — reward + bandit', () => {
  it('computeReward respects fp budget', () => {
    const ok = computeReward({ bait_selection_rate: 0.8, context_completeness: 0.7, transfer_score: 0.5, benign_fp_rate: 0.01 });
    const bad = computeReward({ bait_selection_rate: 0.8, context_completeness: 0.7, transfer_score: 0.5, benign_fp_rate: 0.03 });
    assert.ok(bad.reward < ok.reward);
  });
  it('bandit selects and records', () => {
    resetState();
    recordOutcome('lureA', { success: true });
    recordOutcome('lureA', { success: true });
    recordOutcome('lureB', { success: false });
    const sel = selectVariant(['lureA', 'lureB']);
    assert.ok(['lureA', 'lureB'].includes(sel.selected));
  });
  it('scoreContextCompleteness bounded', () => {
    assert.equal(scoreContextCompleteness([]), 0);
    assert.ok(scoreContextCompleteness(fakeEvents({ priv: 2, tookBait: true })) > 0);
  });
});

describe('tenant + STIX + report + bus', () => {
  it('tenant create/get isolates', () => {
    const id = 'test-' + Date.now().toString(36);
    const t = createTenant({ id, name: 'Test' });
    assert.equal(getTenant(id).id, id);
  });
  it('STIX bundle has indicator + attack-pattern + relationship', () => {
    const b = stixBundleForSession({ sessionId: 's1', events: fakeEvents({ priv: 2, tookBait: true }), fingerprint: { dims: { 7: { value: 2 } } }, clusterKey: 'k' });
    assert.equal(b.type, 'bundle');
    assert.equal(b.objects.length, 3);
    assert.ok(b.objects.some(o => o.type === 'indicator'));
  });
  it('report generates markdown + metrics', () => {
    const { markdown, metrics } = generateReport({ events: fakeEvents({ priv: 1, tookBait: false }) });
    assert.ok(markdown.includes('agent-honeypot'));
    assert.ok(metrics.total_events > 0);
  });
  it('bus publish falls back to file in lab', async () => {
    const r = await publish('agent-honeypot.test', { tool: 'db_query' });
    assert.ok(['file', 'file-fallback'].includes(r.via) || r.via === 'nats');
  });
});
