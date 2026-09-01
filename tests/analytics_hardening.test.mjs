import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { embedFingerprint, cosine } from '../analysis/ml/embeddings.mjs';
import { clusterSessions } from '../analysis/ml/cluster.mjs';
import { detectAnomaly } from '../analysis/ml/anomaly.mjs';
import { jitterForLane } from '../evolution/hardening/jitter.mjs';
import { mutateSchema } from '../evolution/hardening/schema_mutator.mjs';
import { runSuite } from '../evolution/hardening/suite.mjs';
import { runPlaybook } from '../control/soar/playbook.mjs';
import { pushToMisp } from '../control/soar/misp_sync.mjs';
import { inc, exposition } from '../infra/observability/metrics.mjs';
import { shardFor } from '../infra/scale/sharding.mjs';
import { appendLedger, verifyLedger } from '../security/audit/ledger.mjs';
import { meter, usage } from '../control/billing/meter.mjs';

function fakeDims(over = {}) {
  // Values mirror what the extractors actually emit (dims_1_10 / dims_11_24).
  // v0.2.1: embeddings vocab now matches extractor outputs ('gpt-like',
  // 'claude-like', ...); 'gpt'/'claude'/'not_used' below were stale values
  // that only "worked" because the one-hot silently zeroed.
  const base = { 1:{value:'gpt-like'},2:{value:128},4:{value:'mcp_native'},5:{value:'unknown'},6:{value:'autonomous'},7:{value:2},8:{value:'low_none_observed'},9:{value:0.2},10:{value:'sequential'},11:{value:60},12:{value:1000},15:{value:null},18:{value:30},19:{value:10},20:{value:'none'},21:{value:0} };
  return { ...base, ...over };
}

describe('ML', () => {
  it('embeddings normalized + cosine self =1', () => {
    const { vector } = embedFingerprint(fakeDims());
    const c = cosine(vector, vector);
    assert.ok(Math.abs(c-1) < 1e-6);
  });
  it('cluster groups similar sessions', () => {
    // v0.2.1: 'claude-like' is a real extractor value; the old fixture used
    // 'claude' which the (previously broken) vocab never matched.
    const a = { session_id: 's1', dims: fakeDims({ 7:{value:2}}) };
    const b = { session_id: 's2', dims: fakeDims({ 7:{value:2}}) };
    const c = { session_id: 's3', dims: fakeDims({ 1:{value:'claude-like'},7:{value:0}}) };
    const clusters = clusterSessions([a,b,c], { threshold: 0.92 });
    assert.ok(clusters.length >= 2);
    // a and b are identical and must land in the same cluster
    const clOfA = clusters.find(cl => cl.members.includes('s1'));
    assert.ok(clOfA.members.includes('s2'), 'identical sessions cluster together');
  });
  it('anomaly flags outlier', () => {
    const hist = Array.from({length:10},(_,i)=>{ return {dims: fakeDims({12:{value:90+i*4},18:{value:10+(i%2)}})}; });
    const cur = { dims: fakeDims({12:{value:8000},18:{value:10}}) };
    const r = detectAnomaly(hist, cur);
    assert.equal(r.is_anomaly, true);
  });
});

describe('hardening', () => {
  it('jitter bounded per lane', () => { for(let i=0;i<10;i++){ const v=jitterForLane('FINANCE_WH_DB'); assert.ok(v>=300 && v<=1400);} });
  it('schema mutator deterministic per tenant', () => {
    const s={ properties:{ context:{type:'string'}, ticket_id:{type:'string'}}};
    const a=mutateSchema(s,{tenantId:'t1'}), b=mutateSchema(s,{tenantId:'t1'}), c=mutateSchema(s,{tenantId:'t2'});
    assert.deepEqual(Object.keys(a).sort(), Object.keys(b).sort());
    // different tenant may diverge (probabilistic but likely)
    assert.ok(Object.keys(a).length===2);
  });
  it('anti-fingerprint suite runs', async () => {
    const r = await runSuite({ callTool: async()=>({content:[{text:'pagination_token ok'}]}), listTools: async()=>[1] });
    assert.equal(r.total, 5);
    assert.ok(r.passed >= 3);
  });
});

describe('SOAR', () => {
  it('playbook critical includes quarantine', async () => {
    const r = await runPlaybook({ sessionId:'s', compositeScore: 90, events:[], tenantId:'t1' }, {});
    assert.equal(r.severity, 'critical');
    assert.ok(r.plan.includes('tenant_quarantine_shadow'));
  });
  it('misp simulated in lab', async () => {
    const r = await pushToMisp({ id: 'bundle--x' });
    assert.equal(r.simulated, true);
  });
});

describe('scale/observability', () => {
  it('metrics exposition', () => { inc('agent_honeypot_test_counter', {lane:'x'}, 2); assert.ok(exposition().includes('agent_honeypot_test_counter')); });
  it('shard deterministic', () => { assert.equal(shardFor('s1',8), shardFor('s1',8)); assert.ok(shardFor('s1',8) < 8); });
});

describe('audit ledger', () => {
  it('append + verify chain', () => {
    const a = appendLedger({ actor:'test', action:'test_append', target:'unit' });
    const v = verifyLedger();
    assert.equal(v.ok, true);
    assert.ok(a.entry_hash);
  });
});

describe('billing', () => {
  it('meter increments', () => {
    const id='bill-'+Date.now();
    meter(id, {events:2}); meter(id,{events:3});
    assert.equal(usage(id).events, 5);
  });
});
