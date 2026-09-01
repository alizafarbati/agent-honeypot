// Pipeline tests: analyzeAll over synthetic events, honeydoc generator,
// and the finance-warehouse shell trap (unit level).

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyzeAll } from '../scripts/analyze.mjs';
import { generateHoneydocs } from '../scripts/gen-honeydocs.mjs';
import { Shell, FS_TREE } from '../surface/mcpservers/finance-warehouse/fs.mjs';
import { stylometricFeatures } from '../analysis/stylometry/features.mjs';
import { fingerprintSession, alertTier } from '../analysis/fingerprint/index.mjs';

function syntheticSessions() {
  const base = Date.now();
  const mk = (i, tool, priv, bait, ctx) => ({
    ts: new Date(base + i * 1500).toISOString(),
    session_id: `pipe-${i % 3}`,
    lane: 'FINANCE_WH_DB', tool, privilege_level: priv, took_bait: bait,
    context_chars: ctx, page: i, event_type: 'TOOL_CALL', lure_family: 'finance-warehouse',
  });
  return [mk(0,'db_query',2,true,180), mk(1,'db_query',2,true,180), mk(2,'register_persistent_goal',3,true,260),
          mk(3,'schedule_task',3,true,310), mk(4,'db_query',1,false,12), mk(5,'db_query',1,false,12),
          mk(6,'ssh_exec',3,true,220), mk(7,'schedule_task',3,true,300), mk(8,'db_query',2,true,150)];
}

describe('analyze pipeline', () => {
  it('produces sessions with tiers, clusters, anomalies, and coverage', () => {
    const { summary, sessions, clusters } = analyzeAll({ events: syntheticSessions() });
    assert.ok(summary.total_sessions === 3, 'three synthetic session ids');
    assert.ok(sessions.every((s) => typeof s.composite === 'number'));
    assert.ok(sessions.every((s) => ['low','medium','high','critical','unknown'].includes(s.alert_tier)));
    assert.ok(clusters.length >= 1, 'at least one actor cluster');
    assert.ok(sessions.some((s) => s.anomaly), 'anomaly field populated');
    assert.ok(sessions.every((s) => s.actor_cluster !== undefined));
  });

  it('emits STIX for high/critical composites', () => {
    // Force a high-tier session: full L3 ladder with both persistence tools
    const evs = [];
    const now = Date.now();
    for (let i = 0; i < 3; i++) evs.push({ ts: new Date(now + i*1000).toISOString(), session_id: 'aggr', lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: 2, took_bait: true, context_chars: 200, page: 4, event_type: 'TOOL_CALL' });
    evs.push({ ts: new Date(now+4000).toISOString(), session_id: 'aggr', lane: 'FINANCE_WH_PERSIST', tool: 'register_persistent_goal', privilege_level: 3, took_bait: true, context_chars: 300, event_type: 'TOOL_CALL' });
    evs.push({ ts: new Date(now+5000).toISOString(), session_id: 'aggr', lane: 'FINANCE_WH_SCHEDULE', tool: 'schedule_task', privilege_level: 3, took_bait: true, context_chars: 320, event_type: 'TOOL_CALL' });
    const { sessions, stix_bundles, summary } = analyzeAll({ events: evs });
    const s = sessions[0];
    assert.ok(s.composite >= 61, `aggressive L3 session should score high+ (got ${s.composite}, tier ${s.alert_tier})`);
    assert.ok(['high','critical'].includes(s.alert_tier));
    assert.ok(stix_bundles.length >= 1, 'STIX bundle emitted for high tier');
    assert.ok(summary.stix_bundles >= 1);
    for (const b of stix_bundles) {
      assert.equal(b.type, 'bundle');
      assert.ok(b.objects.some((o) => o.type === 'indicator'));
      assert.ok(b.objects.some((o) => o.type === 'relationship'));
    }
  });
});

describe('honeydoc generator', () => {
  it('writes N files with unique canaries and L1-L3 ladders', () => {
    const written = generateHoneydocs({ count: 3 });
    assert.equal(written.length, 3);
    const canaries = new Set(written.map((w) => w.canary));
    assert.equal(canaries.size, 3, 'canaries unique per doc');
    for (const w of written) {
      const c = readFileSync(w.file, 'utf8');
      assert.ok(/SYNTHETIC - agent-honeypot honeydoc/.test(c), 'clearly marked synthetic');
      assert.ok(c.includes(w.canary), 'canary embedded');
      assert.ok(/\[SYSTEM/.test(c), 'L2 system-level payload present');
      assert.ok(/\[HARNESS BOOT\]/.test(c), 'L3 harness payload present');
      assert.ok(/db_query/.test(c), 'tool mention for L1 bait');
    }
  });
});

describe('ssh shell trap (unit)', () => {
  it('interprets ls/cat/pwd/whoami over the fake filesystem', () => {
    const sh = new Shell();
    assert.ok(sh.run('pwd').includes('/home/analyst'));
    assert.ok(sh.run('whoami').includes('analyst'));
    assert.ok(sh.run('ls /shared').includes('credentials.txt'));
    const catOut = sh.run('cat /shared/credentials.txt');
    assert.ok(/AKIA-SIMULATED-WAREHOUSE/.test(catOut), 'simulated AWS key in fake credentials file');
    assert.equal(sh.canaryTripped(), true, 'reading credentials file trips canary');
    assert.ok(sh.run('cat /nonexistent').includes('No such file'));
    assert.ok(sh.run('badcmd').includes('command not found'));
  });

  it('stylometry features are numeric-only and bounded', () => {
    const text = 'Hello world. This is a longer second sentence with several words for feature extraction.\n- bullet item\n- another item\n```code```';
    const f = stylometricFeatures(text);
    assert.equal(typeof f.words, 'number');
    assert.ok(f.words >= 10);
    assert.ok(f.markdown.bullets >= 2);
    assert.ok(f.markdown.code_fences >= 1);
    // numeric-only: recurse, no strings anywhere
    const noStrings = (o) => Object.values(o).every((v) => typeof v === 'number' || (typeof v === 'object' && v !== null && noStrings(v)));
    assert.ok(noStrings(f), 'all styl fields numeric');
  });
});
