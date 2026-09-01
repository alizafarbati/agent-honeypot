// One-shot analysis pipeline over captured sessions:
// group -> fingerprint (24 dims + composite/tier) -> cluster (cosine) ->
// anomaly (z-score) -> STIX 2.1 for high/critical sessions.
// Writes data/analysis.json and prints a compact table.

import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { fingerprintSession, alertTier } from '../analysis/fingerprint/index.mjs';
import { clusterSessions } from '../analysis/ml/cluster.mjs';
import { detectAnomaly } from '../analysis/ml/anomaly.mjs';
import { stixBundleForSession } from '../analysis/ttmapper/stix_emitter.mjs';
import { clusterKey } from '../analysis/correlate/correlate.mjs';
import { PATHS, ensureDataDir } from '../capture/paths.mjs';

function loadSessions() {
  if (!existsSync(PATHS.sessions)) return [];
  return readFileSync(PATHS.sessions, 'utf8').trim().split('\n')
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function groupBySession(events) {
  const m = new Map();
  for (const e of events) {
    const sid = e.session_id ?? 'unknown';
    if (!m.has(sid)) m.set(sid, []);
    m.get(sid).push(e);
  }
  return m;
}

export function analyzeAll({ events } = {}) {
  const evts = events ?? loadSessions();
  const bySess = groupBySession(evts);

  const sessions = [];
  for (const [sid, evs] of bySess) {
    let fp = null;
    try { fp = fingerprintSession(evs); } catch {}
    sessions.push({
      session_id: sid,
      event_count: evs.length,
      dims: fp?.dims ?? null,
      composite: fp?.composite ?? null,
      coverage_pct: fp?.coverage_pct ?? null,
      alert_tier: fp ? alertTier(fp.composite) : 'unknown',
      cluster_key: clusterKey(evs),
      lure_family: evs.find((e) => e.lure_family)?.lure_family ?? 'finance-warehouse',
      canary_ids: [...new Set(evs.filter((e) => e.canary_id).map((e) => e.canary_id))],
      event_type: evs[0]?.event_type ?? 'TOOL_CALL',
    });
  }

  // Actor clustering over fingerprints (lab: greedy cosine; enterprise: pgvector).
  const clusters = clusterSessions(
    sessions.filter((s) => s.dims).map((s) => ({ session_id: s.session_id, dims: s.dims })),
  );
  const clusterOf = new Map();
  for (const c of clusters) for (const m of c.members) clusterOf.set(m, c.actor_id);
  for (const s of sessions) s.actor_cluster = clusterOf.get(s.session_id) ?? null;

  // Anomaly: each session scored against prior sessions in order of arrival.
  const withDims = sessions.filter((s) => s.dims);
  for (let i = 0; i < withDims.length; i++) {
    try {
      const history = withDims.slice(Math.max(0, i - 10), i); // sliding window
      const r = detectAnomaly(history, withDims[i]);
      withDims[i].anomaly = { is_anomaly: r.is_anomaly, reasons: r.reasons, scores: r.scores };
    } catch { withDims[i].anomaly = { is_anomaly: false, reasons: [], scores: {} }; }
  }

  // STIX bundles for high/critical sessions.
  const stix_bundles = [];
  for (const s of sessions) {
    if (s.alert_tier === 'high' || s.alert_tier === 'critical') {
      try {
        const bundle = stixBundleForSession({
          sessionId: s.session_id,
          events: evts.filter((e) => e.session_id === s.session_id),
          fingerprint: { dims: s.dims ?? {} },
          clusterKey: s.cluster_key,
        });
        stix_bundles.push(bundle);
      } catch { /* skip malformed */ }
    }
  }

  const summary = {
    generated_at: new Date().toISOString(),
    total_sessions: sessions.length,
    tier_counts: sessions.reduce((a, s) => { const k = s.alert_tier ?? 'unknown'; a[k] = (a[k] ?? 0) + 1; return a; }, {}),
    actor_clusters: clusters.length,
    anomaly_sessions: sessions.filter((s) => s.anomaly?.is_anomaly).length,
    canary_sessions: sessions.filter((s) => s.canary_ids.length > 0).length,
    stix_bundles: stix_bundles.length,
    lure_families: [...new Set(sessions.map((s) => s.lure_family))],
  };

  return { summary, sessions, clusters, stix_bundles };
}

// ---- runner -----------------------------------------------------------------
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain) {
  ensureDataDir();
  const { summary, sessions } = analyzeAll();

  console.error(`\nagent-honeypot analyze\n---------------------`);
  console.error(`sessions:        ${summary.total_sessions}`);
  console.error(`tiers:           ${JSON.stringify(summary.tier_counts)}`);
  console.error(`actor clusters:  ${summary.actor_clusters}`);
  console.error(`anomalies:       ${summary.anomaly_sessions}`);
  console.error(`canary sessions: ${summary.canary_sessions}`);
  console.error(`stix bundles:    ${summary.stix_bundles} (high/critical)`);
  console.error(`\nsession                             tier      score  cov  cluster`);
  for (const s of sessions.slice(0, 15)) {
    const tier = (s.alert_tier ?? '?').padEnd(8);
    const score = String(s.composite ?? '-').padStart(5);
    const cov = String(s.coverage_pct ?? '-').padStart(3);
    const cl = (s.actor_cluster ?? '-').slice(0, 18);
    console.error(`${(s.session_id ?? '?').slice(0, 34).padEnd(35)}${tier}${score}  ${cov}  ${cl}`);
  }
  writeFileSync(`${PATHS.dataDir}/analysis.json`, JSON.stringify(analyzeAll(), null, 2));
  console.error(`\nfull output: ${PATHS.dataDir}/analysis.json`);
}
