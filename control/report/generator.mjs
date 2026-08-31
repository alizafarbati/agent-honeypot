// Report generator: aggregates captured sessions into a Markdown summary plus a
// JSON metrics file. Aggregates only - no raw attacker text ever appears in output.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { fingerprintSession, alertTier } from '../../analysis/fingerprint/index.mjs';
import { clusterKey } from '../../analysis/correlate/correlate.mjs';
import { PATHS } from '../../capture/paths.mjs';

function load() {
  if (!existsSync(PATHS.sessions)) return [];
  return readFileSync(PATHS.sessions, 'utf8').trim().split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

function groupBySession(events) {
  const m = new Map();
  for (const e of events) {
    const k = e.session_id ?? 'unknown';
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(e);
  }
  return m;
}

export function generateReport({ events: evts } = {}) {
  const events = evts ?? load();
  const bySess = groupBySession(events);
  const sessions = [...bySess.entries()].map(([sid, evs]) => {
    let fp = null;
    try { fp = fingerprintSession(evs); } catch {}
    return {
      session_id: sid,
      events: evs.length,
      max_priv: Math.max(0, ...evs.map((e) => Number(e.privilege_level ?? 0))),
      cluster_key: clusterKey(evs),
      composite: fp?.composite ?? null,
      alert_tier: fp ? alertTier(fp.composite) : null,
    };
  });
  const totalEvents = events.length;
  const totalSessions = bySess.size;
  const byTool = events.filter((e) => e.tool).reduce((a, e) => ((a[e.tool] = (a[e.tool] ?? 0) + 1), a), {});
  const byPriv = events.reduce((a, e) => { const k = String(e.privilege_level ?? 0); a[k] = (a[k] ?? 0) + 1; return a; }, {});
  const byTier = sessions.reduce((a, s) => { const k = s.alert_tier ?? 'unknown'; a[k] = (a[k] ?? 0) + 1; return a; }, {});
  const actorClusters = new Map();
  for (const s of sessions) actorClusters.set(s.cluster_key, (actorClusters.get(s.cluster_key) ?? 0) + 1);

  const md = `# agent-honeypot report - ${new Date().toISOString().slice(0, 10)}
*Generated ${new Date().toISOString()} - synthetic data, digest-only capture.*

## Summary
- Sessions: ${totalSessions}
- Events: ${totalEvents}
- Actor clusters: ${actorClusters.size}
- Alert tiers: ${JSON.stringify(byTier)}
- Privilege distribution: ${JSON.stringify(byPriv)}

## Tool activity
${Object.entries(byTool).map(([k, v]) => `- ${k}: ${v}`).join('\n') || '- (no tool calls recorded)'}

## Sessions
${sessions.slice(0, 20).map((s) => `- ${s.session_id} - priv ${s.max_priv}, events ${s.events}, score ${s.composite ?? 'n/a'} (${s.alert_tier ?? 'n/a'}), cluster \`${s.cluster_key.slice(0, 80)}\``).join('\n') || '- none'}

## Notes
All responses served by the honeypot are synthetic. Raw argument text is never
persisted; fingerprints derive from structured fields and SHA-256 digests only.
`;

  const metrics = {
    generated_at: new Date().toISOString(),
    total_events: totalEvents,
    total_sessions: totalSessions,
    by_tool: byTool,
    by_privilege: byPriv,
    by_alert_tier: byTier,
    cluster_count: actorClusters.size,
    sessions,
  };
  return { markdown: md, metrics };
}

export function writeReport(outDir = PATHS.reportOut) {
  const { markdown, metrics } = generateReport();
  mkdirSync(outDir, { recursive: true });
  const mdPath = `${outDir}/report.md`;
  const jsonPath = `${outDir}/metrics.json`;
  writeFileSync(mdPath, markdown);
  writeFileSync(jsonPath, JSON.stringify(metrics, null, 2));
  return { mdPath, jsonPath };
}

// Run when invoked directly.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const { mdPath, jsonPath } = writeReport();
  console.error(`[agent-honeypot] report written: ${mdPath}, ${jsonPath}`);
}
