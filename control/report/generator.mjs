// agent-honeypot Phase 4 — Quarterly Report Generator ()
// Input: sessions.jsonl + fingerprints. Output: Markdown report + JSON metrics.
// Defensive: aggregates only, no raw attacker text in report.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fingerprintSession } from '../../analysis/fingerprint/index.mjs';
import { clusterKey } from '../../analysis/correlate/correlate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const JSONL = resolve(here, '../../capture/recorder/sessions.jsonl');
const OUT_DIR = resolve(here, 'out');
mkdirSync(OUT_DIR, { recursive: true });

function load() {
  if (!existsSync(JSONL)) return [];
  return readFileSync(JSONL, 'utf8').trim().split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}
function groupBySession(events) {
  const m = new Map(); for (const e of events) { const k = e.session_id ?? 'unknown'; if (!m.has(k)) m.set(k, []); m.get(k).push(e); } return m;
}

export function generateReport({ events: evts } = {}) {
  const events = evts ?? load();
  const bySess = groupBySession(events);
  const sessions = [...bySess.entries()].map(([sid, evs]) => {
    let fp = null; try { fp = fingerprintSession(evs); } catch {}
    return { session_id: sid, events: evs.length, max_priv: Math.max(0, ...evs.map(e => Number(e.privilege_level ?? 0))), cluster_key: clusterKey(evs), fp_hint: fp?.lab_composite_hint ?? null };
  });
  const totalEvents = events.length, totalSessions = bySess.size;
  const byTool = events.filter(e => e.tool).reduce((a, e) => ((a[e.tool]=(a[e.tool]??0)+1), a), {});
  const byPriv = events.reduce((a, e) => { const k = String(e.privilege_level ?? 0); a[k]=(a[k]??0)+1; return a; }, {});
  const actorClusters = new Map(); for (const s of sessions) { const k = s.cluster_key; actorClusters.set(k, (actorClusters.get(k)??0)+1); }

  const md = `# agent-honeypot Quarterly Agent Attack Landscape — ${new Date().toISOString().slice(0, 10)}
*Generated ${new Date().toISOString()} — synthetic-only, digest-only, defensive.*

## Executive summary
- Total sessions: ${totalSessions}
- Total events: ${totalEvents}
- Actor clusters (tool+priv key): ${actorClusters.size}
- Privilege distribution: ${JSON.stringify(byPriv)}

## By tool
${Object.entries(byTool).map(([k,v])=>`- ${k}: ${v}`).join('\n') || '- (no tool calls yet)'}

## Sessions (cluster key = tool histogram + max priv)
${sessions.slice(0, 20).map(s=>`- ${s.session_id} — priv ${s.max_priv}, events ${s.events}, cluster \`${s.cluster_key.slice(0,80)}\``).join('\n') || '- none'}

## Defensive posture
All events synthetic-only. No raw attacker text persisted in hot path. See \`analysis/fingerprint/index.mjs\` for 24-dim scoring.
`;
  const metrics = { generated_at: new Date().toISOString(), total_events: totalEvents, total_sessions: totalSessions, by_tool: byTool, by_privilege: byPriv, cluster_count: actorClusters.size, sessions };
  return { markdown: md, metrics };
}

const _isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (_isMain) {
  const { markdown, metrics } = generateReport();
  writeFileSync(resolve(OUT_DIR, 'report.md'), markdown);
  writeFileSync(resolve(OUT_DIR, 'metrics.json'), JSON.stringify(metrics, null, 2));
  console.error(`[agent-honeypot:report] wrote ${resolve(OUT_DIR, 'report.md')} and metrics.json`);
}
