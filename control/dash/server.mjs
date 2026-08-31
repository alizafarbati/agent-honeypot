import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fingerprintSession } from '../../analysis/fingerprint/index.mjs';
import { clusterKey } from '../../analysis/correlate/correlate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const JSONL = resolve(here, '../../capture/recorder/sessions.jsonl');
const PORT = Number(process.env.HONEYPOT_DASH_PORT ?? 9079);

function loadSessions() {
  if (!existsSync(JSONL)) return [];
  const raw = readFileSync(JSONL, 'utf8').trim();
  if (!raw) return [];
  return raw.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
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

const server = createServer((req, res) => {
  if (req.url === '/health' || req.url === '/v1/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ status: 'ok', service: 'agent-honeypot-dash', version: '1.0.0-alpha.2', phases: 'lab' }));
    return;
  }
  if (req.url === '/summary' || req.url === '/v1/status') {
    const events = loadSessions();
    const byLane = events.reduce((a, s) => ((a[s.lane ?? 'unknown'] = (a[s.lane ?? 'unknown'] ?? 0) + 1), a), {});
    const byTool = events.filter((s) => s.tool).reduce((a, s) => ((a[s.tool] = (a[s.tool] ?? 0) + 1), a), {});
    // Phase 1: actor clustering summary (lightweight — no pgvector, in-memory)
    const bySess = groupBySession(events);
    const actors = [...bySess.entries()].map(([sid, evs]) => ({
      session_id: sid,
      events: evs.length,
      cluster_key: clusterKey(evs),
      fingerprint_hint: (() => { try { return fingerprintSession(evs).lab_composite_hint; } catch { return null; } })(),
    }));
    const maxPriv = events.length ? Math.max(...events.map(e => Number(e.privilege_level ?? 0))) : 0;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ total_events: events.length, sessions: bySess.size, max_privilege: maxPriv, by_lane: byLane, by_tool: byTool, actors, sessions_path: JSONL }, null, 2));
    return;
  }
  if (req.url === '/actors' || req.url === '/v1/actors') {
    const events = loadSessions();
    const bySess = groupBySession(events);
    const out = [...bySess.entries()].map(([sid, evs]) => {
      let fp = null; try { fp = fingerprintSession(evs); } catch {}
      return { session_id: sid, event_count: evs.length, cluster_key: clusterKey(evs), fingerprint: fp };
    });
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(out, null, 2)); return;
  }
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><html><head><meta charset="utf-8"><title>agent-honeypot Control</title><style>code{word-break:break-all}body{font-family:system-ui,Segoe UI,Arial;margin:24px;max-width:900px}</style></head><body><h1>agent-honeypot dashboard</h1><ul><li><a href="/summary">/summary</a> - capture stats + actor hints (JSON)</li><li><a href="/actors">/actors</a> - per-session fingerprint + cluster key (JSON)</li><li><a href="/health">/health</a> - health check (JSON)</li></ul><p>Defensive deception framework - synthetic-only, digest-only, JSONL at <code>${JSONL}</code>.</p><p style="color:#666;font-size:12px">If you see garbled characters, your terminal is on CP1252. Run <code>chcp 65001</code> or open this page in a browser.</p></body></html>`);
    return;
  }
  res.writeHead(404); res.end('not found');
});

server.listen(PORT, () => console.error(`[agent-honeypot] dash 1+2 on http://127.0.0.1:${PORT} (sessions: ${JSONL})`));
