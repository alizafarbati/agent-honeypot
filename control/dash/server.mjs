// Read-only dashboard over captured sessions. Serves JSON endpoints; no write access
// to the capture store. Uses shared PATHS so it works from src and dist alike.

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { fingerprintSession, alertTier } from '../../analysis/fingerprint/index.mjs';
import { clusterKey } from '../../analysis/correlate/correlate.mjs';
import { PATHS, ensureDataDir } from '../../capture/paths.mjs';

ensureDataDir();
const PORT = Number(process.env.AGENT_HONEYPOT_DASH_PORT ?? 9079);

function loadSessions() {
  if (!existsSync(PATHS.sessions)) return [];
  const raw = readFileSync(PATHS.sessions, 'utf8').trim();
  if (!raw) return [];
  return raw
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    })
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

export function createDashboard() {
  return createServer((req, res) => {
    const json = (code, body) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body, null, 2));
    };

    if (req.url === '/health' || req.url === '/v1/health') {
      return json(200, { status: 'ok', service: 'agent-honeypot-dash' });
    }

    if (req.url === '/summary' || req.url === '/v1/status') {
      const events = loadSessions();
      const bySess = groupBySession(events);
      const byLane = events.reduce((a, e) => ((a[e.lane ?? 'unknown'] = (a[e.lane ?? 'unknown'] ?? 0) + 1), a), {});
      const byTool = events.filter((e) => e.tool).reduce((a, e) => ((a[e.tool] = (a[e.tool] ?? 0) + 1), a), {});
      const actors = [...bySess.entries()].map(([sid, evs]) => {
        let fp = null;
        try { fp = fingerprintSession(evs); } catch {}
        return {
          session_id: sid,
          events: evs.length,
          cluster_key: clusterKey(evs),
          composite: fp?.composite ?? null,
          alert_tier: fp ? alertTier(fp.composite) : null,
        };
      });
      const maxPriv = events.length ? Math.max(...events.map((e) => Number(e.privilege_level ?? 0))) : 0;
      return json(200, {
        total_events: events.length,
        sessions: bySess.size,
        max_privilege: maxPriv,
        by_lane: byLane,
        by_tool: byTool,
        actors,
        sessions_path: PATHS.sessions,
      });
    }

    if (req.url === '/actors' || req.url === '/v1/actors') {
      const events = loadSessions();
      const bySess = groupBySession(events);
      const out = [...bySess.entries()].map(([sid, evs]) => {
        let fp = null;
        try { fp = fingerprintSession(evs); } catch {}
        return {
          session_id: sid,
          event_count: evs.length,
          cluster_key: clusterKey(evs),
          composite: fp?.composite ?? null,
          alert_tier: fp ? alertTier(fp.composite) : null,
          fingerprint: fp,
        };
      });
      return json(200, out);
    }

    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><html><head><meta charset="utf-8"><title>agent-honeypot dashboard</title><style>code{word-break:break-all}body{font-family:system-ui,Segoe UI,sans-serif;margin:24px;max-width:900px}</style></head><body><h1>agent-honeypot dashboard</h1><ul><li><a href="/summary">/summary</a> - capture stats and per-session scores (JSON)</li><li><a href="/actors">/actors</a> - full fingerprints and cluster keys (JSON)</li><li><a href="/health">/health</a> - health check (JSON)</li></ul><p>Defensive deception framework - synthetic-only, digest-only. Session log: <code>${PATHS.sessions}</code></p></body></html>`);
      return;
    }

    res.writeHead(404);
    res.end('not found');
  });
}

// Run when invoked directly (node control/dash/server.mjs), not on import.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  createDashboard().listen(PORT, () => {
    console.error(`[agent-honeypot] dashboard on http://127.0.0.1:${PORT} (sessions: ${PATHS.sessions})`);
  });
}
