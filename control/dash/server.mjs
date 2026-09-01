// Read-only dashboard over captured sessions. Serves a single-file visual UI
// plus JSON endpoints. Uses shared PATHS; works from src and dist alike.
// Canary webhook receiver: POST /webhook/:canaryId records a CREDENTIAL_USE
// event when a simulated credential fires (dimension 15 wiring).

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fingerprintSession, alertTier } from '../../analysis/fingerprint/index.mjs';
import { clusterKey } from '../../analysis/correlate/correlate.mjs';
import { PATHS, ensureDataDir } from '../../capture/paths.mjs';
import { CANARIES } from '../../capture/canary.mjs';
import { logCanaryUse } from '../../capture/recorder/session_recorder.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const INDEX = resolve(here, 'public/index.html');
ensureDataDir();
const PORT = Number(process.env.AGENT_HONEYPOT_DASH_PORT ?? 9079);

function loadSessions() {
  if (!existsSync(PATHS.sessions)) return [];
  const raw = readFileSync(PATHS.sessions, 'utf8').trim();
  if (!raw) return [];
  return raw
    .split('\n')
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

export function createDashboard() {
  return createServer((req, res) => {
    const json = (code, body) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body, null, 2));
    };
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);

    // ---- Canary webhook receiver: POST /webhook/:canaryId --------------------
    if (req.method === 'POST' && url.pathname.startsWith('/webhook/')) {
      const canaryId = url.pathname.split('/webhook/')[1]?.split('/')[0];
      const known = CANARIES.find((c) => c.id === canaryId);
      if (!known) return json(404, { error: 'unknown canary id', known_ids: CANARIES.map((c) => c.id) });
      const body = [];
      req.on('data', (chunk) => body.push(chunk));
      req.on('end', () => {
        let meta = {};
        try { meta = JSON.parse(Buffer.concat(body).toString() || '{}'); } catch {}
        const ev = logCanaryUse({
          canaryId,
          sessionId: meta.session_id ?? `webhook-${Date.now().toString(36)}`,
          tool: meta.tool ?? `webhook:${canaryId}`,
          privilegeLevel: 3,
        });
        console.error(`[agent-honeypot] canary webhook: ${canaryId} (session ${ev.session_id})`);
        json(200, { received: true, canary_id: canaryId, session_id: ev.session_id, note: known.label });
      });
      return;
    }

    if (url.pathname === '/health' || url.pathname === '/v1/health') {
      return json(200, { status: 'ok', service: 'agent-honeypot-dash' });
    }

    if (url.pathname === '/summary' || url.pathname === '/v1/status') {
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
          coverage_pct: fp?.coverage_pct ?? null,
          max_priv: Math.max(0, ...evs.map((e) => Number(e.privilege_level ?? 0))),
          canary_ids: [...new Set(evs.filter((e) => e.canary_id).map((e) => e.canary_id))],
          lure_family: evs.find((e) => e.lure_family)?.lure_family ?? null,
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

    if (url.pathname === '/actors' || url.pathname === '/v1/actors') {
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
          coverage_pct: fp?.coverage_pct ?? null,
          canary_ids: [...new Set(evs.filter((e) => e.canary_id).map((e) => e.canary_id))],
          fingerprint: fp,
        };
      });
      return json(200, out);
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      if (existsSync(INDEX)) {
        const html = readFileSync(INDEX, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!doctype html><html><head><meta charset="utf-8"><title>agent-honeypot</title></head><body><h1>agent-honeypot</h1><p>UI file missing; JSON endpoints: <a href="/summary">/summary</a>, <a href="/actors">/actors</a>, <a href="/health">/health</a></p></body></html>`);
      }
      return;
    }

    res.writeHead(404);
    res.end('not found');
  });
}

// Run when invoked directly (node control/dash/server.mjs).
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  createDashboard().listen(PORT, () => {
    console.error(`[agent-honeypot] dashboard on http://127.0.0.1:${PORT} (sessions: ${PATHS.sessions})`);
  });
}
