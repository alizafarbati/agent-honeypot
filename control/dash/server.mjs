// Read-only dashboard over captured sessions. Serves a single-file visual UI
// plus JSON endpoints. Uses shared PATHS; works from src and dist alike.
// Canary webhook receiver: POST /webhook/:canaryId records a CREDENTIAL_USE
// event when a simulated credential fires (dimension 15 wiring).

import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
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

// ---- webhook hardening (F3) -------------------------------------------------
// Canary webhooks are the only externally-writable endpoint on this server.
// Unauthenticated, unbounded accepts would let anyone poison CREDENTIAL_USE
// events (fabricated dim-15 evidence, tier inflation, disk exhaustion).
// Auth model: optional shared-secret HMAC. When AGENT_HONEYPOT_WEBHOOK_SECRET
// is set, requests must carry X-Honeypot-Signature: hex(HMAC_SHA256(body)).
// Without the env var (lab mode) the endpoint stays open but is rate-limited
// and size-capped so it cannot be used as a capture-poisoning amplifiers.
const WEBHOOK_SECRET = process.env.AGENT_HONEYPOT_WEBHOOK_SECRET ?? null;
const WEBHOOK_MAX_BODY = 64 * 1024;            // 64 KB is plenty for canary metadata
const WEBHOOK_RATE_LIMIT = Number(process.env.AGENT_HONEYPOT_WEBHOOK_RATE ?? 60); // req/min per canary id
const webhookBuckets = new Map(); // canaryId -> { count, windowStart }
function webhookRateLimited(canaryId) {
  const now = Date.now();
  let b = webhookBuckets.get(canaryId);
  if (!b || now - b.windowStart > 60_000) { b = { count: 0, windowStart: now }; webhookBuckets.set(canaryId, b); }
  b.count += 1;
  return b.count > WEBHOOK_RATE_LIMIT;
}
function webhookSignatureValid(rawBody, sigHeader) {
  if (!WEBHOOK_SECRET) return true; // lab mode: no secret configured -> open but rate-limited
  if (!sigHeader) return false;
  const expected = createHmac('sha256', WEBHOOK_SECRET).update(rawBody).digest('hex');
  const a = Buffer.from(String(sigHeader), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

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
      if (webhookRateLimited(canaryId)) return json(429, { error: 'rate limit exceeded', retry_after_seconds: 60 });
      const body = [];
      let size = 0;
      let aborted = false;
      req.on('data', (chunk) => {
        size += chunk.length;
        if (size > WEBHOOK_MAX_BODY) {
          aborted = true;
          req.destroy(); // hard stop: never buffer unbounded payloads
          return;
        }
        body.push(chunk);
      });
      req.on('end', () => {
        if (aborted) return; // connection already torn down
        const raw = Buffer.concat(body);
        if (!webhookSignatureValid(raw, req.headers['x-honeypot-signature'])) {
          return json(401, { error: 'invalid or missing X-Honeypot-Signature (HMAC-SHA256 over raw body)' });
        }
        let meta = {};
        try { meta = JSON.parse(raw.toString() || '{}'); } catch {}
        // v0.2.2: attacker-supplied session_id was trusted verbatim, letting
        // the caller inject events into an arbitrary (possibly real) session's
        // event stream — corrupting fingerprints and actor clusters. Webhook
        // events are always their own synthetic session; the submitted id is
        // kept as opaque metadata only.
        const ev = logCanaryUse({
          canaryId,
          source: 'webhook',
          sessionId: `webhook-${Date.now().toString(36)}-${canaryId}`,
          tool: `webhook:${canaryId}`,
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
        // v0.2.2: absolute filesystem path removed from HTTP responses (info leak)
        capture_store: 'sessions.jsonl',
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
