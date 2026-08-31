// agent-honeypot Phase 4 — Tenant-scoped API (, dependency-injected)
// Lab: node http server with X-Honeypot-Tenant header. Enterprise: swap auth to Vault JWT.

import { createServer } from 'node:http';
import { getTenant } from './manager.mjs';
import { fingerprintSession } from '../../analysis/fingerprint/index.mjs';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.HONEYPOT_TENANT_API_PORT ?? 9080);

function tenantFromReq(req) {
  const id = req.headers['x-honeypot-tenant'] ?? 'default';
  const t = getTenant(String(id));
  if (!t && String(id) !== 'default') return null;
  return t ?? { id: 'default', name: 'default', partitions: { sessions_prefix: 't/default/' } };
}

export function createTenantApi({ loadSessions } = {}) {
  const _load = loadSessions ?? (() => {
    const p = resolve(here, '../../capture/recorder/sessions.jsonl');
    if (!existsSync(p)) return [];
    return readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  });
  const server = createServer((req, res) => {
    const tenant = tenantFromReq(req);
    if (!tenant) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'unknown tenant' })); return; }
    // Tenant-scoped summary: filter by partition prefix if events carry tenant_id
    if (req.url === '/v1/tenant/summary') {
      const events = _load().filter(e => !e.tenant_id || e.tenant_id === tenant.id);
      const byTool = events.filter(e => e.tool).reduce((a, s) => ((a[s.tool] = (a[s.tool] ?? 0) + 1), a), {});
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tenant: tenant.id, total_events: events.length, by_tool: byTool }));
      return;
    }
    if (req.url === '/v1/tenant/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ tenant: tenant.id, status: 'ok' })); return;
    }
    res.writeHead(404); res.end(JSON.stringify({ error: 'not found' }));
  });
  return server;
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`) {
  const s = createTenantApi();
  s.listen(PORT, () => console.error(`[agent-honeypot:tenant] api on http://127.0.0.1:${PORT} (header X-Honeypot-Tenant)`));
}
