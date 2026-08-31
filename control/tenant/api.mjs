// Tenant-scoped API. Identifies tenants via the X-Honeypot-Tenant header; swap the
// header lookup for Vault-issued JWTs in enterprise deployments. Reads only.

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { getTenant } from './manager.mjs';
import { fingerprintSession, alertTier } from '../../analysis/fingerprint/index.mjs';
import { PATHS } from '../../capture/paths.mjs';

const PORT = Number(process.env.AGENT_HONEYPOT_TENANT_API_PORT ?? 9080);

function tenantFromReq(req) {
  const id = String(req.headers['x-honeypot-tenant'] ?? 'default');
  const t = getTenant(id);
  if (!t && id !== 'default') return null;
  return t ?? { id: 'default', name: 'default', partitions: { sessions_prefix: 't/default/' } };
}

export function createTenantApi({ loadSessions } = {}) {
  const _load = loadSessions ?? (() => {
    if (!existsSync(PATHS.sessions)) return [];
    return readFileSync(PATHS.sessions, 'utf8').trim().split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  });

  return createServer((req, res) => {
    const json = (code, body) => {
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body, null, 2));
    };
    const tenant = tenantFromReq(req);
    if (!tenant) return json(403, { error: 'unknown tenant' });

    if (req.url === '/v1/tenant/health') {
      return json(200, { tenant: tenant.id, status: 'ok' });
    }
    if (req.url === '/v1/tenant/summary') {
      const events = _load().filter((e) => !e.tenant_id || e.tenant_id === tenant.id);
      const byTool = events.filter((e) => e.tool).reduce((a, e) => ((a[e.tool] = (a[e.tool] ?? 0) + 1), a), {});
      const byTier = events.length ? 'run /actors on the dashboard for per-session tiers' : 'no events';
      return json(200, { tenant: tenant.id, total_events: events.length, by_tool: byTool, note: byTier });
    }
    return json(404, { error: 'not found' });
  });
}

// Run when invoked directly.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  createTenantApi().listen(PORT, () => {
    console.error(`[agent-honeypot] tenant API on http://127.0.0.1:${PORT} (header: X-Honeypot-Tenant)`);
  });
}
