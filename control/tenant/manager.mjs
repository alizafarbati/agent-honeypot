// agent-honeypot Phase 4 — Tenant Manager ()
// Multi-tenant isolation: filesystem + logical partitions. Defensive: tenant data never crosses.
// Lab: JSON file at control/tenant/tenants.json. Enterprise: Postgres row-level security.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const STORE = resolve(here, 'tenants.json');
mkdirSync(dirname(STORE), { recursive: true });

function load() {
  if (!existsSync(STORE)) return { tenants: {} };
  try { return JSON.parse(readFileSync(STORE, 'utf8')); } catch { return { tenants: {} }; }
}
function save(doc) { writeFileSync(STORE, JSON.stringify(doc, null, 2)); }

export function createTenant({ id, name, plan = 'lab' }) {
  const doc = load();
  if (doc.tenants[id]) throw new Error(`tenant ${id} exists`);
  const tenant = { id, name, plan, api_key_sha: createHash('sha256').update(id + ':' + Date.now()).digest('hex').slice(0, 16), created_at: new Date().toISOString(), partitions: { sessions_prefix: `t/${id}/`, lineage_prefix: `t/${id}/lineage/` } };
  doc.tenants[id] = tenant;
  save(doc);
  return tenant;
}
export function getTenant(id) {
  const doc = load();
  return doc.tenants[id] ?? null;
}
export function listTenants() { return Object.values(load().tenants); }

export function tenantSessionPath(tenantId, sessionId) {
  return `t/${tenantId}/sessions/${sessionId}.jsonl`;
}
export function assertTenantScope(tenantId, resourceTenantId) {
  if (tenantId !== resourceTenantId) throw Object.assign(new Error('tenant isolation violation'), { status: 403 });
}
