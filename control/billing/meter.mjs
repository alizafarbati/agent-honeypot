// agent-honeypot Phase 10 — Billing Meter ()
// Lab: file counters. Enterprise: Stripe metered billing via API.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const STORE = resolve(here, 'usage.json');
mkdirSync(dirname(STORE), { recursive: true });

function load() { if (!existsSync(STORE)) return {}; try { return JSON.parse(readFileSync(STORE, 'utf8')); } catch { return {}; } }
function save(d) { writeFileSync(STORE, JSON.stringify(d, null, 2)); }

export function meter(tenantId, { events = 1, stixBundles = 0, siemDispatches = 0 } = {}) {
  const d = load();
  const cur = d[tenantId] ?? { events: 0, stixBundles: 0, siemDispatches: 0, updated_at: null };
  cur.events += events; cur.stixBundles += stixBundles; cur.siemDispatches += siemDispatches;
  cur.updated_at = new Date().toISOString();
  d[tenantId] = cur; save(d); return cur;
}
export function usage(tenantId) { return load()[tenantId] ?? { events: 0, stixBundles: 0, siemDispatches: 0 }; }
export function allUsage() { return load(); }
