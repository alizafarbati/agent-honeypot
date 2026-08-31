// agent-honeypot Phase 7 — MISP Sync ( stub)
// Pushes STIX bundles to MISP via API. Lab: file fallback to control/soar/misp_out.jsonl.

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(here, 'misp_out.jsonl');
mkdirSync(dirname(OUT), { recursive: true });

export async function pushToMisp(bundle, { url = process.env.HONEYPOT_MISP_URL, key = process.env.HONEYPOT_MISP_KEY } = {}) {
  if (!url || !key) {
    // Lab fallback — still auditable
    const line = JSON.stringify({ ts: new Date().toISOString(), simulated: true, bundle_id: bundle.id }) + '\n';
    // lazy import to avoid top-level side effect in tests
    const { appendFileSync } = await import('node:fs');
    appendFileSync(OUT, line);
    return { pushed: false, simulated: true, bundle_id: bundle.id };
  }
  const r = await fetch(`${url}/events`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: key }, body: JSON.stringify({ Event: { info: `agent-honeypot ${bundle.id}`, distribution: 0, analysis: 2, Attribute: [{ type: 'text', value: JSON.stringify(bundle).slice(0, 4000) }] } }) });
  return { pushed: r.ok, status: r.status, bundle_id: bundle.id };
}
