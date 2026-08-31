// agent-honeypot — SIEM webhook dispatcher (Phase 2, defensive alerting)
// Sends STIX-derived alerts to configured SIEM endpoints (Splunk HEC / generic webhook).
// Lab tier: logs to console + appends to control/siem/deliveries.jsonl (no real egress required).
// Production: set HONEYPOT_SIEM_URL and HONEYPOT_SIEM_TOKEN env.

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const LOG = resolve(here, 'deliveries.jsonl');
mkdirSync(dirname(LOG), { recursive: true });

export async function dispatchSiemAlert({ sessionId, severity, bundle }) {
  const event = { ts: new Date().toISOString(), session_id: sessionId, severity, stix_bundle_id: bundle?.id ?? null, lane: 'agent-honeypot-siem' };
  appendFileSync(LOG, JSON.stringify(event) + '\n');
  const url = process.env.HONEYPOT_SIEM_URL;
  const token = process.env.HONEYPOT_SIEM_TOKEN;
  if (!url) {
    console.error(`[agent-honeypot:siem] simulated dispatch — session ${sessionId} severity ${severity} (set HONEYPOT_SIEM_URL to enable real webhook)`);
    return { dispatched: false, simulated: true, event };
  }
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ event, bundle }) });
    const ok = r.ok;
    console.error(`[agent-honeypot:siem] webhook ${r.status} for ${sessionId}`);
    return { dispatched: ok, status: r.status, event };
  } catch (e) {
    console.error(`[agent-honeypot:siem] webhook error for ${sessionId}: ${String(e).slice(0, 200)}`);
    return { dispatched: false, error: String(e).slice(0, 300), event };
  }
}
