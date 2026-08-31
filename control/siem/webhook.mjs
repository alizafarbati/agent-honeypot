// SIEM webhook dispatcher: sends STIX-derived alerts to a configured endpoint
// (Splunk HEC or any generic JSON webhook). Without AGENT_HONEYPOT_SIEM_URL set,
// records a simulated (auditable) delivery to the local JSONL file.

import { appendFileSync } from 'node:fs';
import { PATHS, ensureDataDir } from '../../capture/paths.mjs';

ensureDataDir();

export async function dispatchSiemAlert({ sessionId, severity, bundle }) {
  const event = {
    ts: new Date().toISOString(),
    session_id: sessionId,
    severity,
    stix_bundle_id: bundle?.id ?? null,
    lane: 'siem-dispatch',
  };
  appendFileSync(PATHS.siem, JSON.stringify(event) + '\n');

  const url = process.env.AGENT_HONEYPOT_SIEM_URL;
  const token = process.env.AGENT_HONEYPOT_SIEM_TOKEN;
  if (!url) {
    return { dispatched: false, simulated: true, event };
  }
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ event, bundle }),
    });
    return { dispatched: r.ok, status: r.status, event };
  } catch (e) {
    return { dispatched: false, error: String(e).slice(0, 300), event };
  }
}
