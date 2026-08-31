// MISP sync: pushes STIX bundles to a MISP instance via its REST API.
// Without AGENT_HONEYPOT_MISP_URL/KEY set, writes a simulated (auditable) JSONL record instead.

import { appendFileSync } from 'node:fs';
import { PATHS, ensureDataDir } from '../../capture/paths.mjs';

ensureDataDir();

export async function pushToMisp(bundle, { url = process.env.AGENT_HONEYPOT_MISP_URL, key = process.env.AGENT_HONEYPOT_MISP_KEY } = {}) {
  if (!url || !key) {
    appendFileSync(PATHS.misp, JSON.stringify({ ts: new Date().toISOString(), simulated: true, bundle_id: bundle.id }) + '\n');
    return { pushed: false, simulated: true, bundle_id: bundle.id };
  }
  const r = await fetch(`${url}/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: key },
    body: JSON.stringify({
      Event: {
        info: `agent-honeypot ${bundle.id}`,
        distribution: 0,
        analysis: 2,
        Attribute: [{ type: 'text', value: JSON.stringify(bundle).slice(0, 4000) }],
      },
    }),
  });
  return { pushed: r.ok, status: r.status, bundle_id: bundle.id };
}
