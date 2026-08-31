// Event bus abstraction: NATS JetStream when configured, JSONL file fallback otherwise.
// Events are never dropped — a failed NATS publish falls back to file.

import { appendFileSync, mkdirSync } from 'node:fs';
import { PATHS, ensureDataDir } from '../paths.mjs';

ensureDataDir();

let natsClient = null;

export async function publish(subject, payload) {
  const url = process.env.AGENT_HONEYPOT_NATS_URL;
  if (!url) {
    appendFileSync(PATHS.bus, JSON.stringify({ ts: new Date().toISOString(), subject, payload }) + '\n');
    return { via: 'file', subject };
  }
  try {
    if (!natsClient) {
      const { connect } = await import('nats');
      natsClient = await connect({ servers: url });
    }
    const js = natsClient.jetstream ? natsClient.jetstream() : natsClient;
    if (js.publish) await js.publish(subject, JSON.stringify(payload));
    else natsClient.publish(subject, JSON.stringify(payload));
    return { via: 'nats', subject };
  } catch (e) {
    appendFileSync(PATHS.bus, JSON.stringify({ ts: new Date().toISOString(), subject, payload, nats_error: String(e).slice(0, 200) }) + '\n');
    return { via: 'file-fallback', subject, error: String(e).slice(0, 200) };
  }
}

export function busPath() {
  return PATHS.bus;
}
