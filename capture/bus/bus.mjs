// agent-honeypot — Capture bus abstraction (NATS JetStream interface, lab = file fallback)
// Production: set HONEYPOT_NATS_URL (e.g. nats://nats:4222) and install `nats` package.
// Lab tier: publish() appends to capture/bus/bus.jsonl so Phase 2 consumers can be tested
// without a running NATS cluster. Switching to real NATS is a one-line env change.

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const FALLBACK = resolve(here, 'bus.jsonl');
mkdirSync(dirname(FALLBACK), { recursive: true });

let natsClient = null;

export async function publish(subject, payload) {
  const url = process.env.HONEYPOT_NATS_URL;
  if (!url) {
    appendFileSync(FALLBACK, JSON.stringify({ ts: new Date().toISOString(), subject, payload }) + '\n');
    return { via: 'file', subject };
  }
  try {
    if (!natsClient) {
      const { connect } = await import('nats');
      natsClient = await connect({ servers: url });
    }
    const sc = natsClient.jetstream ? natsClient.jetstream() : natsClient;
    // JetStream publish if available, else core publish
    if (sc.publish) await sc.publish(subject, JSON.stringify(payload));
    else natsClient.publish(subject, JSON.stringify(payload));
    return { via: 'nats', subject };
  } catch (e) {
    // Fallback to file on NATS failure — never drop a capture event
    appendFileSync(FALLBACK, JSON.stringify({ ts: new Date().toISOString(), subject, payload, nats_error: String(e).slice(0, 200) }) + '\n');
    return { via: 'file-fallback', subject, error: String(e).slice(0, 200) };
  }
}

export function busPath() { return FALLBACK; }
