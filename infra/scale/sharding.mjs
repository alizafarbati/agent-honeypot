// agent-honeypot Phase 8 — Sharding ()
// Consistent hash sharding for sessions across N capture nodes.
// Deterministic: same session_id always routes to same shard (sticky).

import { createHash } from 'node:crypto';

export function shardFor(sessionId, shardCount = 8) {
  const h = createHash('sha256').update(String(sessionId)).digest();
  const n = h.readUInt32BE(0);
  return n % shardCount;
}

export function shardMap(sessionIds, shardCount = 8) {
  const m = new Map();
  for (const id of sessionIds) {
    const s = shardFor(id, shardCount);
    if (!m.has(s)) m.set(s, []);
    m.get(s).push(id);
  }
  return m;
}

export const config = {
  default_shards: Number(process.env.HONEYPOT_SHARDS ?? 8),
  rebalance_note: 'Add shards only via consistent-hash ring expansion; existing sessions stay sticky.',
};
