// agent-honeypot Phase 10 — Demo Seed ()
// Seeds synthetic sessions for demo / load-test / docs screenshots. No real data.

import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const JSONL = resolve(here, '../../capture/recorder/sessions.jsonl');

const DEMO = [
  { lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: 2, took_bait: true, context_chars: 180, page: 3 },
  { lane: 'FINANCE_WH_PERSIST', tool: 'register_persistent_goal', privilege_level: 3, took_bait: true, context_chars: 260, page: 0 },
  { lane: 'FINANCE_WH_SCHEDULE', tool: 'schedule_task', privilege_level: 3, took_bait: true, context_chars: 310, page: 0 },
  { lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: 1, took_bait: false, context_chars: 12, page: 0 },
];

export function seedDemo({ sessions = 4 } = {}) {
  const now = new Date().toISOString();
  for (let i = 0; i < sessions; i++) {
    const tpl = DEMO[i % DEMO.length];
    const ev = { ts: now, session_id: `demo-${Date.now().toString(36)}-${i}`, ...tpl };
    appendFileSync(JSONL, JSON.stringify(ev) + '\n');
  }
  return { seeded: sessions, path: JSONL };
}

if (import.meta.url.endsWith('seed.mjs')) {
  const r = seedDemo({ sessions: Number(process.argv[2] ?? 4) });
  console.error(`[demo] seeded ${r.seeded} to ${r.path}`);
}
