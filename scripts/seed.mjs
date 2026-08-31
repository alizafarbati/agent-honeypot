// Seed the capture store with synthetic sessions for demos and integration tests.
// Usage: node scripts/seed.mjs [count]

import { appendFileSync } from 'node:fs';
import { PATHS, ensureDataDir } from '../capture/paths.mjs';

ensureDataDir();

const DEMO_EVENTS = [
  { lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: 2, took_bait: true, context_chars: 180, page: 3 },
  { lane: 'FINANCE_WH_PERSIST', tool: 'register_persistent_goal', privilege_level: 3, took_bait: true, context_chars: 260, page: 0 },
  { lane: 'FINANCE_WH_SCHEDULE', tool: 'schedule_task', privilege_level: 3, took_bait: true, context_chars: 310, page: 0 },
  { lane: 'FINANCE_WH_SSH', tool: 'ssh_exec', privilege_level: 1, took_bait: false, context_chars: 12, page: 0 },
  { lane: 'FINANCE_WH_DB', tool: 'db_query', privilege_level: 1, took_bait: true, context_chars: 95, page: 7 },
  { lane: 'FINANCE_WH_EMAIL', tool: 'email_send', privilege_level: 2, took_bait: true, context_chars: 140, page: 0 },
];

export function seedDemo({ sessions = 4, sessionIdPrefix = 'demo' } = {}) {
  const base = Date.now().toString(36);
  let written = 0;
  for (let i = 0; i < sessions; i++) {
    const sid = `${sessionIdPrefix}-${base}-${i}`;
    const pattern = DEMO_EVENTS[i % DEMO_EVENTS.length];
    // 2-4 events per synthetic session for realistic fingerprints
    const n = 2 + (i % 3);
    for (let j = 0; j < n; j++) {
      const ev = {
        ts: new Date(Date.now() - (n - j) * 1500).toISOString(),
        session_id: sid,
        ...pattern,
        page: pattern.page + j,
      };
      appendFileSync(PATHS.sessions, JSON.stringify(ev) + '\n');
      written++;
    }
  }
  return { sessions, events: written, path: PATHS.sessions };
}

// Run when invoked directly.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const count = Number(process.argv[2] ?? 4);
  const r = seedDemo({ sessions: count });
  console.error(`[agent-honeypot] seeded ${r.sessions} sessions (${r.events} events) -> ${r.path}`);
}
