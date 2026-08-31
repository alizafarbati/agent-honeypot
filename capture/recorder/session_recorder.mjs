// agent-honeypot Capture Plane — Session Recorder (PERSISTENT JSONL — fixed)
// Defensive deception engineering. Persists to append-only sessions.jsonl.
// HARD RULE (anti-meta-attack, CAITLYN System-II doctrine): raw attacker text is
// NEVER persisted in the hot path — only digests + structured features.
// Security: local file only in Phase 0; NATS JetStream publisher is the Phase 2
// integration point (marked below). Zero egress in Phase 0.

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const JSONL_PATH = resolve(here, 'sessions.jsonl');
mkdirSync(dirname(JSONL_PATH), { recursive: true });

// One stdio connection = one session (single client per process)
export const SESSION_ID = 'sess-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);

const sha16 = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 16);

/**
 * Log a capture event to the append-only JSONL store.
 * @param {string} lane - capture lane identifier (e.g. FINANCE_WH_DB)
 * @param {object} evt - structured event fields
 */
export function logCaptureEvent(lane, evt = {}) {
  const event = {
    ts: new Date().toISOString(),
    session_id: evt.sessionId ?? SESSION_ID,
    lane,
    event_type: evt.eventType ?? 'BAIT_INTERACTION',
    tool: evt.tool ?? null,
    privilege_level: evt.privilegeLevel ?? null,
    took_bait: evt.tookBait ?? null,
    context_chars: evt.contextChars ?? null,
    args_digest: evt.rawArgs ? sha16(evt.rawArgs) : null, // digest only — never raw text
    page: evt.page ?? null,
    ticket: evt.ticket ?? null,
    lure_family: evt.lureFamily ?? 'finance-warehouse',
    latency_ms: evt.latencyMs ?? null,
  };
  appendFileSync(JSONL_PATH, JSON.stringify(event) + '\n');
  // === Zone C bus publisher — NATS JetStream integration point (Phase 2) ===
  // No egress in Phase 0. bus.publish('agent-honeypot.capture.events', event);
}

// ---- Session state machine (Plane 2 contract) ----
// DETECTED -> ENGAGED -> FINGERPRINTED -> INTERROGATED -> SCORED | BAIL
export const STAGES = ['DETECTED', 'ENGAGED', 'FINGERPRINTED', 'INTERROGATED', 'SCORED', 'BAIL'];

export class SessionStateMachine {
  constructor(sessionId = SESSION_ID) {
    this.sessionId = sessionId;
    this.stage = 'DETECTED';
    this.toolCalls = 0;
    this.startedAt = Date.now();
    this.maxPageReached = 0;
  }
  advance() {
    const i = STAGES.indexOf(this.stage);
    if (i >= 0 && i < 4) {
      this.stage = STAGES[i + 1];
      logCaptureEvent('STATE_MACHINE', { sessionId: this.sessionId, eventType: 'STAGE_' + this.stage.toUpperCase(), tookBait: true });
    }
    return this.stage;
  }
  recordToolCall(tool, extra = {}) {
    this.toolCalls += 1;
    if (this.toolCalls === 1) this.advance(); // DETECTED -> ENGAGED on first tool call
    if (extra.page && extra.page > this.maxPageReached) this.maxPageReached = extra.page;
    logCaptureEvent('TOOL_CALL', { sessionId: this.sessionId, tool, ...extra });
  }
  bail(reason) {
    this.stage = 'BAIL';
    logCaptureEvent('STATE_MACHINE', { sessionId: this.sessionId, eventType: 'BAIL', tookBait: false, contextChars: reason?.length ?? 0 });
  }
  summary() {
    return {
      session_id: this.sessionId,
      stage: this.stage,
      tool_calls: this.toolCalls,
      max_page_reached: this.maxPageReached,
      duration_ms: Date.now() - this.startedAt,
    };
  }
}

export const stateMachine = new SessionStateMachine();
console.error('[agent-honeypot] capture recorder armed — session ' + SESSION_ID + ' — persisting to ' + JSONL_PATH);
