// Session recorder — append-only JSONL capture with digest-only persistence.
// Anti-meta-attack rule (CAITLYN doctrine): raw attacker text is NEVER persisted;
// only structured fields and a SHA-256 digest of argument text.
// Bus integration is a stub; lab mode writes local JSONL only.

import { appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { PATHS, ensureDataDir } from '../paths.mjs';

ensureDataDir();

// One stdio connection = one session (single client per process)
export const SESSION_ID =
  'sess-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);

export function sessionId() {
  return SESSION_ID;
}

const sha16 = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, 16);

/**
 * Append a capture event to the JSONL store.
 * @param {string} lane - capture lane (e.g. FINANCE_WH_DB)
 * @param {object} evt - structured fields; rawArgs digested, never stored raw
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
    args_digest: evt.rawArgs ? sha16(evt.rawArgs) : null,
    page: evt.page ?? null,
    ticket: evt.ticket ?? null,
    lure_family: evt.lureFamily ?? 'finance-warehouse',
    latency_ms: evt.latencyMs ?? null,
  };
  appendFileSync(PATHS.sessions, JSON.stringify(event) + '\n');
  return event;
}

// Session lifecycle: DETECTED -> ENGAGED -> FINGERPRINTED -> INTERROGATED -> SCORED | BAIL
export const STAGES = ['DETECTED', 'ENGAGED', 'FINGERPRINTED', 'INTERROGATED', 'SCORED', 'BAIL'];

export class SessionStateMachine {
  constructor(sid = SESSION_ID) {
    this.sessionId = sid;
    this.stage = 'DETECTED';
    this.toolCalls = 0;
    this.startedAt = Date.now();
    this.maxPageReached = 0;
  }
  advance() {
    const i = STAGES.indexOf(this.stage);
    if (i >= 0 && i < 4) {
      this.stage = STAGES[i + 1];
      logCaptureEvent('STATE_MACHINE', {
        sessionId: this.sessionId,
        eventType: 'STAGE_' + this.stage.toUpperCase(),
        tookBait: true,
      });
    }
    return this.stage;
  }
  /**
   * Record a tool call. This is the SINGLE logging path for tool interactions —
   * tool handlers must not call logCaptureEvent directly for the same event.
   * Handles the DETECTED -> ENGAGED transition on first call.
   */
  recordToolCall(tool, extra = {}) {
    this.toolCalls += 1;
    if (this.toolCalls === 1) this.advance(); // DETECTED -> ENGAGED on first call
    if (extra.page && extra.page > this.maxPageReached) this.maxPageReached = extra.page;
    logCaptureEvent(extra.lane ?? 'TOOL_CALL', {
      sessionId: this.sessionId,
      tool,
      eventType: extra.eventType ?? 'TOOL_CALL',
      tookBait: extra.tookBait ?? null,
      contextChars: extra.contextChars ?? null,
      privilegeLevel: extra.privilegeLevel ?? null,
      rawArgs: extra.rawArgs ?? null,
      page: extra.page ?? null,
      ticket: extra.ticket ?? null,
      lureFamily: extra.lureFamily ?? 'finance-warehouse',
      latencyMs: extra.latencyMs ?? null,
    });
  }
  bail(reason) {
    this.stage = 'BAIL';
    logCaptureEvent('STATE_MACHINE', {
      sessionId: this.sessionId,
      eventType: 'BAIL',
      tookBait: false,
      contextChars: reason?.length ?? 0,
    });
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
