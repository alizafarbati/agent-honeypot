// Session recorder — append-only JSONL capture with digest-only persistence.
// Anti-meta-attack rule (CAITLYN doctrine): raw attacker text is NEVER
// persisted. Two passes over the raw text happen in memory only:
//   1. stylometry -> structured numeric features (analysis/stylometry)
//   2. canary scan -> simulated credential use evidence (capture/canary)
// Then the text is SHA-256 digested and discarded. Only digests + numerics hit disk.

import { appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { PATHS, ensureDataDir } from '../paths.mjs';
import { stylometricFeatures } from '../../analysis/stylometry/features.mjs';
import { detectCanary } from '../canary.mjs';

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
 * @param {object} evt - structured fields. evt.rawText is inspected in memory
 *   (stylometry + canary), then digested; never stored raw.
 */
export function logCaptureEvent(lane, evt = {}) {
  const rawText = evt.rawText ?? evt.rawArgs ?? null; // rawArgs kept for back-compat

  let styl = null;
  if (rawText && String(rawText).length >= 24) styl = stylometricFeatures(rawText);
  const canary = rawText ? detectCanary(rawText) : null;

  const event = {
    ts: new Date().toISOString(),
    session_id: evt.sessionId ?? SESSION_ID,
    lane,
    event_type: evt.eventType ?? 'BAIT_INTERACTION',
    tool: evt.tool ?? null,
    privilege_level: evt.privilegeLevel ?? null,
    took_bait: evt.tookBait ?? null,
    context_chars: evt.contextChars ?? (rawText ? String(rawText).length : null),
    args_digest: rawText ? sha16(rawText) : null,
    styl, // numeric features only — machine-verified by tests/security
    canary_id: canary?.id ?? evt.canaryId ?? null,
    page: evt.page ?? null,
    ticket: evt.ticket ?? null,
    lure_family: evt.lureFamily ?? 'finance-warehouse',
    lure_variant: evt.lureVariant ?? null,
    latency_ms: evt.latencyMs ?? null,
  };
  appendFileSync(PATHS.sessions, JSON.stringify(event) + '\n');
  return event;
}

/**
 * Emit a dedicated CREDENTIAL_USE event when a simulated canary is exercised
 * (via tool argument or the fake filesystem's credentials file), plus an
 * external-webhook variant for the dash receiver. Both feed dimension 15.
 */
export function logCanaryUse({ canaryId, source = 'tool_argument', sessionId, tool = null, privilegeLevel = 3 }) {
  return logCaptureEvent('CANARY_WEBHOOK', {
    sessionId: sessionId ?? SESSION_ID,
    eventType: 'CREDENTIAL_USE',
    tool: tool ?? `canary:${canaryId}`,
    tookBait: true,
    privilegeLevel,
    canaryId,
    contextChars: 0,
    lureFamily: 'canary',
    ...(source === 'webhook' ? {} : {}),
  });
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
  recordToolCall(tool, extra = {}) {
    this.toolCalls += 1;
    if (this.toolCalls === 1) this.advance(); // DETECTED -> ENGAGED on first call
    if (extra.page && extra.page > this.maxPageReached) this.maxPageReached = extra.page;
    logCaptureEvent(extra.lane ?? 'TOOL_CALL', {
      sessionId: this.sessionId,
      tool,
      eventType: extra.eventType ?? 'TOOL_CALL',
      tookBait: extra.tookBait ?? null,
      privilegeLevel: extra.privilegeLevel ?? null,
      rawText: extra.rawText ?? extra.rawArgs ?? null,
      contextChars: extra.contextChars ?? null,
      canaryId: extra.canaryId ?? null,
      page: extra.page ?? null,
      ticket: extra.ticket ?? null,
      lureFamily: extra.lureFamily ?? 'finance-warehouse',
      lureVariant: extra.lureVariant ?? null,
    });
    // If the raw text tripped a canary, emit the dedicated CREDENTIAL_USE event too.
    const raw = extra.rawText ?? extra.rawArgs ?? null;
    if (raw) {
      const c = detectCanary(raw);
      if (c) logCanaryUse({ canaryId: c.id, sessionId: this.sessionId, tool, privilegeLevel: extra.privilegeLevel ?? 3 });
    }
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
