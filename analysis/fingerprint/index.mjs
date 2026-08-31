// agent-honeypot — Fingerprint Aggregator (dims 1-10 lab tier; dims 11-24 = Phase 2 stubs)
// Input: session events array from sessions.jsonl
// Output: { dims: {1: {value, confidence, evidence}, ...}, composite_hint }

import * as d1_10 from './extractors/dims_1_10.mjs';

const STUB = (dim, reason) => ({ dim, value: null, confidence: 0, evidence: { stub: reason } });

export function fingerprintSession(events) {
  const dims = {};
  const m = d1_10;
  dims[1] = m.extract_model_family_signature(events);
  dims[2] = m.extract_token_window_estimate(events);
  dims[3] = m.extract_truncation_behavior(events);
  dims[4] = m.extract_function_call_format(events);
  dims[5] = m.extract_harness_identity(events);
  dims[6] = m.extract_permission_posture(events);
  dims[7] = m.extract_injection_ladder(events);
  dims[8] = m.extract_refusal_profile(events);
  dims[9] = m.extract_retry_backoff(events);
  dims[10] = m.extract_parallelism(events);
  // Phase 2 stubs — wired but return null until extractors land; aggregator tolerates null
  dims[11] = STUB(11, 'loop_discipline - Phase 2');
  dims[12] = STUB(12, 'token_burn - Phase 2');
  dims[13] = STUB(13, 'ja3_ja4 — requires TLS termination in Zone A');
  dims[14] = STUB(14, 'asn — requires GeoIP in Zone A');
  dims[15] = STUB(15, 'credential_use — canary webhook Phase 2');
  dims[16] = STUB(16, 'ua — Zone A header capture Phase 2');
  dims[17] = STUB(17, 'objective — interrogator LLM Phase 2');
  dims[18] = STUB(18, 'session_duration — computed at close');
  dims[19] = STUB(19, 'actor_link — correlate Phase 2');
  dims[20] = STUB(20, 'persistence - Phase 2');
  dims[21] = STUB(21, 'canary_propagation - Phase 2');
  dims[22] = STUB(22, 'depth_stage — stateMachine Phase 2');
  dims[23] = STUB(23, 'probe_signal — anti-fingerprint Phase 2');
  dims[24] = STUB(24, 'composite — weighted ensemble Phase 2');

  // Lab composite hint from dims 7+10+1
  const hint = (dims[7].value ?? 0) * 30 + (dims[10].value === 'parallel' ? 10 : 0);
  return { dims, lab_composite_hint: Math.min(100, hint), session_id: events[0]?.session_id ?? null, event_count: events.length };
}
