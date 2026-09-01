// Fingerprint extractors, dimensions 1-10.
// Each extractor: (events: CaptureEvent[]) => { dim, value, confidence, evidence }
// Defensive: operates on persisted JSONL structured fields and numeric stylometry
// features only — never raw text (there is none on disk to read).

import { coarseFamilyFromFeatures } from '../../stylometry/features.mjs';

// ---- stylometry helper: latest event carrying styl features -----------------
function latestStyl(events) {
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i]?.styl && events[i].styl.words >= 24) return events[i].styl;
  }
  return null;
}

export function extract_model_family_signature(events) {
  // Preferred path: coarse-family heuristic over persisted numeric features
  // (privacy-preserving stylometry computed at capture time).
  const styl = latestStyl(events);
  if (styl) {
    const fam = coarseFamilyFromFeatures(styl);
    return {
      dim: 1,
      value: fam.family,
      confidence: fam.confidence,
      evidence: { source: 'stylometry_features', reasons: fam.reasons, styl_words: styl.words, features: { avg_sentence_len: styl.avg_sentence_len, bullets: styl.markdown.bullets, kv_pairs: styl.markdown.kv_pairs, json_blocks: styl.markdown.json_blocks, code_fences: styl.markdown.code_fences, ttr: styl.lexical_diversity } },
    };
  }
  // Legacy fallback for sessions without styl (seed/demo data): context length heuristic
  const contexts = events.filter((e) => (e.context_chars ?? 0) > 0);
  const avgCtx = contexts.length ? contexts.reduce((s, e) => s + e.context_chars, 0) / contexts.length : 0;
  let value = 'unknown', confidence = 0.2;
  if (avgCtx > 800) { value = 'claude-like'; confidence = 0.3; }
  else if (avgCtx > 400) { value = 'gpt-like'; confidence = 0.3; }
  return { dim: 1, value, confidence, evidence: { source: 'context_length_fallback', avg_context_chars: avgCtx } };
}

export function extract_token_window_estimate(events) {
  const maxPage = Math.max(0, ...events.map((e) => Number(e.page ?? 0)));
  const estK = maxPage === 0 ? 8 : maxPage <= 4 ? 32 : maxPage <= 8 ? 128 : 1000;
  return { dim: 2, value: estK, unit: 'k_tokens', confidence: maxPage ? 0.6 : 0.2, evidence: { max_page: maxPage } };
}

export function extract_truncation_behavior(events) {
  const hasBailAfterPage = events.some((e) => e.event_type === 'BAIL' && e.page >= 8);
  const value = hasBailAfterPage ? 'hard_cut' : events.length > 6 ? 'none_detected' : 'soft_summary';
  return { dim: 3, value, confidence: 0.45, evidence: { bail_after_page: hasBailAfterPage, total_events: events.length } };
}

export function extract_function_call_format(events) {
  const hasMcp = events.some((e) => e.lane && String(e.lane).startsWith('FINANCE_WH'));
  const hasHr = events.some((e) => e.lane && String(e.lane).startsWith('HR_PORTAL'));
  const value = hasMcp || hasHr ? 'mcp_native' : 'unknown';
  return { dim: 4, value, confidence: hasMcp || hasHr ? 0.95 : 0.2, evidence: { mcp_lanes: Boolean(hasMcp || hasHr) } };
}

export function extract_harness_identity(events) {
  // Stylometry-informed: heavy kv-pairs/JSON with zero markdown suggests a
  // structured harness (codex/custom tooling); heavy markdown suggests an
  // interactive assistant harness (claude-code class).
  const styl = latestStyl(events);
  if (styl && styl.words >= 40) {
    const kv = styl.markdown.kv_pairs, jsonB = styl.markdown.json_blocks, md = styl.markdown.bullets + styl.markdown.headers;
    if (jsonB >= 2 || kv >= 5) return { dim: 5, value: 'custom', confidence: 0.5, evidence: { source: 'stylometry', json_blocks: jsonB, kv_pairs: kv } };
    if (md >= 3) return { dim: 5, value: 'claude_code', confidence: 0.4, evidence: { source: 'stylometry', markdown_markers: md } };
  }
  const tools = events.map((e) => e.tool).filter(Boolean);
  const seq = tools.join(',');
  let value = 'unknown';
  if (seq.includes('db_query,register_persistent_goal')) value = 'custom';
  return { dim: 5, value, confidence: 0.35, evidence: { tool_sequence: seq } };
}

export function extract_permission_posture(events) {
  // Autonomous if multiple distinct tools were used in a short session with no
  // error backoff; human-in-loop shows single tool + slow cadence. Coarse.
  const distinctTools = new Set(events.filter((e) => e.tool).map((e) => e.tool)).size;
  const ts = events.map((e) => new Date(e.ts).getTime()).filter(Number.isFinite);
  const spanMin = ts.length > 1 ? (Math.max(...ts) - Math.min(...ts)) / 60000 : 0;
  const value = distinctTools >= 3 || (distinctTools >= 2 && spanMin < 2) ? 'autonomous' : 'human_in_loop';
  return { dim: 6, value, confidence: distinctTools >= 3 ? 0.6 : 0.4, evidence: { distinct_tools: distinctTools, span_minutes: Math.round(spanMin * 10) / 10 } };
}

export function extract_injection_ladder(events) {
  const maxPriv = Math.max(0, ...events.map((e) => Number(e.privilege_level ?? 0)));
  return { dim: 7, value: maxPriv, confidence: maxPriv ? 0.85 : 0.3, evidence: { max_privilege_level: maxPriv } };
}

export function extract_refusal_profile(events) {
  const hasError = events.some((e) => String(e.event_type).includes('ERROR'));
  const tookBait = events.some((e) => e.took_bait);
  let value = 'low_none_observed';
  if (hasError && !tookBait) value = 'high_refusal_rigid';
  else if (hasError && tookBait) value = 'moderate_selective';
  return { dim: 8, value, confidence: 0.5, evidence: { has_error: hasError, took_bait: tookBait } };
}

export function extract_retry_backoff(events) {
  const timestamps = events.map((e) => new Date(e.ts).getTime()).filter(Number.isFinite);
  if (timestamps.length < 3) return { dim: 9, value: 0, confidence: 0.2, evidence: { insufficient_samples: true } };
  const gaps = [];
  for (let i = 1; i < timestamps.length; i++) gaps.push(timestamps[i] - timestamps[i - 1]);
  const avgGap = gaps.reduce((s, v) => s + v, 0) / gaps.length;
  const variance = gaps.reduce((s, v) => s + (v - avgGap) ** 2, 0) / gaps.length;
  const value = variance < 50000 ? 0.1 : 0.9;
  return { dim: 9, value, confidence: 0.45, evidence: { gaps_ms: gaps.slice(0, 5), variance } };
}

export function extract_parallelism(events) {
  // Sub-50ms inter-arrival clusters between distinct tools = parallel/batched.
  const ts = events.filter((e) => e.tool).map((e) => new Date(e.ts).getTime());
  let bursts = 0;
  for (let i = 1; i < ts.length; i++) if (ts[i] - ts[i - 1] < 50 && ts[i] - ts[i - 1] >= 0) bursts++;
  const value = bursts >= 2 ? 'batch_request' : bursts === 1 ? 'parallel' : 'sequential';
  return { dim: 10, value, confidence: 0.7, evidence: { sub_50ms_pairs: bursts } };
}
