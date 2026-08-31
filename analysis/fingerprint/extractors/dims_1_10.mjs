// agent-honeypot — Fingerprint Extractors dims 1-10
// Each extractor: (events: CaptureEvent[]) => { value, confidence, evidence }
// Defensive: operates on persisted JSONL digests + structured fields, never raw text.

export function extract_model_family_signature(events) {
  // Heuristic from context formatting + tool-call shape (dim 1+4 correlated)
  // Real model-ID requires hosted-LLM classifier; this heuristic is the lab-tier stub.
  const contexts = events.filter(e => e.context_chars > 0);
  const avgCtx = contexts.length ? contexts.reduce((s, e) => s + e.context_chars, 0) / contexts.length : 0;
  const hasStructured = events.some(e => e.structuredContent);
  let value = 'unknown';
  if (avgCtx > 800) value = 'claude'; else if (avgCtx > 400) value = 'gpt'; else if (hasStructured) value = 'gemini';
  return { dim: 1, value, confidence: value === 'unknown' ? 0.2 : 0.55, evidence: { avg_context_chars: avgCtx, has_structured: hasStructured } };
}

export function extract_token_window_estimate(events) {
  // Max page reached in 12-page pagination trap approximates context ceiling (dim 2)
  const maxPage = Math.max(0, ...events.map(e => Number(e.page ?? 0)));
  const estK = maxPage === 0 ? 8 : maxPage <= 4 ? 32 : maxPage <= 8 ? 128 : 1000;
  return { dim: 2, value: estK, unit: 'k_tokens', confidence: maxPage ? 0.6 : 0.2, evidence: { max_page: maxPage } };
}

export function extract_truncation_behavior(events) {
  const hasBailAfterPage = events.some(e => e.event_type === 'BAIL' && e.page >= 8);
  const value = hasBailAfterPage ? 'hard_cut' : events.length > 6 ? 'none_detected' : 'soft_summary';
  return { dim: 3, value, confidence: 0.45, evidence: { bail_after_page: hasBailAfterPage, total_events: events.length } };
}

export function extract_function_call_format(events) {
  // From mcp_server: all calls are mcp_native in lab; future HTTP tier distinguishes openai_native_json vs claude_tool_use
  const hasMcp = events.some(e => e.lane && String(e.lane).startsWith('FINANCE_WH'));
  return { dim: 4, value: hasMcp ? 'mcp_native' : 'unknown', confidence: hasMcp ? 0.95 : 0.2, evidence: { mcp_lanes: hasMcp } };
}

export function extract_harness_identity(events) {
  // Harness residue: look for tool-name sequences that fingerprint known harnesses
  // Lab stub: sequence-based heuristic; prod replaces with classifier trained on harness traces
  const tools = events.map(e => e.tool).filter(Boolean);
  const seq = tools.join(',');
  let value = 'unknown';
  if (seq.includes('db_query,register_persistent_goal')) value = 'custom';
  else if (tools.length === 1 && tools[0] === 'db_query') value = 'unknown';
  return { dim: 5, value, confidence: 0.4, evidence: { tool_sequence: seq } };
}

export function extract_permission_posture(events) {
  // Autonomous if multiple distinct tools without human confirmation gaps; lab has no human gaps
  const distinctTools = new Set(events.map(e => e.tool).filter(Boolean)).size;
  const value = distinctTools >= 3 ? 'autonomous' : distinctTools >= 1 ? 'autonomous' : 'human_in_loop';
  return { dim: 6, value, confidence: 0.5, evidence: { distinct_tools: distinctTools } };
}

export function extract_injection_ladder(events) {
  const maxPriv = Math.max(0, ...events.map(e => Number(e.privilege_level ?? 0)));
  return { dim: 7, value: maxPriv, confidence: maxPriv ? 0.85 : 0.3, evidence: { max_privilege_level: maxPriv } };
}

export function extract_refusal_profile(events) {
  const hasError = events.some(e => e.event_type === 'ERROR_429');
  const tookBait = events.some(e => e.took_bait);
  let value = 'low_none_observed';
  if (hasError && !tookBait) value = 'high_refusal_rigid';
  else if (hasError && tookBait) value = 'moderate_selective';
  return { dim: 8, value, confidence: 0.5, evidence: { has_error: hasError, took_bait: tookBait } };
}

export function extract_retry_backoff(events) {
  const timestamps = events.map(e => new Date(e.ts).getTime()).filter(n => Number.isFinite(n));
  if (timestamps.length < 3) return { dim: 9, value: 0, confidence: 0.2, evidence: { insufficient_samples: true } };
  const gaps = [];
  for (let i = 1; i < timestamps.length; i++) gaps.push(timestamps[i] - timestamps[i - 1]);
  const avgGap = gaps.reduce((s, v) => s + v, 0) / gaps.length;
  const variance = gaps.reduce((s, v) => s + (v - avgGap) ** 2, 0) / gaps.length;
  // Low variance = linear/constant retry; high = exponential jitter
  const value = variance < 50000 ? 0.1 : 0.9;
  return { dim: 9, value, confidence: 0.45, evidence: { gaps_ms: gaps.slice(0, 5), variance } };
}

export function extract_parallelism(events) {
  // Lab tier: stdio is sequential; HTTP tier will show parallel batches
  const hasBurst = false; // would detect sub-50ms inter-arrival clusters
  return { dim: 10, value: hasBurst ? 'parallel' : 'sequential', confidence: 0.7, evidence: { burst_detected: hasBurst } };
}
