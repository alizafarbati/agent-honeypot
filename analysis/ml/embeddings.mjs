// agent-honeypot Phase 5 — ML Embeddings ()
// Fingerprint (24 dims) → normalized embedding for cosine similarity + pgvector.
// Defensive: numeric dims scaled, categoricals hashed to stable buckets, no PII.

// v0.2.1 fix: vocabularies now match the values the extractors actually emit
// (dims_1_10/11_24). The previous model_family vocab ('gpt','claude',...)
// never matched the emitted 'claude-like'/'gpt-like'/'unknown', silently
// zeroing that one-hot block and dropping the model-family signal from
// clustering entirely.
const CAT_ORDER = {
  model_family_signature: ['gpt-like', 'claude-like', 'gemini', 'deepseek', 'qwen', 'llama', 'mistral', 'unknown'],
  function_call_format: ['openai_native_json', 'claude_tool_use', 'mcp_native', 'retext', 'raw_text'],
  harness_identity_residue: ['claude_code', 'codex', 'opencode', 'hermes', 'openclaw', 'custom', 'unknown'],
  permission_posture: ['autonomous', 'human_in_loop'],
  refusal_profile_class: ['high_refusal_rigid', 'moderate_selective', 'low_none_observed', 'adversarial_inverted'],
  parallel_tool_call_behavior: ['sequential', 'parallel', 'batch_request'],
  truncation_behavior: ['hard_cut', 'none_detected', 'soft_summary'],
  persistence_class: ['both', 'persistent_goal_only', 'scheduled_task_only'],
};

function oneHot(val, vocab) {
  const v = Array(vocab.length).fill(0);
  const i = vocab.indexOf(val);
  if (i >= 0) v[i] = 1;
  return v;
}
function scale(n, min, max) {
  if (n == null || !Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, (n - min) / (max - min || 1)));
}

/**
 * @param {object} dims — fingerprintSession().dims (1..24)
 * @returns {{ vector: number[], dim: number, meta: object }}
 */
export function embedFingerprint(dims) {
  const vec = [];
  // Numeric scaled
  vec.push(scale(dims[2]?.value, 8, 1000)); // token window
  vec.push(scale(dims[7]?.value, 0, 3)); // ladder
  vec.push(scale(dims[11]?.value, 0, 100) / 100); // loop discipline already 0-100
  vec.push(scale(dims[12]?.value, 0, 5000)); // token burn
  vec.push(scale(dims[18]?.value, 0, 3600)); // duration
  vec.push(scale(dims[9]?.value, 0, 1)); // retry shape
  vec.push(scale(dims[19]?.value, 0, 100) / 100);
  vec.push(scale(dims[21]?.value, 0, 100) / 100);
  // Categorical one-hot (compact)
  vec.push(...oneHot(dims[1]?.value, CAT_ORDER.model_family_signature));
  vec.push(...oneHot(dims[4]?.value, CAT_ORDER.function_call_format));
  vec.push(...oneHot(dims[5]?.value, CAT_ORDER.harness_identity_residue));
  vec.push(...oneHot(dims[6]?.value, CAT_ORDER.permission_posture));
  vec.push(...oneHot(dims[8]?.value, CAT_ORDER.refusal_profile_class));
  vec.push(...oneHot(dims[10]?.value, CAT_ORDER.parallel_tool_call_behavior));
  vec.push(...oneHot(dims[3]?.value, CAT_ORDER.truncation_behavior));
  vec.push(...oneHot(dims[20]?.value, CAT_ORDER.persistence_class));
  // Binary flags
  vec.push(dims[15]?.value === 'used' ? 1 : 0);
  // Persistence as graded signal (was binary; 'both' is strictly worse than
  // a single persistence channel and should not embed identically).
  vec.push(dims[20]?.value === 'both' ? 1 : dims[20]?.value && dims[20]?.value !== 'none' ? 0.5 : 0);
  // L2 normalize for cosine
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0)) || 1;
  const normed = vec.map(v => v / norm);
  return { vector: normed, dim: normed.length, meta: { source_dims: Object.keys(dims).length } };
}

export function cosine(a, b) {
  let dot = 0; for (let i = 0; i < Math.min(a.length, b.length); i++) dot += a[i] * b[i];
  return dot; // already normalized
}
