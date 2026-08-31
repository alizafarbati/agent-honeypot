// agent-honeypot Phase 3 — RL Reward (ContextLeak inverted, defender-operated)
// Implements bait_config/contextleak_reward.yaml as code. Pure function, testable.
// Reward = 0.4*bait_selection + 0.4*context_completeness + 0.2*transfer - penalties

/**
 * @param {{ bait_selection_rate: number, context_completeness: number, transfer_score: number, detection_signal?: number, benign_fp_rate?: number }} m
 * @returns {{ reward: number, breakdown: object }}
 */
export function computeReward(m) {
  const bait = clamp01(m.bait_selection_rate ?? 0);
  const ctx = clamp01(m.context_completeness ?? 0);
  const tr = clamp01(m.transfer_score ?? 0);
  const det = clamp01(m.detection_signal ?? 0);
  const fp = clamp01(m.benign_fp_rate ?? 0);

  const base = 0.4 * bait + 0.4 * ctx + 0.2 * tr;
  const penalties = 0.5 * det + (fp >= 0.02 ? 1.0 : 0); // fp >=2% is hard fail per reward.yaml
  const reward = Math.max(-1, Math.min(1, base - penalties));
  return { reward, breakdown: { base, bait, ctx, transfer: tr, detection_penalty: 0.5 * det, fp_penalty: fp >= 0.02 ? 1.0 : 0, benign_fp_rate: fp } };
}

function clamp01(x) { return Math.max(0, Math.min(1, Number(x) || 0)); }

/** Helper: score a session's context completeness from events (lab heuristic) */
export function scoreContextCompleteness(events) {
  const maxChars = Math.max(0, ...events.map(e => Number(e.context_chars ?? 0)));
  const hasPriv = events.some(e => Number(e.privilege_level ?? 0) >= 2);
  const charsNorm = Math.min(1, maxChars / 300);
  return Math.min(1, 0.7 * charsNorm + 0.3 * (hasPriv ? 1 : 0));
}
