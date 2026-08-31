// agent-honeypot Phase 5 — Anomaly Detector ()
// Isolation heuristic on numeric dims: z-score over sliding window.
// Flags sessions where token_burn, retry variance, or duration are outliers.

export function zScore(value, mean, std) {
  if (!Number.isFinite(std) || std === 0) return 0;
  return (value - mean) / std;
}

function stats(arr) {
  const n = arr.length; if (!n) return { mean: 0, std: 0 };
  const mean = arr.reduce((s, v) => s + v, 0) / n;
  const std = Math.sqrt(arr.reduce((s, v) => s + (v - mean) ** 2, 0) / n);
  return { mean, std };
}

/**
 * @param {Array<{dims:object}>} history — prior sessions
 * @param {{dims:object}} current
 * @returns {{ is_anomaly:boolean, scores: object, reasons: string[] }}
 */
export function detectAnomaly(history, current) {
  const dims = ['token_burn_ceiling_estimate','retry_backoff_shape','session_duration_seconds'];
  const keys = { token_burn_ceiling_estimate: 12, retry_backoff_shape: 9, session_duration_seconds: 18 };
  const reasons = []; const scores = {};
  let is_anomaly = false;
  for (const name of dims) {
    const id = keys[name];
    const histVals = history.map(h => Number(h.dims?.[id]?.value)).filter(Number.isFinite);
    const cur = Number(current.dims?.[id]?.value);
    if (!Number.isFinite(cur) || !histVals.length) continue;
    const { mean, std } = stats(histVals);
    const z = zScore(cur, mean, std);
    scores[name] = z;
    if (Math.abs(z) > 3) { is_anomaly = true; reasons.push(`${name} z=${z.toFixed(2)} (mean ${mean.toFixed(1)}, std ${std.toFixed(1)})`); }
  }
  // Heuristic: persistence+both + canary propagation is rare → anomaly
  if (current.dims?.[20]?.value === 'both' && Number(current.dims?.[21]?.value) > 50) {
    is_anomaly = true; reasons.push('rare persistence+both with high canary propagation');
  }
  return { is_anomaly, scores, reasons };
}
