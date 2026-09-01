// agent-honeypot Phase 5 — Anomaly Detector
// z-score over a sliding window, with a minimum-evidence gate.
//
// v0.2.1 fixes:
//  - Population std on tiny windows (n=1-2 => std 0 => z 0) let real
//    anomalies through. Now requires n >= MIN_HISTORY (5) before scoring.
//  - Sample std (n-1 denominator) for small-sample unbiasedness.
//  - Dim keys corrected: token_burn (12) is char volume, retry shape (9)
//    is the 0.1/0.9 classifier, duration (18) is seconds — each scored on
//    a scale appropriate to what the extractor actually emits.

export function zScore(value, mean, std) {
  if (!Number.isFinite(std) || std === 0) return 0;
  return (value - mean) / std;
}

const MIN_HISTORY = 5; // below this, evidence is too thin to call anything anomalous

function stats(arr) {
  const n = arr.length; if (!n) return { mean: 0, std: 0, n: 0 };
  const mean = arr.reduce((s, v) => s + v, 0) / n;
  if (n < 2) return { mean, std: 0, n };
  const std = Math.sqrt(arr.reduce((s, v) => s + (v - mean) ** 2, 0) / (n - 1)); // sample std
  return { mean, std, n };
}

/**
 * @param {Array<{dims:object}>} history — prior sessions
 * @param {{dims:object}} current
 * @returns {{ is_anomaly:boolean, scores: object, reasons: string[] }}
 */
export function detectAnomaly(history, current) {
  const reasons = []; const scores = {}; let is_anomaly = false;

  const DIMS = [
    { key: 'token_burn_ceiling_estimate', dim: 12 },
    { key: 'retry_backoff_shape', dim: 9 },
    { key: 'session_duration_seconds', dim: 18 },
  ];
  for (const { key, dim } of DIMS) {
    const histVals = history.map(h => Number(h.dims?.[dim]?.value)).filter(Number.isFinite);
    const cur = Number(current.dims?.[dim]?.value);
    if (!Number.isFinite(cur) || histVals.length < MIN_HISTORY) continue;
    const { mean, std, n } = stats(histVals);
    if (n < MIN_HISTORY || std === 0) continue; // degenerate window: no verdict
    const z = zScore(cur, mean, std);
    scores[key] = z;
    if (Math.abs(z) > 3) { is_anomaly = true; reasons.push(`${key} z=${z.toFixed(2)} (mean ${mean.toFixed(1)}, std ${std.toFixed(1)}, n=${n})`); }
  }
  // Heuristic: persistence+both + canary propagation is rare → anomaly
  if (current.dims?.[20]?.value === 'both' && Number(current.dims?.[21]?.value) > 50) {
    is_anomaly = true; reasons.push('rare persistence+both with high canary propagation');
  }
  return { is_anomaly, scores, reasons };
}
