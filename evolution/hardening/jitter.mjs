// agent-honeypot Phase 6 — Jitter Engine ()
// Lognormal latency distribution shaped per lane. Defeats timing fingerprinting.
// Config: per-lane mu/sigma; budget enforcement via metrics.

export function lognormalSample(mu, sigma) {
  // Box-Muller → lognormal
  let u = 0, v = 0; while (u === 0) u = Math.random(); while (v === 0) v = Math.random();
  const n = Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  return Math.exp(mu + sigma * n);
}

const LANES = {
  FINANCE_WH_DB: { mu: 6.2, sigma: 0.35, min: 300, max: 1400 }, // ~500ms median
  FINANCE_WH_SSH: { mu: 6.9, sigma: 0.30, min: 600, max: 2200 },
  default: { mu: 6.0, sigma: 0.4, min: 250, max: 1200 },
};

export function jitterForLane(lane) {
  const cfg = LANES[lane] ?? LANES.default;
  let v = lognormalSample(cfg.mu, cfg.sigma);
  v = Math.max(cfg.min, Math.min(cfg.max, v));
  return Math.round(v);
}

export async function sleepJitter(lane) {
  const ms = jitterForLane(lane);
  await new Promise(r => setTimeout(r, ms));
  return ms;
}
