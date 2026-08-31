// agent-honeypot Phase 3 — Thompson Sampling Bandit (lure rotation)
// Lab tier: Beta-Bernoulli Thompson sampling over lure variants. Persists to evolution/bandit_state.json.
// Production: swap store to Postgres/Redis; algorithm unchanged.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const STATE = resolve(here, 'bandit_state.json');
mkdirSync(dirname(STATE), { recursive: true });

function betaSample(alpha, beta) {
  // Marsaglia method via gamma sampling (simple, sufficient for lab)
  const gamma = (a) => {
    if (a < 1) return gamma(a + 1) * Math.pow(Math.random(), 1 / a);
    const d = a - 1 / 3, c = 1 / Math.sqrt(9 * d);
    while (true) {
      let x, v;
      do { x = randn(); v = 1 + c * x; } while (v <= 0);
      v = v * v * v; const u = Math.random();
      if (u < 1 - 0.0331 * x * x * x * x) return d * v;
      if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
    }
  };
  const ga = gamma(alpha), gb = gamma(beta);
  return ga / (ga + gb);
}
function randn() { let u = 0, v = 0; while (u === 0) u = Math.random(); while (v === 0) v = Math.random(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }

function loadState() {
  if (!existsSync(STATE)) return {};
  try { return JSON.parse(readFileSync(STATE, 'utf8')); } catch { return {}; }
}
function saveState(s) { writeFileSync(STATE, JSON.stringify(s, null, 2)); }

export function recordOutcome(variantId, { success }) {
  const s = loadState();
  const cur = s[variantId] ?? { alpha: 1, beta: 1, pulls: 0, successes: 0 };
  cur.pulls += 1;
  if (success) cur.successes += 1;
  // Beta posterior: alpha = 1 + successes, beta = 1 + failures
  cur.alpha = 1 + cur.successes;
  cur.beta = 1 + (cur.pulls - cur.successes);
  s[variantId] = cur;
  saveState(s);
  return cur;
}

export function selectVariant(variantIds) {
  const s = loadState();
  let best = null, bestScore = -1;
  for (const id of variantIds) {
    const cur = s[id] ?? { alpha: 1, beta: 1 };
    const score = betaSample(cur.alpha, cur.beta);
    if (score > bestScore) { bestScore = score; best = id; }
  }
  return { selected: best, score: bestScore };
}

export function getState() { return loadState(); }
export function resetState() { writeFileSync(STATE, JSON.stringify({}, null, 2)); }
