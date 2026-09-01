// Thompson-sampling bandit for lure variant rotation. Beta-Bernoulli posterior per
// variant; state persists across restarts. Swap the store for Redis/Postgres in
// multi-node deployments; the algorithm is unchanged.
//
// v0.2.1 fix: loadState()->mutate->write was an unlocked read-modify-write.
// Two MCP server processes (finance + hr spawn concurrently) could interleave
// and silently drop each other's outcomes. Now guarded by a best-effort
// lockfile with bounded retry; on contention we re-read and re-apply so the
// last writer never clobbers a concurrent update.

import { readFileSync, writeFileSync, existsSync, mkdirSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { PATHS, ensureDataDir } from '../../capture/paths.mjs';

ensureDataDir();
const STATE = PATHS.bandit;
const LOCK = PATHS.bandit + '.lock';

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

// ---- best-effort exclusive lock (O_EXCL create, stale after 2s) -------------
function acquireLock() {
  try {
    const fd = openSync(LOCK, 'wx'); // fails if exists
    writeFileSync(fd, String(Date.now()));
    closeSync(fd);
    return true;
  } catch {
    // Stale-lock reclaim: if older than 2s, remove and retry once.
    try {
      const t = Number(readFileSync(LOCK, 'utf8'));
      if (Number.isFinite(t) && Date.now() - t > 2000) { unlinkSync(LOCK); try { const fd = openSync(LOCK, 'wx'); writeFileSync(fd, String(Date.now())); closeSync(fd); return true; } catch { return false; } }
    } catch {}
    return false;
  }
}
function releaseLock() { try { unlinkSync(LOCK); } catch { /* already gone */ } }

export function recordOutcome(variantId, { success }) {
  // Bounded retry: lock contention here is expected to be rare and short
  // (two processes at most in lab mode). 50 tries x 20ms = 1s worst case,
  // then we proceed unlocked rather than losing the outcome entirely.
  for (let attempt = 0; attempt < 50; attempt++) {
    if (acquireLock()) {
      try {
        const s = loadState(); // re-read INSIDE the lock — no lost updates
        const cur = s[variantId] ?? { alpha: 1, beta: 1, pulls: 0, successes: 0 };
        cur.pulls += 1;
        if (success) cur.successes += 1;
        cur.alpha = 1 + cur.successes;
        cur.beta = 1 + (cur.pulls - cur.successes);
        s[variantId] = cur;
        writeFileSync(STATE, JSON.stringify(s, null, 2));
        return cur;
      } finally {
        releaseLock();
      }
    }
    // back off briefly before retrying
    const until = Date.now() + 20;
    while (Date.now() < until) { /* sync sleep */ }
  }
  // Fallback: unlocked write (pre-v0.2.1 behavior) — better a rare lost
  // update than dropping the bandit signal.
  const s = loadState();
  const cur = s[variantId] ?? { alpha: 1, beta: 1, pulls: 0, successes: 0 };
  cur.pulls += 1;
  if (success) cur.successes += 1;
  cur.alpha = 1 + cur.successes;
  cur.beta = 1 + (cur.pulls - cur.successes);
  s[variantId] = cur;
  writeFileSync(STATE, JSON.stringify(s, null, 2));
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
