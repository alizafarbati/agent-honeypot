// agent-honeypot Phase 5 — ML Clustering
// Actor clustering from embeddings. Lab: greedy threshold. Enterprise: swap to HDBSCAN via pgvector.
// Defensive: deterministic, no raw text, bounded clusters.
//
// v0.2.1 fix: greedy order-dependent assignment meant identical captures
// could produce different clusters across replays — unacceptable for
// forensic re-analysis. Sessions are now embedded and merged in a
// deterministic order (sorted by session_id), and actor IDs derive from
// cluster content hashes, so re-running analysis over the same data yields
// identical actor identity.

import { embedFingerprint, cosine } from './embeddings.mjs';

function stableActorId(members) {
  // content-derived actor id: same members (any order) -> same id
  const h = [...members].sort().join('|');
  let x = 2166136261 >>> 0; // FNV-1a
  for (let i = 0; i < h.length; i++) { x ^= h.charCodeAt(i); x = Math.imul(x, 16777619) >>> 0; }
  return `actor-${x.toString(16).padStart(8, '0')}`;
}

/**
 * @param {Array<{session_id:string, dims:object}>} sessions — each with fingerprint dims
 * @param {{ threshold?: number }} opts — cosine threshold for same actor (default 0.88)
 * @returns {Array<{ actor_id:string, members:string[], centroid:number[], size:number }>}
 */
export function clusterSessions(sessions, { threshold = 0.88 } = {}) {
  // Deterministic processing order: sort by session_id before embedding.
  const ordered = [...sessions].sort((a, b) =>
    String(a.session_id ?? '').localeCompare(String(b.session_id ?? '')));
  const clusters = [];
  for (const s of ordered) {
    const { vector } = embedFingerprint(s.dims);
    let best = null, bestScore = -1;
    for (const c of clusters) {
      const sc = cosine(vector, c.centroid);
      if (sc > bestScore) { bestScore = sc; best = c; }
    }
    if (best && bestScore >= threshold) {
      best.members.push(s.session_id);
      best.size += 1;
      // running centroid update
      for (let i = 0; i < best.centroid.length; i++) best.centroid[i] = (best.centroid[i] * (best.size - 1) + vector[i]) / best.size;
      // re-normalize
      const n = Math.sqrt(best.centroid.reduce((a, v) => a + v * v, 0)) || 1;
      best.centroid = best.centroid.map(v => v / n);
    } else {
      clusters.push({ actor_id: null, members: [s.session_id], centroid: vector, size: 1 });
    }
  }
  // Assign stable actor ids AFTER membership settles.
  for (const c of clusters) c.actor_id = stableActorId(c.members);
  return clusters;
}
