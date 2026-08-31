// agent-honeypot Phase 5 — ML Clustering ()
// Actor clustering from embeddings. Lab: greedy threshold. Enterprise: swap to HDBSCAN via pgvector.
// Defensive: deterministic, no raw text, bounded clusters.

import { embedFingerprint, cosine } from './embeddings.mjs';

/**
 * @param {Array<{session_id:string, dims:object}>} sessions — each with fingerprint dims
 * @param {{ threshold?: number }} opts — cosine threshold for same actor (default 0.88)
 * @returns {Array<{ actor_id:string, members:string[], centroid:number[], size:number }>}
 */
export function clusterSessions(sessions, { threshold = 0.88 } = {}) {
  const clusters = [];
  for (const s of sessions) {
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
      clusters.push({ actor_id: `actor-${clusters.length + 1}-${s.session_id.slice(0, 6)}`, members: [s.session_id], centroid: vector, size: 1 });
    }
  }
  return clusters;
}
