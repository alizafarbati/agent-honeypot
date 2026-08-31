// agent-honeypot Correlation stub — Zone C
// Cosine similarity over bipartite feature sets for actor clustering.
// Phase 2 will back this with pgvector (analysis/fingerprint schema dims 1-23).

function toVector(map, vocab) {
  return vocab.map((k) => Number(map[k] ?? 0));
}
function cosine(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  const d = Math.sqrt(na) * Math.sqrt(nb);
  return d ? dot / d : 0;
}

export function actorSimilarity(actorAByTool, actorBByTool) {
  const vocab = [...new Set([...Object.keys(actorAByTool ?? {}), ...Object.keys(actorBByTool ?? {})])];
  return cosine(toVector(actorAByTool, vocab), toVector(actorBByTool, vocab));
}

export function clusterKey(sessionEvents) {
  // Stable-ish key: tool histogram + max privilege — cheap, no PII
  const byTool = sessionEvents.reduce((a, e) => ((a[e.tool ?? 'x'] = (a[e.tool ?? 'x'] ?? 0) + 1), a), {});
  return JSON.stringify({ byTool, priv: Math.max(0, ...sessionEvents.map((e) => Number(e.privilege_level ?? 0))) });
}
