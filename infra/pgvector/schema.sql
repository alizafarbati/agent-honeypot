-- agent-honeypot pgvector schema (Phase 2 actor clustering)
-- Postgres 15+ with pgvector 0.7+. Lab tier: correlate.mjs in-memory; Enterprise: this table.
-- Vector = normalized dims 1-19 (or dims 1-10 lab) for cosine similarity.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS agent_honeypot.actors (
  actor_id     TEXT PRIMARY KEY,
  cluster_key  TEXT NOT NULL,
  first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  sessions     INT NOT NULL DEFAULT 1,
  -- 19 dims (1-19) as 19-dim vector; expand to 24 when dims 11-24 live
  embedding    vector(19),
  dims_json    JSONB
);

CREATE INDEX IF NOT EXISTS actors_embedding_idx ON agent_honeypot.actors
USING hnsw (embedding vector_cosine_ops);

-- Upsert pattern (correlate.mjs -> here in Phase 2):
-- INSERT INTO agent_honeypot.actors (actor_id, cluster_key, embedding, dims_json)
-- VALUES ($1,$2,$3,$4)
-- ON CONFLICT (actor_id) DO UPDATE SET last_seen=now(), sessions=actors.sessions+1;
