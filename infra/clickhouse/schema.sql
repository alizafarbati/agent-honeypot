-- agent-honeypot ClickHouse schema (Phase 2 OLAP — events + fingerprint rollups)
-- Lab tier: file JSONL; Enterprise tier: this schema on ClickHouse 24+.
-- Query pattern: time-series by lane/tool/privilege, actor clustering via fingerprint dims.

CREATE DATABASE IF NOT EXISTS agent_honeypot;

CREATE TABLE IF NOT EXISTS agent_honeypot.events
(
  ts               DateTime64(3, 'UTC'),
  session_id       String,
  lane             LowCardinality(String),
  event_type       LowCardinality(String),
  tool             LowCardinality(String),
  privilege_level  UInt8,
  took_bait        UInt8,
  context_chars    UInt32,
  args_digest      FixedString(16),
  page             UInt8,
  lure_family      LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (session_id, ts)
TTL ts + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS agent_honeypot.fingerprints
(
  session_id       String,
  computed_at      DateTime64(3, 'UTC'),
  dims_json        String,  -- JSON of dims 1-24 (fingerprintSession output)
  lab_hint         UInt8,
  cluster_key      String
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY session_id;

-- Example rollups (materialized views can be added in Phase 2+):
-- SELECT lane, count() FROM agent_honeypot.events GROUP BY lane;
-- SELECT tool, avg(context_chars) FROM agent_honeypot.events WHERE took_bait=1 GROUP BY tool;
