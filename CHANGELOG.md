# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [0.1.0] â€” 2026-08-31

Initial public prototype.

### Added
- MCP honeypot server (`finance-warehouse`) with five synthetic tools: `db_query`,
  `email_send`, `ssh_exec`, `register_persistent_goal`, `schedule_task`, with
  realistic latency jitter, ~3% error injection, and 12-page pagination trap.
- Append-only JSONL capture plane with digest-only persistence (SHA-256 of
  argument text; raw text never stored) and a per-session state machine.
- 24-dimension session fingerprint: model-family heuristics, context-window
  ceiling, harness residue, permission posture, injection-susceptibility
  ladder, loop discipline, token-burn ceiling, credential-use and persistence
  evidence, plus a coverage-weighted composite threat score and alert tiers.
- Actor clustering via cosine similarity over fingerprint embeddings.
- Counterexample-driven lure evolution: escape sessions produce structured
  antigen profiles (no raw text), candidate variants, a validation gauntlet
  (self-monitor, benign-corpus FP gate, anti-fingerprint), shadow deployment,
  and an explicit human promotion gate. Thompson-sampling bandit for rotation.
- STIX 2.1 bundle emitter; SIEM webhook dispatcher; MISP push (all with
  no-network lab fallbacks).
- Multi-tenant API, Prometheus-style metrics, OTLP-ready tracing stub,
  consistent-hash sharding helper.
- Hash-chain audit ledger with verification.
- Deployment assets: Terraform (deny-all NetworkPolicy, restricted PSS, Vault
  policies), Helm chart, Cloudflare Worker + R2 adapter (digest-only at edge),
  ClickHouse and pgvector schemas.
- CLI (`agent-honeypot serve|dash|seed|report|test|build|doctor`).
- Test suite: 47 tests including a machine-checked security suite and a real stdio end-to-end against the MCP server
  using the official SDK client.

### Security
- All honeypot responses are synthetic; no real host, credential, or dataset
  is contacted. See SECURITY.md.
