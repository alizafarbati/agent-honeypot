# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows SemVer.

## [0.2.0] — 2026-09-01

### Added
- **hr-portal**: second MCP honeypot family (employee directory, payslip,
  leave, IT provisioning) proving the architecture generalizes beyond
  finance-warehouse. `agent-honeypot serve hr-portal`.
- **SSH trap**: fake filesystem with command interpreter (ls, cat, cd, pwd,
  whoami, ps, netstat, history) on `ssh_exec`. Reading the fake
  `credentials.txt` trips canary detection (dimension 15 goes live).
- **Canary webhook receiver**: `POST /webhook/:canaryId` on the dashboard
  records CREDENTIAL_USE events; simulated AWS/GitHub/DB/Slack patterns
  detected at capture time (inspect-before-digest).
- **Stylometry**: numeric-only text features computed in memory before
  digesting (sentence stats, markdown markers, lexical diversity, stopword
  ratio) — privacy-preserving model-family evidence for dimension 1.
- **Lure variant rotation**: 3 phrasing variants for finance-warehouse, 2 for
  hr-portal, selected per session via the Thompson-sampling bandit
  (ContextLeak-informed; co-evolutionary per REPLICANT).
- **Analyze pipeline** (`agent-honeypot analyze`): one-shot fingerprints →
  clusters → anomaly scan → STIX 2.1 for high/critical sessions.
- **Watch mode** (`agent-honeypot watch`): evolution engine over escape
  sessions; shadow-only promotion (human gate unchanged).
- **Honeydoc generator** (`agent-honeypot honeydocs [n]`): synthetic documents
  with L1–L3 payload ladders at LongPIBench-calibrated positions.
- **Visual dashboard**: single-file dark-theme UI with session cards, tool
  activity bars, per-session tier chips, canary badges, 5s auto-refresh.
- Docker: multi-stage Dockerfile (node:20-slim), docker-compose with volume,
  healthcheck, optional NATS sidecar.
- CLI `serve [name]` picks between deployed families.

### Changed
- tsconfig now compiles `evolution/` and `surface/**/*.mjs` into `dist/` so the
  built finance server can import the bandit and shell modules.
- Fingerprint dimension 1 upgraded to stylometry-informed (legacy context-length
  heuristic as fallback); dimension 15 wired to live canary events; dimension 17
  recognizes hr-portal tools.
- Test suite: 47 → 57 tests across 7 suites (new: hr-portal E2E, pipeline).

## [0.1.0] — 2026-08-31

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
