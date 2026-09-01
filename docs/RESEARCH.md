# Research & Ideation — Agent Honeypot Hardening

> **Scope**: adversarial literature → cross-test findings → 10× research → improvements → roadmap.
> Covers the v0.2.1 and v0.2.2 hardening cycles (14 + 10 findings).

## 1. Adversarial Literature Grounding

### 1.1 LLM Agent Honeypots
- **LongPIBench** (long-context position bias 60–80%): honeydocs embed L1–L3 ladders at empirically weak positions; verified in `scripts/gen-honeydocs.mjs`.
- **CAITLYN System-II** (counterexample → structured antigen, no raw text in LLM): evolution engine (`evolution/engine/antigen.mjs`) follows this pattern strictly — verified in `security.test.mjs`.
- **ContextLeak / When Context Gets Root**: inverted bait design — context field disclosure (L1), persistence tools (L2/L3). Grounded in `surface/mcpservers/*` tool descriptions.
- **ATLAS / MITRE**: technique mapping in `analysis/ttmapper/stix_emitter.mjs` now emits real IDs (AML.T0040 reconnaissance, AML.T0048 dataset collection, AML.T0049 persistence, AML.T0051 exfiltration).

### 1.2 Prompt Injection & Tool Misuse Taxonomies
- **OWASP LLM Top 10 (2023–2025)**: LLM01 Prompt Injection, LLM07 Insecure Plugin Design — the finance-warehouse `db_query` context field is a classic plugin-design bait.
- **Indirect Prompt Injection** (Greshake et al.): honeydocs are RAG-poisoning vectors; canary markers (`canary-*`) enable document-to-tool-call provenance.
- **Tool-output injection**: `ssh_exec` fake filesystem is a controlled tool-output channel; `grep`/`env` gaps identified in v0.2.1 audit (N8) remain open for v0.3.0.

### 1.3 Stylometry & Model Fingerprinting
- **Burrows's Delta** (authorship attribution): stylometry features (`analysis/stylometry/features.mjs`) use stopword ratio, TTR, sentence length variance.
- **Model-family signals**: markdown markers, JSON blocks, code fences — verified in `dims_1_10` and `embeddings.mjs` (F11 vocab fix).

### 1.4 Anomaly Detection
- **Population vs sample std**: v0.2.0 used population std on n<3 windows → false negatives. v0.2.1: min-history gate (n≥5) + sample std (n-1) — standard robust-statistics practice.
- **MAD/median** (deferred to v0.3.0): more robust for skewed honeypot data (long-tailed token burn).

## 2. Cross-Test Findings (v0.2.1 + v0.2.2)

### 2.1 v0.2.1 — 14 Findings (F1–F14)
| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| F1 | Critical | Data fragmentation: `dist/` servers wrote to `dist/data/`, invisible to analysis (82 events lost) | `capture/paths.mjs` walks to `package.json` |
| F2 | Critical | `Math.random()` session IDs guessable (~31 bits) | `crypto.randomBytes` (128-bit) |
| F3 | Critical | Webhook unauthenticated, unbounded, no rate limit | HMAC-SHA256 + 64KB cap + 60/min |
| F4 | High | `logCanaryUse` dead spread + unreachable `SCORED` stage | Signal-grounded stage progression |
| F5 | High | 64-bit truncated digests (birthday-unsafe) | Full SHA-256 (64-hex) |
| F6 | High | Anomaly detector n=1 std=0 → silent false negatives | n≥5 gate + sample std |
| F7 | High | Bandit RMW race (concurrent servers clobber state) | Lockfile + retry |
| F8 | Medium | Pagination `dec()` returns 1 on garbage → ladder reset | Strict regex + `ERROR_BAD_TOKEN` |
| F9 | Medium | Zod schemas allow empty strings (pollution) | `min(1)` + max caps on all 9 tools |
| F10 | Medium | STIX pattern invalid + placeholder ATLAS IDs | Valid `x-honeypot:` grammar + real AML IDs |
| F11 | Medium | Embeddings vocab mismatch (model-family zeroed) | Vocab aligned to extractor outputs |
| F12 | Medium | Anomaly dims mis-keyed | Corrected mapping |
| F13 | Low | `analyzeAll()` double compute | Single pass |
| F14 | Low | Non-deterministic clustering | Sorted + content-derived stable IDs |

### 2.2 v0.2.2 — 10 New Findings (N1–N10)
| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| N1 | Critical | Honeydoc canaries (`canary-*`) matched no pattern — entire doc tracking dead | `cw-doc-005` pattern + crypto canaries |
| N2 | High | Seed events lacked `event_type`/`lure_family` (coverage skew) | Added to `seed.mjs` |
| N3 | Critical | `STATE_MACHINE` events `took_bait:true` (bookkeeping) → 61% escapes invisible | `took_bait:null` for lifecycle events |
| N4 | High | `watch.mjs` re-promotes same escapes → +216 duplicates/run | `watch_processed.json` ledger (antigen SHA dedupe) |
| N5 | High | `ssh_cat` canary source mislabeled | `source: 'ssh_cat'` |
| N7 | Critical | Edge worker `slice(0,8)` raw prefix → violates digest-only | Full SHA-256 via `crypto.subtle` |
| N8 | Low | STIX IDs 36-hex, not UUID | UUID-shaped from hash |
| N10 | Medium | Metrics histograms missing `_bucket`/`le` | Proper `le` buckets + `+Inf` |
| N15 | High | Webhook trusts attacker `session_id` → grouping pollution | Always synthetic session ID |
| N16-19 | Medium | 4 orphan modules never wired (jitter, metrics, schema mutator, bus) | Wired jitter + metrics + bandit fix |

### 2.3 Remaining Gaps (Deferred)
- **Per-session canary entropy**: single static `AKIA-SIMULATED-WAREHOUSE-01-2026` — cross-session reuse not linkable (dim 21). Plan: generate per-process canaries.
- **MAD/median anomaly**: z-score breaks on skewed data; add MAD alongside.
- **Contextual bandit**: variant × time-of-day × entry-point conditioning.
- **Event ceiling**: per-session 10k event cap (DoS guard).
- **Schema mutator wiring**: needs tenant identity in stdio servers (AGENT_HONEYPOT_TENANT env).
- **Bus/NATS**: capture plane not using bus abstraction.

## 3. 10× Research — Deeper Adversarial Vectors

### 3.1 Multi-Session Calibration (Adaptive Thresholds)
Static thresholds (40/30/50) are bisectable. v0.2.1: per-session ±15% jitter (drawn once per process). Attacker averaging across N sessions converges on noise (variance ∝ spread²/N). Future: per-call jitter or Bayesian adaptive threshold.

### 3.2 Homoglyph & Encoding Evasion
Fullwidth `ＡＫＩＡ`, zero-width joiners, base64-wrapped canaries. v0.2.1: NFKD confusable folding before regex. Future: handle base64/hex encoding, leetspeak, chunked exfil.

### 3.3 Timing Side Channels
Uniform jitter → fingerprintable. v0.2.1: lognormal per-lane (`jitter.mjs` wired). Future: add decoy variance per tool family + cover traffic.

### 3.4 Schema Fingerprinting
MCP tool schemas are static honeypot tells. `schema_mutator.mjs` exists but unwired. Future: per-tenant field renaming + order shuffling via `AGENT_HONEYPOT_TENANT`.

### 3.5 RAG / Document Poisoning
Honeydocs with `canary-*` markers enable provenance; v0.2.1 fixes detection. Future: embed canaries in varied encodings (QR, image, PDF metadata).

### 3.6 STIX/TAXII Interop
v0.2.1: valid STIX 2.1 bundles with real ATLAS IDs, UUIDs. Future: TAXII 2.1 server, MISP galaxy tagging.

### 3.7 Privacy & Retention
Digest-only + synthetic-only guarantees verified in `security.test.mjs`. v0.2.1: edge digest-only, unified data dir. Future: retention policy, GDPR for honeypot logs, differential privacy for aggregate stats.

### 3.8 Forensic Determinism
v0.2.1: deterministic clustering (sorted input, content-derived actor IDs), idempotent `watch` (antigen SHA ledger). Future: ledger hash-chain verification on every analyze run.

## 4. Ideation — 10× Improvement Backlog

1. **Per-session canary vault**: generate `AKIA-SIMULATED-{SESSION}-{RND}` per process; record `canary_value` in capture for cross-session reuse correlation (dim 21).
2. **Contextual bandit**: Thompson → contextual (features: time-of-day, entry tool, prior bait rate).
3. **MAD anomaly ensemble**: z-score + MAD + isolation score, voted.
4. **Event ceiling + truncation event**: 10k events/session, then `TRUNCATED` marker.
5. **Schema mutation live**: wire `mutateSchema` in both MCP servers behind `AGENT_HONEYPOT_TENANT`.
6. **Honeydoc polyglot**: markdown + PDF + JSON variants with varied L1–L3 encodings.
7. **Tool-output injection harness**: test `ssh_exec` with `grep`/`env`/`find` canary exfil paths (N8 remediation).
8. **TAXII feed**: expose STIX bundles via TAXII 2.1 `/taxii2/`.
9. **Differential-privacy aggregates**: add Laplace noise to public `/summary` counts.
10. **Red-team agent**: LLM-driven adversary that tries to evade thresholds/canaries; measure detection recall.

## 5. Planning — Roadmap

### v0.2.2 (This Release)
- Fix N1–N10, update tests (HR/persistence/pagination args, threshold bands), 10× research doc, README/docs.

### v0.3.0 — Adversarial Robustness
- Per-session canaries (1), MAD ensemble (3), event ceiling (4), schema mutation live (5), `grep`/`env` SSH trap expansion (7).

### v0.4.0 — Enterprise Interop
- Contextual bandit (2), TAXII feed (8), tenant API auth (bearer), bus/NATS wiring.

### v1.0.0 — Production Honeypot
- All gaps closed, full red-team validation, differential privacy (9), retention/GDPR, Helm/prod Terraform.

## 6. Verification Matrix (v0.2.2)

| Suite | Count | Status |
|-------|-------|--------|
| Unit (`npm test`) | 57 | ✅ 57/57 |
| Mega (both servers, all tools, canaries, chains, edge) | 56 | ✅ 56/56 |
| Deep (attack patterns, disclosure, injection) | 37 | ✅ 37/37 |
| Direct MCP (raw protocol) | 6 | ✅ 6/6 |
| Agent simulation (ASSASSIN/OpenClaw/benign) | 13 | ✅ 13/13 |
| Hardening verify (crypto IDs, token tamper, digest, thresholds) | 9 | ✅ 9/9 |
| **Total** | **178** | **✅ 178/178** |

All synthetic credentials are placeholders (e.g., `AKIAIOSFODNN7EXAMPLE000`, `ghp_xxxxxxxxxxxxxxxx`, `xoxb-xxxxxxxxxxxxxxxx`); no real secrets are contacted or persisted.
