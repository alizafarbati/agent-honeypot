# agent-honeypot

A defensive honeypot for LLM agents. It exposes synthetic MCP tool servers and canary documents, records how interacting agents behave, and fingerprints them — model family, harness, permission posture, injection susceptibility, persistence attempts — without ever touching a real system.

**This is a research prototype.** Every response the honeypot returns is synthetic. No real credentials, hosts, or datasets are involved. It is built to study an emerging attacker class (autonomous agents probing tool surfaces) and to give defenders a measurable early-warning signal.

## Why

CrowdStrike's 2026 Global Threat Report records an 89% year-over-year increase in attacks by AI-enabled adversaries and a 27-second fastest eCrime breakout time. IBM X-Force 2026 reporting describes agentic AI as a new attack-surface class that conventional CVE tracking does not cover. On the research side, 2026 work has demonstrated practical attacks against agents via tool descriptions (ContextLeak, arXiv:2608.27800), long-context prompt injection (LongPIBench, arXiv:2608.28411), and instruction privilege escalation in agent harnesses (arXiv:2608.27299).

Existing deception tooling (e.g., canary tokens) is designed for human attackers: fire-and-forget markers with no interaction. Agents, by contrast, hold multi-turn state, leak their own context into arguments, and follow injected instructions. This project adapts honeypot technique to that behavior model:

| Research finding | How it is used here |
|---|---|
| ContextLeak — RL-crafted tool names/descriptions induce agents to disclose runtime context | Inverted: tool schemas request "audit context," capturing the visiting agent's objective and tool inventory (dimensions 1-2, 7) |
| LongPIBench — simple injections bypass defenses at long context | Can be embedded in synthetic documents at empirically weak positions (~60-80% depth) |
| When Context Gets Root — low-privilege content escalated by harnesses | Fake `register_persistent_goal` / `schedule_task` tools capture persistence behavior (dimension 20) |
| CAITLYN — counterexample-driven defense synthesis | Reused as an evolution loop: escaped sessions generate new lure candidates, validated, shadow-deployed |

## What it does

1. **Deception surface** — an MCP server (`finance-warehouse`) offering five synthetic tools: `db_query`, `email_send`, `ssh_exec`, `register_persistent_goal`, `schedule_task`. Tools paginate, inject realistic latency jitter, and fail at plausible rates so the surface does not announce itself.
2. **Capture plane** — every interaction is appended to a JSONL ledger. Only digests and structured fields are recorded; no raw argument text is persisted.
3. **Fingerprinting** — a 24-dimension vector per session: model-family heuristics, context-window ceiling, harness residue, permission posture, injection-susceptibility ladder, loop discipline (non-decaying loop detection), token-burn ceiling, credential-use evidence, persistence evidence, and a composite threat score. See `analysis/fingerprint/fingerprint_schema.json`.
4. **Actor clustering** — cosine similarity over fingerprints groups sessions into likely operators (lab: in-memory greedy; production: pgvector).
5. **Evolution engine** — sessions that escape without engaging trigger candidate lure variants (deterministic lab generator; LLM hook optional), pass a validation gauntlet (self-monitor, benign-corpus false-positive gate, anti-fingerprint checks), then enter shadow deployment. Promotion requires a human gate.
6. **Output** — STIX 2.1 bundles, SIEM webhooks (MISP hook included), a per-tenant API, Prometheus metrics, and a quarterly report generator.

## Quickstart

```bash
npm install
npm run build
npm test                 # 38 tests, including a real MCP end-to-end

# CLI (alternative to npm scripts)
npx agent-honeypot doctor   # environment health check
npx agent-honeypot seed 4   # write synthetic sessions
npx agent-honeypot report   # Markdown + JSON report from captures
npx agent-honeypot dash     # dashboard on http://127.0.0.1:9079
npx agent-honeypot serve    # run the MCP honeypot on stdio
```

Captures, dashboards, and reports all read/write under `data/` (override with
`AGENT_HONEYPOT_DATA_DIR`). Connecting an MCP client? See
[examples/mcp-clients.md](examples/mcp-clients.md).

Optional integrations are environment-variable switches, not code changes:

| Variable | Enables |
|---|---|
| `AGENT_HONEYPOT_NATS_URL` | NATS JetStream event bus instead of file fallback |
| `AGENT_HONEYPOT_SIEM_URL` / `AGENT_HONEYPOT_SIEM_TOKEN` | real SIEM webhook dispatch |
| `AGENT_HONEYPOT_MISP_URL` / `AGENT_HONEYPOT_MISP_KEY` | MISP event push |
| `AGENT_HONEYPOT_LLM_URL` | LLM-based candidate generation in the evolution engine |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP trace export |

## Repository layout

```
analysis/       fingerprint extractors (24 dims), clustering, anomaly, STIX emitter
antibodies/     self-monitor checks (CAITLYN-style Tier-0)
bait_config/    reward function for lure optimization
bin/            CLI entry point
capture/        shared paths, session recorder, event bus
control/        dashboard, tenant API, SIEM/MISP, report generator, usage metering
corpus/         benign replay corpus (false-positive gate)
credential/     canary credential templates
data/           runtime state (sessions.jsonl, ledger, reports) - gitignored
docs/           architecture reference
evolution/     counterexample engine (antigen->candidate->validate->shadow), RL bandit, hardening
examples/       MCP client connection guides
honeydocs/      synthetic documents
infra/          Terraform, Helm, Cloudflare Worker + R2, ClickHouse, pgvector, Vault policies, metrics, tracing, sharding
lures/          lure contracts with lineage
mcp_tool/       tool contract JSON Schema
payloads/       L1-L3 injection payload definitions
scripts/        seed utility
security/       hash-chain audit ledger, rotation schedules
surface/        MCP honeypot servers (finance-warehouse)
tests/          core, evolution, analytics/hardening, end-to-end suites
```

## Defensive guarantees

- All honeypot responses are **synthetic**; no real host, credential, or dataset is ever contacted.
- Capture plane records **digests only** — raw argument text never reaches disk in the hot path.
- The **analysis LLM, if configured, never receives raw attacker text** — only bounded, structured antigen profiles.
- Every lure change passes a validation gauntlet and requires explicit human promotion from shadow.
- All counter-actions are policy-gated and appended to a hash-chain audit ledger (`security/audit/`).

## Deployment tiers

| Tier | Sessions/day | Storage | Notes |
|---|---|---|---|
| Lab | <100 | local JSONL | zero external dependencies |
| Enterprise | 10k-1M | NATS + ClickHouse + pgvector | Terraform/Helm under `infra/` |
| Edge | >1M | Cloudflare Worker + R2 | `infra/cloudflare/`, digest-only at edge |

## Status and limitations

Pre-alpha research prototype. Known limitations: model-family heuristics are coarse (a trained classifier is future work); extractors for dimensions 13-14 require TLS termination at an edge zone; the RL reward function is specified (`bait_config/`) and unit-tested but no fine-tuned model ships here. MIT technique IDs in `analysis/ttmapper/atlas_map.yaml` are marked verify-before-publish.

## References

1. Jia, Y. et al. *ContextLeak: Exfiltrating LLM Agent Context via Malicious Tools.* arXiv:2608.27800 (2026).
2. Liu, Y. et al. *LongPIBench: A Long-Context Benchmark for Prompt Injection.* Findings of EMNLP 2026. arXiv:2608.28411.
3. He, X. et al. *When Context Gets Root: Privilege Escalation in LLM Harnesses.* arXiv:2608.27299 (2026).
4. Liang, Z. et al. *CAITLYN: Can LLM Agents Autonomously Synthesize Defenses against Emerging Injection Attacks?* (2026). github.com/liangzid/caitlyn
5. CrowdStrike. *2026 Global Threat Report.*
6. Model Context Protocol. *Tools Specification*, 2025-06-18. modelcontextprotocol.io
7. Spitzner, L. *Honeypots: Tracking Hackers.* Addison-Wesley (2002) — foundational deception concepts adapted for non-human visitors.

## License

MIT — see [LICENSE](LICENSE).
