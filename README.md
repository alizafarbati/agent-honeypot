<p align="center">
  <img src="docs/logo.svg" alt="agent-honeypot logo" width="480">
</p>

<h1 align="center">agent-honeypot</h1>

<p align="center">
  <strong>A defensive honeypot for LLM agents.</strong><br>
  Synthetic MCP tool servers. Canary documents. 24-dimension fingerprinting.<br>
  Study how autonomous agents probe, escalate, and persist — without touching a real system.
</p>

<p align="center">
  <a href="https://www.gnu.org/software/coreutils/"><img alt="platform" src="https://img.shields.io/badge/platform-win%20%7C%20linux%20%7C%20macos-lightgrey"></a>
  <a href="https://www.npmjs.com/"><img alt="node" src="https://img.shields.io/badge/node-%3E%3D20-brightgreen"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <a href="https://github.com/agent-honeypot/agent-honeypot/actions"><img alt="CI" src="https://img.shields.io/badge/CI-38%2F38%20tests-brightgreen"></a>
  <a href="https://github.com/agent-honeypot/agent-honeypot/releases"><img alt="release" src="https://img.shields.io/badge/version-0.1.0--alpha-orange"></a>
</p>

---

## Table of contents

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Quickstart](#quickstart)
- [Using the honeypot with an MCP client](#using-the-honeypot-with-an-mcp-client)
- [Security guarantees (tested)](#security-guarantees-tested)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Testing](#testing)
- [Deployment tiers](#deployment-tiers)
- [Repository layout](#repository-layout)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Why this exists

The threat model changed. CrowdStrike's 2026 Global Threat Report records an **89%** year-over-year increase in attacks by AI-enabled adversaries and a 27-second fastest eCrime breakout time. IBM X-Force 2026 reporting describes agentic AI as an attack-surface class that CVE-style tracking does not cover. Meanwhile, 2026 research demonstrates practical agent attacks via tool descriptions ([ContextLeak](https://arxiv.org/abs/2608.27800)), long-context injection ([LongPIBench](https://arxiv.org/abs/2608.28411)), and harness-level privilege escalation ([When Context Gets Root](https://arxiv.org/abs/2608.27299)).

Classical deception tooling (canary tokens, classic honeypots) assumes a *human* attacker: fire-and-forget markers with no interaction. Agents behave differently — they hold multi-turn state, disclose their own context into tool arguments, and follow injected instructions. agent-honeypot adapts honeypot technique to that behavior model:

| Research finding | How this project uses it |
|---|---|
| **ContextLeak** — RL-crafted tool names/descriptions induce agents to disclose runtime context | Inverted: tool schemas request "audit context," capturing the visiting agent's objective and tool inventory |
| **LongPIBench** — simple injections bypass defenses at long context | Payload definitions calibrated to empirically weak positions (~60–80% depth) |
| **When Context Gets Root** — low-privilege content escalated by harnesses | `register_persistent_goal` / `schedule_task` tools capture persistence behavior live |
| **CAITLYN** — counterexample-driven defense synthesis | Escaped sessions generate new lure candidates → validation gauntlet → shadow deployment |

## How it works

```
                    +-------------------------------------------------+
   visiting agent   |                DECEPTION SURFACE                |
  ----------------->|  MCP server "finance-warehouse" (synthetic)     |
                    |  5 tools - latency jitter - 3% error injection  |
                    |  12-page pagination trap - per-tenant schemas   |
                    +------------------------+------------------------+
                                             |
                    +------------------------v------------------------+
                     CAPTURE PLANE  (append-only, digest-only)
                     session state machine  DETECTED -> ENGAGED -> ... -> SCORED
                                             |
                    +------------------------v------------------------+
                     ANALYSIS  24-dim fingerprint - composite score
                     actor clustering (cosine) - anomaly detection
                     STIX 2.1 - SIEM / MISP output
                                             |
                    +------------------------v------------------------+
                     EVOLUTION  escaped session -> antigen (no raw text)
                     -> candidates -> validation gauntlet -> SHADOW
                     -> human approval -> live   [bandit rotation]
                    +-------------------------------------------------+
```

Five synthetic tools, three bait families:

| Tool | Family | Captures |
|---|---|---|
| `db_query` | Context-bait (ContextLeak inverted) | objective, tool inventory, context-window ceiling, pagination/loop discipline |
| `email_send` | Context-bait | disclosure behavior |
| `ssh_exec` | Interactive trap | command sequences, justification quality, token-burn ceiling |
| `register_persistent_goal` | Persistence bait (When Context Gets Root) | objective + action plan, privilege confirmation |
| `schedule_task` | Persistence bait | trajectory disclosure, cron-style persistence attempt |

Every interaction yields a fingerprint — 24 dimensions including model-family heuristics, harness residue, permission posture, injection-susceptibility ladder (L1–L3), loop discipline (non-decaying loop detection), and persistence evidence — rolled into a coverage-weighted composite with alert tiers (low &lt;26 / medium &lt;61 / high &lt;86 / critical ≥86).

## Quickstart

```bash
git clone https://github.com/agent-honeypot/agent-honeypot.git
cd agent-honeypot
npm install
npm run build
npm test
```

CLI (all operations, one entry point):

```bash
npx agent-honeypot doctor    # environment health check
npx agent-honeypot seed 4    # synthetic sessions for demos/reports
npx agent-honeypot report    # Markdown + JSON report from captures
npx agent-honeypot dash      # dashboard: http://127.0.0.1:9079
npx agent-honeypot serve     # run the MCP honeypot on stdio
```

Dashboard endpoints:

| Endpoint | Returns |
|---|---|
| `/summary` | totals, per-tool/per-lane counts, per-session composite + alert tier |
| `/actors` | full 24-dim fingerprints + cluster keys per session |
| `/health` | liveness |

## Using the honeypot with an MCP client

The honeypot is a standard MCP stdio server. Claude Desktop:

```json
{
  "mcpServers": {
    "finance-warehouse": {
      "command": "node",
      "args": ["/path/to/agent-honeypot/dist/surface/mcpservers/finance-warehouse/mcp_server.js"]
    }
  }
}
```

For other clients and a programmatic SDK example, see [examples/mcp-clients.md](examples/mcp-clients.md).

## Security guarantees (tested)

These are **machine-checked** in `tests/security.test.mjs`, not just documented:

1. **Digest-only persistence.** Raw argument text never reaches disk — SHA-256 digests only. The test suite feeds known secret strings through the capture plane and asserts they never appear in the store.
2. **Tamper-evident audit ledger.** Every privileged operation appends to a hash chain; `verifyLedger()` detects any edited entry and reports where integrity broke. The test forges an entry and asserts detection.
3. **No raw text in the LLM path.** Antigen profiles passed to candidate generation contain counts and hashes only — session IDs appear as truncated digests.
4. **Human promotion gate.** Shadow lures require validation gates + minimum volume, and promotion itself is a human action — there is no programmatic `promoteToLive()`.
5. **Per-tenant isolation.** Schema mutation is deterministic per tenant (stable) and synonym-only (no semantic fields dropped).
6. **Synthetic responses.** Every response is generated; no real host, credential, or dataset is contacted. Canaries are clearly marked simulated.

Full policy: [SECURITY.md](SECURITY.md).

## Architecture

```
Zone A (edge, untrusted)   Zone B (deception surface)   Zone C (analysis)   Zone D (control)
------------------------   --------------------------   -----------------   -----------------
Cloudflare Worker    -->   MCP honeypot (gVisor)   -->  fingerprint 24-d   STIX / SIEM / MISP
R2 (digest-only)          zero egress                   clustering          evolution engine
                          synthetic only                audit ledger        tenant API
```

Zones communicate over NATS JetStream when configured (file fallback in lab mode); no zone trusts another by network position. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Configuration

Everything works offline with zero configuration. Integrations are environment switches (see [.env.example](.env.example)):

| Variable | Effect |
|---|---|
| `AGENT_HONEYPOT_DATA_DIR` | relocate all runtime state (default `./data`) |
| `AGENT_HONEYPOT_NATS_URL` | NATS JetStream event bus |
| `AGENT_HONEYPOT_SIEM_URL`/`TOKEN` | live SIEM webhook dispatch |
| `AGENT_HONEYPOT_MISP_URL`/`KEY` | MISP event push |
| `AGENT_HONEYPOT_LLM_URL` | LLM candidate generation |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP trace export |

## Testing

```bash
npm test    # 47 tests across 5 suites
```

| Suite | What it proves |
|---|---|
| `core` | fingerprint dimensions, composite scoring, interrogator profile |
| `evolution` | antigen -> candidate -> validation -> shadow pipeline; bandit rotation |
| `analytics_hardening` | clustering, anomaly detection, jitter bounds, schema mutation, ledger, billing |
| `security` | the six guarantees above (leak-proof, tamper-evident, gate-checked) |
| `integration` | **real end-to-end**: official MCP SDK client over stdio against the built server — tool listing, pagination, L3 persistence capture, unknown-tool handling |

## Deployment tiers

| Tier | Sessions/day | Storage | Assets |
|---|---|---|---|
| Lab | <100 | `data/` (JSONL) | zero dependencies |
| Enterprise | 10k–1M | NATS + ClickHouse + pgvector | `infra/terraform`, `infra/helm` |
| Edge | >1M | Cloudflare Worker + R2 | `infra/cloudflare` (digest-only at edge) |

## Repository layout

```
analysis/     fingerprint extractors (24 dims), clustering, anomaly, STIX
antibodies/   Tier-0 self-monitor (CAITLYN pattern)
bin/          CLI entry point
capture/      shared paths, session recorder, event bus
control/      dashboard, tenant API, SIEM/MISP, report, billing
corpus/       benign replay corpus (false-positive gate)
credential/   simulated canary templates
docs/         architecture reference, logo
examples/     MCP client guides
evolution/    counterexample engine, RL bandit, hardening suite
honeydocs/    synthetic documents
infra/        Terraform, Helm, Cloudflare, ClickHouse, pgvector, Vault, metrics
lures/        lure contracts with lineage
payloads/     L1-L3 injection payload definitions
scripts/      seed utility
security/     hash-chain audit ledger, rotation schedules
surface/      MCP honeypot servers (finance-warehouse)
tests/        5 suites, 47 tests
```

## Limitations

Pre-alpha research prototype. Model-family heuristics are coarse (a trained classifier is future work); TLS/GeoIP dimensions (13–14) require edge termination; the RL reward function is specified and unit-tested but no fine-tuned generator ships. MITRE ATLAS IDs in `analysis/ttmapper/atlas_map.yaml` are marked *verify before external sharing*. The 3% error rate and latency distributions are lab-calibrated; production tuning is a deployment concern.

## Contributing

Defensive research only — see [CONTRIBUTING.md](CONTRIBUTING.md). PRs must keep `npm test` green and `npm run typecheck` clean.

## References

1. Jia, Y. et al. *ContextLeak: Exfiltrating LLM Agent Context via Malicious Tools.* arXiv:2608.27800 (2026).
2. Liu, Y. et al. *LongPIBench: A Long-Context Benchmark for Prompt Injection.* Findings of EMNLP 2026.
3. He, X. et al. *When Context Gets Root: Privilege Escalation in LLM Harnesses.* arXiv:2608.27299 (2026).
4. Liang, Z. et al. *CAITLYN: Can LLM Agents Autonomously Synthesize Defenses against Emerging Injection Attacks?* (2026).
5. CrowdStrike. *2026 Global Threat Report.*
6. Model Context Protocol. *Tools Specification*, 2025-06-18.
7. Spitzner, L. *Honeypots: Tracking Hackers.* Addison-Wesley (2002).

## License

MIT — see [LICENSE](LICENSE).
