# Agent-Honeypot Architecture and Analysis Report

## 1. Overview and Threat Model
`agent-honeypot` is a defensive deception honeypot designed to detect, track, and study malicious or unauthorized LLM agents. Instead of returning real data, it acts as a synthetic MCP (Model Context Protocol) tool server. Agents visiting this honeypot interact with fake tools—such as databases or shells—and all their actions are logged and analyzed.

The threat model addresses modern AI-enabled adversaries, focusing on:
- **Context Leaks:** Tricking agents into disclosing their objective and state.
- **Prompt Injections & Persistence:** Tracking when agents try to establish recurring tasks or register persistent goals.
- **Reconnaissance & Escalation:** Observing interaction depths over a synthetic shell trap.

The system is deployed in isolated zones:
- **Zone A (Untrusted Edge):** Cloudflare Workers (digest-only).
- **Zone B (Deception Surface):** MCP Honeypot servers returning synthetic data and maintaining zero egress.
- **Zone C (Capture & Analysis):** Session recorder, 24-dimension fingerprinting, actor clustering.
- **Zone D (Evolution & Control):** System components that manage lure lineage, shadowing, promotion, and output to STIX/SIEM.

## 2. Codebase Structure
The codebase is structured into several interconnected modules:
- **`surface/`**: Contains the MCP servers (like `finance-warehouse` and `hr-portal`). These define the synthetic tools the agent interacts with (`db_query`, `ssh_exec`, `schedule_task`).
- **`capture/`**: Manages recording interactions (append-only JSONL files, digest-only persistence). It implements a state machine: `DETECTED → ENGAGED → FINGERPRINTED → INTERROGATED → SCORED`.
- **`analysis/`**: Processes captured events to create a 24-dimension behavioral fingerprint. It clusters agents (to identify repeated actors) and generates STIX 2.1 threat intelligence bundles for SIEM tools.
- **`evolution/`**: The core for counterexample-driven lure generation. It runs a Thompson-sampling bandit to rotate variants and implements a validation pipeline before promoting a new lure.
- **`tests/`**: A robust suite verifying both core utilities and ensuring critical security guarantees (e.g., confirming no raw text is logged).

## 3. Analysis Capabilities
Running the built-in analysis script (`npm run analyze`) on a synthesized dataset produced the following output:
- **Sessions Analyzed**: 117 total sessions.
- **Alert Tiers**: Graded threat scores into tiers (`low`: 40, `medium`: 69, `high`: 8).
- **Clustering & Anomalies**: Detected 11 distinct actor clusters (useful for correlating repeated attacks) and 12 anomalies.
- **STIX 2.1 Generation**: Successfully generated 8 bundles for the `high/critical` sessions.
This demonstrates the system's ability to ingest log events, fingerprint an agent's behavior, identify its threat level, and output standard threat intelligence data.

## 4. Security Guarantees
The security guarantees of the architecture were verified via the test suite (`npm test`), all 57 tests passing successfully. Specifically:
- **Digest-only Persistence:** Confirmed. Raw argument text from an agent is never persisted; only stable SHA-256 digests are stored, preventing the honeypot from accidentally saving sensitive data.
- **Audit Ledger Integrity:** The tampered-evident ledger properly detects and identifies any unauthorized changes.
- **Per-tenant Schema Isolation:** Validated.
- **Human Promotion Gate:** Automatic promotion to "live" is blocked; the system enforces human approval before rotating the deception surface.

## 5. Deployment and Production Readiness
The `agent-honeypot` repository supports different deployment tiers based on the volume and operational requirement:

- **Lab Tier (Default):** `<100 sessions/day`. All data is logged in a local `data/` directory using JSONL. Suitable for local testing and research out-of-the-box (no external dependencies).
- **Docker Tier:** `<1k sessions/day`. Launchable via a single `docker compose up -d` command using a multi-stage Dockerfile based on `node:20-slim`. It uses a persistent volume for the captured data. A NATS sidecar can optionally be uncommented for the message bus.
- **Enterprise Tier:** `10k–1M sessions/day`. This tier scales horizontally and introduces robust infrastructure requirements:
  - **Message Bus:** NATS JetStream (configurable via `AGENT_HONEYPOT_NATS_URL`) replaces the fallback JSON file.
  - **Data Stores:** Requires `ClickHouse` for event logging and `pgvector` for actor clustering and anomaly scanning.
  - **Network and Auth Policies:** Handled via Terraform/Helm configurations (deny-all NetworkPolicy, restricted Pod Security Standards, Vault policies).
- **Edge Tier:** `>1M sessions/day`. Pushes the initial engagement to the network edge utilizing Cloudflare Workers (`infra/cloudflare`) and stores digest-only captures in R2 object storage. Deployed via `wrangler deploy`.

To make the system fully production-ready (at the Enterprise Tier or above):
1. Compile the server locally via `npm run build` or rely on the Docker multi-stage build.
2. Provide valid connection URLs for external services through environment variables such as:
   - `AGENT_HONEYPOT_NATS_URL`
   - `AGENT_HONEYPOT_SIEM_URL` and `AGENT_HONEYPOT_SIEM_TOKEN` (for STIX events to a SIEM)
   - `OTEL_EXPORTER_OTLP_ENDPOINT` (for telemetry)
3. Do not blindly expose the honeypot on public interfaces without edge termination or proper networking controls, ensuring it maintains its fundamental Zero Egress property.