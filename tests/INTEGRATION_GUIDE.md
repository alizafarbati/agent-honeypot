# Agent Honeypot - Integration Guide

Connect the honeypot MCP servers to any MCP-capable AI agent client.
All servers are synthetic, zero-egress, and safe to attach to any agent.

## 1. Claude Desktop

Add to `claude_desktop_config.json` (usually `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "finance-warehouse": {
      "command": "node",
      "args": ["<REPO>/dist/surface/mcpservers/finance-warehouse/mcp_server.js"]
    },
    "hr-portal": {
      "command": "node",
      "args": ["<REPO>/surface/mcpservers/hr-portal/mcp_server.mjs"]
    }
  }
}
```

## 2. ASSASSIN

Merge the entries from `assassin_mcp_config.json` into your ASSASSIN
`config.json` `mcp_servers` array (see the ASSASSIN docs for the config
location on your platform), or pass the config via `--mcp`.

## 3. OpenClaw

```sh
openclaw config patch --file <patch-file>
```

Example patch file (relative to the repo root):

```json
{
  "mcp": {
    "servers": {
      "honeypot-finance": {
        "enabled": true,
        "command": "node",
        "args": ["<REPO>/dist/surface/mcpservers/finance-warehouse/mcp_server.js"]
      },
      "honeypot-hr": {
        "enabled": true,
        "command": "node",
        "args": ["<REPO>/surface/mcpservers/hr-portal/mcp_server.mjs"]
      }
    }
  }
}
```

## 4. Any other MCP client

Any client that speaks the Model Context Protocol over stdio can connect:

- **command:** `node`
- **args (finance):** `<REPO>/dist/surface/mcpservers/finance-warehouse/mcp_server.js`
- **args (HR):** `<REPO>/surface/mcpservers/hr-portal/mcp_server.mjs`

Optional environment variable `AGENT_HONEYPOT_DATA_DIR` redirects capture
output to a custom directory (defaults to `<REPO>/data`).

## What each server exposes

| Server | Tools | Lure family |
|--------|-------|-------------|
| finance-warehouse | `db_query`, `email_send`, `ssh_exec`, `register_persistent_goal`, `schedule_task` | fw-audit-plain / fw-audit-sox / fw-audit-governance |
| hr-portal | `employee_lookup`, `payslip_download`, `submit_leave_request`, `it_provisioning_request` | hr-selfservice-plain / hr-selfservice-gdpr |

## Safety

- All data returned by the servers is synthetic.
- Zero network egress - nothing leaves the host.
- Raw argument text is never persisted - SHA-256 digests only.
- Canary credentials are fake and trip an alert when an agent uses them.
