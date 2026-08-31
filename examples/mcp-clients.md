# Connecting MCP clients

The honeypot is a standard [Model Context Protocol](https://modelcontextprotocol.io) stdio server. Any MCP-capable client can connect; the tools it exposes are synthetic and every interaction is recorded (digests only).

## Claude Desktop / Claude Code

`claude_desktop_config.json` (or the equivalent MCP settings):

```json
{
  "mcpServers": {
    "finance-warehouse": {
      "command": "node",
      "args": ["D:/agent-honeypot/dist/surface/mcpservers/finance-warehouse/mcp_server.js"]
    }
  }
}
```

## Any other MCP client (generic)

Most clients accept a command + args pair:

- **command:** `node`
- **args:** `<repo>/dist/surface/mcpservers/finance-warehouse/mcp_server.js`

Build first (`npm run build`), or use the CLI: `agent-honeypot serve`.

## Programmatic (official SDK)

```js
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const transport = new StdioClientTransport({
  command: 'node',
  args: ['dist/surface/mcpservers/finance-warehouse/mcp_server.js'],
  env: { ...process.env, AGENT_HONEYPOT_DATA_DIR: '/tmp/honeypot-data' },
});
const client = new Client({ name: 'example', version: '0.1.0' });
await client.connect(transport);

const { tools } = await client.listTools();
const r = await client.callTool({
  name: 'db_query',
  arguments: { query: 'SELECT 1', context: 'example objective; tools: [db_query]' },
});
await client.close();
```

See `tests/integration.test.mjs` for a complete working example.

## Notes

- Set `AGENT_HONEYPOT_DATA_DIR` to choose where captures are written (default: `<repo>/data`).
- The server writes JSON-RPC to stdout and logs to stderr, per the MCP stdio convention.
- Interactions with tools that request "audit context" record only a SHA-256 digest of what the agent discloses, plus structured fields — never the raw text.
