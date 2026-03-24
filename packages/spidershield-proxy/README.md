# SpiderShield MCP Proxy

Security proxy for MCP servers — Trust Score checks, DLP scanning, and policy enforcement for every tool call.

## Usage

```bash
npx spidershield-proxy <mcp-server-command> [args...]
```

## Examples

```bash
# Protect a GitHub MCP server
npx spidershield-proxy npx @modelcontextprotocol/server-github

# Protect a local server
npx spidershield-proxy -- node my-server.js --port 3000

# Strict mode (block unknown servers)
SPIDERSHIELD_POLICY=strict npx spidershield-proxy npx @modelcontextprotocol/server-filesystem
```

## What it does

Sits between your MCP client and server, intercepting every tool call:

1. **Trust Score** — Checks the server against SpiderRating's database of 15,923 rated servers
2. **Policy rules** — Auto-generated allow/deny/escalate rules based on scan data
3. **DLP scan** — Detects secrets (API keys, tokens) and PII in parameters
4. **Output scan** — Checks tool results for data leaks
5. **Audit log** — Every decision logged to `~/.spidershield/audit/`

## Policy Modes

| Mode | Malicious (F) | Risky (D) | Unknown | Safe (C+) | Secrets |
|------|:---:|:---:|:---:|:---:|:---:|
| `audit-only` | log | log | log | log | log |
| **`balanced`** | **block** | warn | allow | allow | **redact** |
| `strict` | **block** | **block** | **block** | allow | **block** |

Set via environment variable: `SPIDERSHIELD_POLICY=strict`

## Claude Desktop config

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["spidershield-proxy", "npx", "@modelcontextprotocol/server-github"]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPIDERSHIELD_POLICY` | `balanced` | Policy mode |
| `SPIDERSHIELD_API_KEY` | — | Pro API key for cloud audit |
| `SPIDERSHIELD_API_URL` | SpiderRating public API | Custom API URL |

## Links

- [SpiderRating](https://spiderrating.com) — MCP ecosystem security ratings
- [SpiderShield](https://github.com/teehooai/spidershield) — Open-source scanner (MIT)
