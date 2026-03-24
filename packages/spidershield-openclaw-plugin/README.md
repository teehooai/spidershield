# SpiderShield OpenClaw Plugin

Automatic security checks for every tool call in OpenClaw agents.

## What it does

- **before_tool_call**: Checks Trust Score + scans parameters for secrets/PII
- **after_tool_call**: Scans tool output for data leaks + writes audit log
- **message_sending**: Scans outbound messages for secrets

## Install

```bash
openclaw plugins install spidershield-openclaw-plugin
```

## Configure

In `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "spidershield": {
        "enabled": true,
        "config": {
          "policy": "balanced"
        }
      }
    }
  }
}
```

## Policy Modes

| Mode | Malicious (F) | Risky (D) | Unknown | Safe (C+) | Secrets in params |
|------|:---:|:---:|:---:|:---:|:---:|
| `audit-only` | log | log | log | log | log |
| **`balanced`** | **block** | warn | allow | allow | **redact** |
| `strict` | **block** | **block** | **block** | allow | **block** |

## How it works

1. Agent calls a tool (e.g., `mcp__stripe__create_charge`)
2. Plugin queries [SpiderRating Trust API](https://spiderrating.com) for the server's security score
3. If Grade F (malicious) → **blocked**. If Grade D (risky) → **warning**. If C+ → allowed.
4. DLP scanner checks parameters for API keys, tokens, PII — redacts or blocks.
5. After execution, tool output is scanned for data leaks.
6. Everything logged to `~/.spidershield/audit/YYYY-MM-DD.jsonl`.

## Pro Features (optional)

Add a SpiderRating API key for cloud audit dashboard:

```json
{
  "config": {
    "policy": "balanced",
    "apiKey": "sr_..."
  }
}
```

Enables: cloud audit log, security dashboard, alert rules, compliance reports at [spiderrating.com/dashboard](https://spiderrating.com/dashboard).

## Links

- [SpiderRating](https://spiderrating.com) — MCP ecosystem security ratings
- [SpiderShield](https://github.com/teehooai/spidershield) — Open-source scanner (MIT)
- [Trust API docs](https://spiderrating.com/methodology) — Scoring methodology
