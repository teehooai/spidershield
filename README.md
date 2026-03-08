# TeeShield -- Security Scanner for MCP tools

Scan, rate, and improve MCP server tool descriptions so AI agents use them correctly.

We scanned 7 public MCP servers (79 tools) and found the average description quality is **3.1 / 10**. Most tools give agents zero guidance on when to use them, what parameters to pass, or what errors to expect.

TeeShield fixes this.

## Install

```bash
pip install teeshield
```

Requires Python 3.11+.

## Quickstart

```bash
teeshield scan ./your-mcp-server
```

Example output:

```
            TeeShield Scan Report
   modelcontextprotocol/servers/filesystem
+---------------------------------------------+
| Metric                | Value     |   Score |
|-----------------------+-----------+---------|
| License               | MIT       |      OK |
| Tools                 | 14        |      OK |
| Security              | 0 issues  | 10.0/10 |
| Descriptions          |           |  3.2/10 |
| Architecture          |           | 10.0/10 |
| Tests                 | Yes       |      OK |
|                       |           |         |
| Overall               | Rating: B |  7.6/10 |
| Improvement Potential |           |  2.4/10 |
+---------------------------------------------+
```

## Rewrite tool descriptions

TeeShield can automatically rewrite tool descriptions to be action-oriented, with scenario triggers, parameter examples, and error guidance.

```bash
# Preview changes (no files modified)
teeshield rewrite ./your-mcp-server --dry-run

# Apply changes to source files
teeshield rewrite ./your-mcp-server
```

Before (score 2.9):
```
"Shows the working tree status"
```

After (score 9.6):
```
"Query the current state of the Git working directory and staging area.
 Use when the user wants to check which files are modified, staged, or
 untracked before committing."
```

The rewriter works offline using templates (zero cost). Set `ANTHROPIC_API_KEY` for higher-quality LLM-powered rewrites.

## Scan results across the MCP ecosystem

| Server | Tools | Security | Descriptions | Overall | Rating |
|--------|-------|----------|-------------|---------|--------|
| filesystem | 14 | 10.0 | 3.2 | 7.6 | B |
| git | 12 | 10.0 | 2.4 | 7.3 | B |
| memory | 9 | 10.0 | 2.3 | 7.3 | B |
| fetch | 1 | 9.0 | 3.5 | 7.3 | B |
| supabase | 30 | 9.0 | 2.3 | 6.4 | B |

Full report: [CURATION-REPORT.md](CURATION-REPORT.md)

## What TeeShield checks

**Descriptions** (weighted 40%)
- Scenario triggers ("Use when the user wants to...")
- Parameter examples
- Error handling guidance
- Disambiguation between similar tools
- Length (too short = vague, too long = noisy)

**Security** (weighted 30%)
- Path traversal
- Command injection
- SQL injection
- SSRF (unrestricted network access)
- Credential exposure

**Architecture** (weighted 20%)
- Test coverage
- Error handling
- Type annotations
- Input validation patterns

**License** (weighted 10%)
- MIT, Apache-2.0, BSD = OK
- GPL, AGPL = warning
- Missing = fail

## Rating scale

| Rating | Score | Meaning |
|--------|-------|---------|
| A+ | 9.0+ | Production-ready |
| A | 8.0+ | Safe with minor suggestions |
| B | 6.0+ | Usable, needs improvements |
| C | 4.0+ | Significant issues |
| F | <4.0 | Unsafe, do not deploy |

## JSON output

```bash
teeshield scan ./server --format json
teeshield scan ./server --format json -o report.json
```

## GitHub Action

Add TeeShield to your CI pipeline:

```yaml
- uses: teehooai/teeshield@v0.1.0
  with:
    target: '.'
    fail-below: '6.0'
```

## Commands

| Command | Description |
|---------|-------------|
| `teeshield scan <path>` | Scan and rate an MCP server |
| `teeshield rewrite <path>` | Rewrite tool descriptions |
| `teeshield harden <path>` | Security hardening recommendations |
| `teeshield eval <original> <improved>` | Compare tool selection accuracy |

## License

MIT
