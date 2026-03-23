# SpiderShield -- Security Scanner & Runtime Guard for MCP Servers

![SpiderShield Verified](https://img.shields.io/badge/MCP-SpiderShield_Verified-green)
[![PyPI](https://img.shields.io/pypi/v/spidershield)](https://pypi.org/project/spidershield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Security toolkit for MCP servers and AI agents.** Static analysis, runtime policy enforcement, DLP, and audit logging -- from development to production.

## What SpiderShield does

SpiderShield is a 5-subsystem security toolkit:

| Subsystem | Command / API | What it does |
|-----------|---------------|-------------|
| **Static Scanner** | `spidershield scan` | Score tool descriptions, detect code vulnerabilities, rate overall quality (F/C/B/A/A+) |
| **Agent Security** | `spidershield agent-check` | 18 config checks, 15 malicious pattern detections, toxic flow analysis, rug pull detection |
| **Runtime Guard SDK** | `SpiderGuard(policy="balanced")` | Pre/post-execution policy enforcement for tool calls |
| **MCP Proxy** | `guard_mcp_server(cmd)` | Transparent security proxy between agent and MCP server |
| **DLP Engine** | Built into Guard SDK | Scan tool outputs for PII/secrets, redact or block |

## Install

```bash
pip install spidershield
```

Requires Python 3.11+. See [SUPPORT.md](SUPPORT.md) for version compatibility and optional dependencies.

## 5-Minute Success Path

```bash
# 1. Install
pip install spidershield

# 2. Scan any MCP server
spidershield scan ./your-mcp-server

# 3. See what's wrong and how to fix it
spidershield rewrite ./your-mcp-server --dry-run

# 4. (Optional) Protect at runtime
spidershield proxy -- npx server-filesystem /tmp
```

For contributors:

```bash
git clone https://github.com/teehooai/spidershield && cd spidershield
make verify-oss   # One command: install + lint + type check + test + scan
```

## Quick Start

### Static scan (CI / development)

```bash
spidershield scan ./your-mcp-server
```

Example output:

```
            SpiderShield Scan Report
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

### Runtime Guard SDK (production)

Enforce security policies on every tool call at runtime:

```python
from spidershield import SpiderGuard, Decision

guard = SpiderGuard(policy="strict")

result = guard.check("read_file", {"path": "/etc/passwd"})
if result.decision == Decision.DENY:
    print(result.reason)       # "System file access blocked"
    print(result.suggestion)   # "Use application-level files instead"
```

Policy presets:

| Preset | Behavior |
|--------|----------|
| `strict` | Deny by default, explicit allow list |
| `balanced` | Block known-dangerous patterns, allow common operations |
| `permissive` | Warn on suspicious patterns, allow most operations |
| Custom YAML | Load your own policy file: `SpiderGuard(policy="my-policy.yaml")` |

With audit logging and DLP:

```python
guard = SpiderGuard(
    policy="strict",
    audit=True,              # Write audit trail to disk
    audit_dir="./logs",      # Custom audit directory
    dlp="redact",            # Scan outputs for PII/secrets, redact matches
)

# Pre-execution check
result = guard.check("query_db", {"sql": "SELECT * FROM users"})

# Post-execution DLP scan
clean_output = guard.after_check("query_db", raw_result)
```

With data flywheel (opt-in telemetry to local SQLite):

```python
guard = SpiderGuard(policy="balanced", dataset=True)
# Every check() call feeds the local dataset for scoring calibration
```

### MCP Proxy (transparent protection)

Wrap any MCP server with SpiderShield policy enforcement:

```python
from spidershield import guard_mcp_server

# Proxy between agent and server, enforcing "balanced" policy
guard_mcp_server(
    ["npx", "server-filesystem", "/tmp"],
    policy="balanced",
    audit=True,
)
```

Or from the CLI:

```bash
spidershield proxy -- npx server-filesystem /tmp --policy balanced
```

## Rewrite tool descriptions

SpiderShield can automatically rewrite tool descriptions to be action-oriented, with scenario triggers, parameter examples, and error guidance.

```bash
# Preview changes (no files modified)
spidershield rewrite ./your-mcp-server --dry-run

# Apply changes to source files
spidershield rewrite ./your-mcp-server
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

Full report: [MCP-SECURITY-REPORT.md](MCP-SECURITY-REPORT.md) | Raw data: [CURATION-REPORT.md](CURATION-REPORT.md)

## Try it on an example

The repo includes example MCP servers for instant demo:

```bash
git clone https://github.com/teehooai/spidershield
cd spidershield

spidershield scan examples/insecure-server   # Rating: D (3.3/10)
spidershield scan examples/secure-server     # Rating: D (4.7/10)
```

## What SpiderShield checks

### Static Scanner

**Security** (weighted 35%)
- Path traversal
- Command injection / dangerous eval
- SQL injection (Python + TypeScript)
- SSRF (unrestricted network access)
- Hardcoded credentials
- Unsafe deserialization (pickle, yaml.load)
- Prototype pollution (TypeScript)

**Descriptions** (weighted 35%)
- Action verb starts ("List", "Create", "Execute")
- Scenario triggers ("Use when the user wants to...")
- Parameter documentation
- Parameter examples
- Error handling guidance
- Disambiguation between similar tools
- Length (too short = vague, too long = noisy)

**Architecture** (weighted 30%)
- Test coverage (gradual: count-based)
- Error handling (gradual: coverage-based)
- README quality (gradual: length-based)
- Type annotations
- Dependency management
- Environment configuration

**License** (pass/fail gate, not weighted)
- MIT, Apache-2.0, BSD = OK
- GPL, AGPL = warning
- Missing = fail

### Agent Security Checker

Scan AI agent installations for security misconfigurations and malicious skills.

```bash
spidershield agent-check ~/.openclaw
```

**What it checks:**
- 10 configuration security checks (auth, sandbox, SSRF, permissions, etc.)
- 20+ malicious skill patterns (reverse shells, credential theft, prompt injection)
- Toxic flow detection -- flags skills that can read sensitive data AND send it externally
- Typosquat detection for skill names
- Excessive permission requests

**Advanced options:**

```bash
# Verify skill integrity (rug pull detection)
spidershield agent-check --verify

# Only approved skills allowed
spidershield agent-check --allowlist approved.json

# Strict mode: fail on any finding
spidershield agent-check --policy strict

# Ignore specific rules
spidershield agent-check --ignore TS-W001 --ignore typosquat

# Auto-fix configuration issues
spidershield agent-check --fix

# SARIF output for GitHub Code Scanning
spidershield agent-check --format sarif > results.sarif
```

**Skill pinning (rug pull protection):**

```bash
spidershield agent-pin add ~/.openclaw/skills/my-skill/SKILL.md
spidershield agent-pin add-all
spidershield agent-pin verify    # detect tampered skills
spidershield agent-pin list
```

**46 standardized issue codes** across 4 categories:

| Code | Category | Example |
|------|----------|---------|
| TS-E001~E015 | Error (malicious) | Reverse shell, credential theft, prompt injection |
| TS-W001~W011 | Warning (suspicious) | Typosquat, toxic flow, unapproved skill |
| TS-C001~C018 | Config | No auth, sandbox disabled, SSRF enabled |
| TS-P001~P002 | Pin | Verified, tampered |

## Rating scale (SpiderRating)

| Rating | Score | Meaning |
|--------|-------|---------|
| A | 9.0+ | Exemplary |
| B | 7.0+ | Production-ready |
| C | 5.0+ | Usable, needs improvements |
| D | 3.0+ | Significant issues |
| F | <3.0 | Unsafe, do not deploy |

Formula (MCP servers): `description × 0.38 + security × 0.34 + metadata × 0.28`
Formula (Skills): `description × 0.45 + security × 0.35 + metadata × 0.20`

## JSON output

```bash
spidershield scan ./server --format json
spidershield scan ./server --format json -o report.json
```

## GitHub Action

Add SpiderShield to your CI pipeline:

```yaml
- uses: teehooai/spidershield@v0.3.0
  with:
    target: '.'
    fail-below: '6.0'
```

## Commands

| Command | Description |
|---------|-------------|
| `spidershield scan <path>` | Scan and rate an MCP server |
| `spidershield rewrite <path>` | Rewrite tool descriptions |
| `spidershield harden <path>` | Suggest security hardening (advisory only) |
| `spidershield eval <original> <improved>` | Compare tool selection accuracy |
| `spidershield agent-check [dir]` | Scan an AI agent for security issues |
| `spidershield agent-pin <cmd>` | Manage skill pins for rug pull detection |
| `spidershield guard -- <cmd>` | Wrap any subprocess with security guard |
| `spidershield proxy -- <cmd>` | MCP proxy with policy enforcement |
| `spidershield policy list\|show\|validate` | Manage security policies |
| `spidershield audit show\|stats` | View guard audit logs |
| `spidershield dataset stats` | View data flywheel statistics |
| `spidershield dataset benchmark-add` | Add a benchmark entry |
| `spidershield dataset benchmark-run` | Re-run benchmarks |
| `spidershield dataset calibrate` | Run scoring calibration |

## Threat model

SpiderShield provides both **static analysis** and **runtime policy enforcement**.

**What it catches:**
- Ambiguous tool definitions that lead to agent misuse
- Missing side-effect declarations (writes, deletes, network calls)
- Unsafe permission patterns (unbounded file access, unrestricted queries)
- Vague descriptions that give agents no operational boundaries
- Malicious agent skills (reverse shells, credential theft, prompt injection)
- Dangerous capability combinations (data exfiltration flows)
- Insecure agent configurations (no auth, disabled sandbox, open DM policy)
- Skill tampering (rug pull detection via content hashing)
- PII/secret leakage in tool outputs (DLP engine)
- Policy violations at runtime (Runtime Guard)

**What it does NOT do:**
- Network traffic monitoring
- Container-level sandboxing
- Access control management (it enforces policies, not manages identities)

## License

MIT
