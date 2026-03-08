# TeeShield -- MCP Server Security Linter

## Project Overview
TeeShield is a static analysis tool for MCP (Model Context Protocol) servers.
It scans tool descriptions, security patterns, architecture quality, and licensing.
Think "npm audit for MCP tools".

## Architecture
```
src/teeshield/
  cli.py              -- Click CLI (scan, rewrite, harden, eval)
  models.py            -- Pydantic V2 models (ScanReport, SecurityIssue, etc.)
  server.py            -- MCP server mode (scan_mcp_server tool)
  scanner/
    runner.py          -- Orchestrates 4-stage scan pipeline
    description_quality.py -- Tool description scoring (7 criteria)
    security_scan.py   -- Static security pattern matching
    architecture_check.py -- Code quality checks
    license_check.py   -- License detection
  rewriter/runner.py   -- Template + LLM description rewriter
  hardener/runner.py   -- Security fix suggestions
  evaluator/runner.py  -- Tool selection accuracy testing
```

## Hard Constraints (G0 -- never violate)

1. **No false sense of security**: Never give A/A+ rating to a server with undetected critical issues.
   If uncertain, score conservatively.
2. **No destructive modifications**: `rewrite` and `harden` must never break working code.
   Always preserve original semantics.
3. **Reproducible results**: Same input must produce identical scan output.
   No randomness, no network-dependent scoring.

## Evolution Mode Protocol

TeeShield uses evidence-driven evolution (see docs/observations/001-audit-quality-evolution-2026-03-08.md).

### Per-Change Cycle
1. **Evidence first**: Before changing a scanner, document the false positive/negative that motivates the change
2. **Measure before/after**: Run `teeshield scan` on test-targets/ before and after changes
3. **Update observation doc**: Record what changed and why in docs/observations/

### Scanner Quality Rules
- Security scanner: Minimize false positives. A false positive erodes trust more than a missed issue.
- Description scorer: Score must correlate with actual LLM tool selection success.
- Architecture checker: Gradual scoring preferred over binary pass/fail.
- Overall score: weighted `security*0.4 + descriptions*0.35 + architecture*0.25`.

### Scoring Calibration
- A server with no quality signals in descriptions should score 0-2/10, not 3-4/10
- A server with all quality signals should score 8-10/10
- Security score 10.0 means zero issues found, not "secure" (we can't prove absence)

## Development Standards

- Python 3.11+ with type hints on all new functions
- Use Pydantic V2 for data models
- Rich console for CLI output
- Tests in tests/ directory
- No unnecessary dependencies

## Key Files for Common Tasks

| Task | Files |
|------|-------|
| Add security pattern | scanner/security_scan.py (DANGEROUS_PATTERNS dict) |
| Add description criterion | scanner/description_quality.py + models.py (ToolDescriptionScore) |
| Change scoring weights | scanner/description_quality.py (line ~90-108) |
| Add tool extraction pattern | scanner/description_quality.py (_extract_tools) |
| Change report output | scanner/runner.py (_print_table) |
| Add CLI command | cli.py |
