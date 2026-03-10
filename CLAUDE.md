# SpiderShield -- MCP Server Security Linter

## Project Overview
SpiderShield is a static analysis tool for MCP (Model Context Protocol) servers.
It scans tool descriptions, security patterns, architecture quality, and licensing.
Think "npm audit for MCP tools".

## Architecture
```
src/spidershield/
  cli.py              -- Click CLI (scan, rewrite, harden, eval, dataset)
  models.py            -- Pydantic V2 models (ScanReport, SecurityIssue, etc.)
  server.py            -- MCP server mode (scan_mcp_server tool)
  spiderrating.py      -- SpiderRating format conversion (metadata, grades)
  scanner/
    runner.py          -- Orchestrates 4-stage scan pipeline + metadata emission
    description_quality.py -- Tool description scoring (7 criteria)
    security_scan.py   -- Static security pattern matching
    architecture_check.py -- Code quality checks
    license_check.py   -- License detection
  dataset/
    db.py              -- SQLite schema v5, migration, get_stats
    collector.py       -- Best-effort recording (scans, rewrites, PRs, agent, guard)
  agent/
    scanner.py         -- Agent config security audit
    skill_scanner.py   -- Skill malware/injection pattern matching (20 patterns)
    toxic_flow.py      -- Dangerous capability combination detection (keyword + AST)
    pinning.py         -- SHA-256 content pinning for rug-pull detection
    allowlist.py       -- Approved-only skills enforcement
    sarif.py           -- SARIF output for agent findings
    models.py          -- Finding, SkillFinding, ScanResult, AuditFramework
    issue_codes.py     -- TS-E/W/C/P code registry
  rewriter/
    runner.py          -- Template + LLM description rewriter
    cache.py           -- SHA-256 keyed LLM rewrite cache
    providers.py       -- Anthropic / OpenAI / Gemini providers
  hardener/runner.py   -- Security fix suggestions
  evaluator/runner.py  -- Tool selection accuracy testing
```

## Hard Constraints (G0 -- never violate)

1. **No false sense of security**: Never give A rating to a server with undetected critical issues.
   If uncertain, score conservatively.
2. **No destructive modifications**: `rewrite` and `harden` must never break working code.
   Always preserve original semantics.
3. **Reproducible results**: Same input must produce identical scan output.
   No randomness, no network-dependent scoring.

## Evolution Mode Protocol

SpiderShield uses evidence-driven evolution (see docs/internal/001-audit-quality-evolution-2026-03-08.md).

### Per-Change Cycle
1. **Evidence first**: Before changing a scanner, document the false positive/negative that motivates the change
2. **Measure before/after**: Run `spidershield scan` on test-targets/ before and after changes
3. **Update observation doc**: Record what changed and why in docs/internal/

### Scanner Quality Rules
- Security scanner: Minimize false positives. A false positive erodes trust more than a missed issue.
- Description scorer: Score must correlate with actual LLM tool selection success.
- Architecture checker: Gradual scoring preferred over binary pass/fail.
- Overall score: SpiderRating formula `descriptions*0.35 + security_adjusted*0.35 + architecture*0.30`.
- Architecture bonus: `min(3.0, arch_score * 0.3)` folds into security_adjusted.
- Grade scale: F/D/C/B/A (thresholds: 3.0/5.0/7.0/8.5).
- Hard constraints: critical→F, no_tools→F, license_banned→D cap.

### Scoring Calibration
- A server with no quality signals in descriptions should score 0-2/10, not 3-4/10
- A server with all quality signals should score 8-10/10
- Security score 10.0 means zero issues found, not "secure" (we can't prove absence)

## PR Campaign Quality Gates (G1 -- must pass before submitting any PR)

Before submitting a PR to any external MCP repo, ALL 5 gates must pass:

1. **Real problem**: The original description has a concrete, demonstrable issue
   (ambiguous scope, missing side-effects, misleading trigger). Not "could be better".
2. **Narrower and more precise**: The rewrite must be semantically narrower or more
   specific than the original. Never broaden scope.
3. **Preserves command semantics**: The rewrite must not change what the tool actually does.
   `git fetch` fetches from git remotes, not URLs. `git add` stages files, not "appends".
4. **One-sentence justification**: If you cannot explain the change in one sentence,
   the change is not high-confidence enough for an automated PR.
5. **Tests must pass**: If the target repo has CI, the PR must not break it.
   Description-only changes should never break tests.

### PR Strategy by Repo Type

| Type | Stars | Action | Example |
|------|-------|--------|---------|
| A: Small active | < 1k | Direct PR | HenkDz/postgresql-mcp-server |
| B: Large/strict | > 1k | Issue first, PR if invited | modelcontextprotocol/servers |
| C: Corporate | any | Issue only | playwright-mcp, github-mcp |

### PR Anti-Patterns (learned from rejected PRs)

- **Tautological triggers**: "Opens a file. Use when user wants to open a file." (rejected by ida-pro-mcp #277)
- **Semantic mismatches**: git "fetch" matched to URL "fetch", git "add" matched to "append" (flagged on git-mcp-server #42)
- **Template boilerplate**: Generic error guidance unrelated to the tool's domain
- **Too many changes**: Large PRs scare maintainers. Keep to 1-5 tool descriptions per PR.

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
| SpiderRating conversion (MCP) | spiderrating.py (convert, metadata scoring) |
| SpiderRating conversion (Skill) | spiderrating.py (convert_skill, score_skill_description) |
| Agent security patterns | agent/skill_scanner.py (MALICIOUS_PATTERNS list) |
| Agent config checks | agent/scanner.py |
| Toxic flow detection | agent/toxic_flow.py (keyword + AST) |
| LLM rewrite cache | rewriter/cache.py (~/.spidershield/rewrite-cache/) |
| Dataset schema/migration | dataset/db.py (SCHEMA_VERSION, _migrate_vN) |
| Add benchmark server | cli.py (dataset benchmark-add/list/run) |
| Label calibration data | cli.py (dataset calibrate/calibrate-report) |
| Add CLI command | cli.py |
