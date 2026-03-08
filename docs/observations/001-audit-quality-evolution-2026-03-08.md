# Obs 001: Audit Quality Evolution -- From v0.1 to v0.2

> Date: 2026-03-08
> Theme: Systematic audit of TeeShield's 4-stage scanner quality, with evidence-driven improvements
> Reference: teehoo Obs 93 (Evolvable Research Methodology), fullhouse-asset EvolutionEngine, teehoo Obs 119 (Self-Improvement Audit)

---

## $1 Evolution Framework

TeeShield adopts a **three-layer evolution architecture** (adapted from teehoo Obs 93):

```
Layer 0: Evidence Collection
  | Scan real MCP servers, collect ground-truth findings
  v
Layer 1: Scanner Calibration
  | Compare scanner output vs ground truth, measure false positive/negative rates
  v
Layer 2: Scoring Model
  | Adjust weights, thresholds, and criteria based on calibration data
  ^
  | Feedback loop: PR campaign feedback, maintainer responses, community input
```

### Core Properties (from Obs 93 $1.2)

- **Robust**: Same server scanned twice produces identical results
- **Evolvable**: Each iteration documents what changed and why
- **Self-correcting**: Scanner bugs discovered via real-world scanning feed back into improvements

---

## $2 Current State Audit (v0.1.3)

### 2.1 Description Quality Scanner

| Criterion | v0.1.3 State | Issue | Severity |
|-----------|-------------|-------|----------|
| Action verb detection | MISSING | No check for imperative mood opening | HIGH |
| Scenario trigger | Regex-only | Only matches "use when/use for/call this" | MEDIUM |
| Parameter examples | Regex-only | Checks for "e.g." etc., misses backtick params | MEDIUM |
| Parameter documentation | MISSING | No check for param docs at all | HIGH |
| Error guidance | Regex-only | OK but could miss structured error sections | LOW |
| Disambiguation | Word overlap | Uses raw word overlap, no stop-word filtering | HIGH |
| Length scoring | Basic | Only 4 buckets, no mid-range nuance | LOW |
| Scoring weights | Unbalanced | disambiguation+length = 3.5/10 base even with 0 quality signals | CRITICAL |

**Evidence**: PR #277 (ida-pro-mcp) REJECTED because template rewrites added tautological scenario triggers.
**Evidence**: PR #42 (git-mcp-server) flagged by Codex Review for semantic mismatches (git_add -> "append to collection").

**Root Cause**: Scoring gives inflated scores to descriptions that are actually poor quality.

### 2.2 Security Scanner

| Pattern | v0.1.3 State | Issue | Severity |
|---------|-------------|-------|----------|
| command_injection | Includes exec/eval | exec/eval are different from shell injection | MEDIUM |
| credential_exposure | Too broad | Flags `os.environ.get("API_KEY")` which is standard practice | HIGH |
| no_input_validation | Too broad | Matches any function with `str` param, not just MCP handlers | HIGH |
| unsafe_deserialization | MISSING | No check for pickle.load, yaml.load, etc. | HIGH |
| Scoring | Linear penalty | One critical = -3.0, but doesn't scale well | LOW |

**Evidence**: Scanning real servers produces false positives on credential_exposure for every server that reads env vars.

### 2.3 Architecture Checker

| Check | v0.1.3 State | Issue | Severity |
|-------|-------------|-------|----------|
| Tests | Boolean only | "Has tests" gives full 3.0 even with 1 test file | MEDIUM |
| Error handling | Boolean only | Any single try/catch = full 3.0 | MEDIUM |
| README | Boolean only | Exists = full 2.0, no quality check | LOW |
| Type hints | Boolean only | Any TS file = full 2.0 | LOW |
| Missing checks | N/A | No CI/CD, no linting, no dependency management check | LOW |

### 2.4 Report Output

| Issue | Severity |
|-------|----------|
| Per-tool scores generated but not displayed in table | HIGH |
| Recommendations are generic ("Run teeshield rewrite") | MEDIUM |
| No color coding for score ranges | LOW |
| Security issues truncated at 10, no severity sorting | LOW |

---

## $3 v0.2 Evolution: Changes Applied

### 3.1 Description Quality (DONE)

- [x] Added `has_action_verb` check (imperative mood detection with 50+ verbs)
- [x] Added `has_param_docs` check (param/input/argument mentions + backtick detection)
- [x] Added stop-word filtering for disambiguation (words in >50% of tools excluded)
- [x] Recalibrated scoring weights:
  - action_verb: 1.5 (was 0)
  - scenario: 3.0 (unchanged, most important)
  - param_docs: 1.5 (new)
  - examples: 1.5 (was 2.0)
  - error_guidance: 1.0 (was 1.5)
  - disambiguation: 1.0 (was 2.0, reduced -- too much free score)
  - length: 0.5 (was 1.5, reduced -- too much free score)
- [x] Added mid-range length bucket (50-80 chars = 0.7)

### 3.2 Security Scanner (DONE)

- [x] Split `exec/eval` into separate `dangerous_eval` category (only flags non-literal args)
- [x] Narrowed `credential_exposure` -> `hardcoded_credential` (only hardcoded strings, not env vars)
- [x] Added `unsafe_deserialization` (pickle, yaml.load, marshal, shelve)
- [x] Narrowed `no_input_validation` to MCP tool handler functions only (@tool, @server.tool)

### 3.3 Report Output (DONE)

- [x] Per-tool description score table with Y/N columns for each criterion
- [x] Color-coded scores (green >= 8, yellow >= 5, red < 5)
- [x] Severity-colored security issues with fix suggestions
- [x] Actionable recommendations with worst-tool names and missing-criteria counts

### 3.4 Remaining Gaps (TODO)

- [ ] Architecture checker: gradual scoring instead of binary
- [ ] Architecture checker: add CI/CD detection, dependency management, .env.example
- [ ] Security scanner: TypeScript-specific patterns (prototype pollution, require injection)
- [ ] Security scanner: context-aware analysis (is the flagged code in a tool handler?)
- [ ] Description quality: handle multi-language descriptions (non-English)
- [ ] Scoring calibration: validate against ground-truth dataset of known-quality servers
- [ ] Rewriter: context-aware scenario triggers (not keyword-based)

---

## $4 Evolution Cycle Protocol

Adapted from teehoo Obs 93 and fullhouse-asset EvolutionEngine:

### 4.1 Per-Release Cycle

```
1. SCAN: Run teeshield on 10+ diverse MCP servers
2. AUDIT: Manual review of scan results vs reality
3. MEASURE: Calculate false positive rate, false negative rate
4. CALIBRATE: Adjust patterns, weights, thresholds
5. VALIDATE: Re-scan and confirm improvement
6. DOCUMENT: Update this observation with evidence
```

### 4.2 Metrics to Track

| Metric | Target | Current |
|--------|--------|---------|
| False positive rate (security) | < 10% | ~30% (credential_exposure) |
| False negative rate (security) | < 5% | Unknown |
| Description score correlation with actual quality | > 0.7 | ~0.5 (estimated) |
| Tools extracted / tools actual | > 90% | ~85% |
| PR acceptance rate | > 50% | 33% (2/6 closed) |

### 4.3 Residual Analysis (from teehoo Obs 69C)

For each scanner category, track the "residual" -- the gap between our score and expert assessment:

```
residual = |scanner_score - expert_score| / 10.0

0.0-0.1: WELL_CALIBRATED (scanner matches reality)
0.1-0.3: ACCEPTABLE (minor disagreement)
0.3-0.5: NEEDS_CALIBRATION (significant gap)
0.5+:    BROKEN (scanner is misleading)
```

---

## $5 Self-Improvement Infrastructure

### 5.1 What Works (from teehoo Obs 119)

- **Rules files** (`.claude/rules/*.md`) -- auto-loaded, most reliable enforcement
- **CLAUDE.md** -- auto-loaded, good for project-level standards
- **Memory files** -- MEMORY.md auto-loaded (first 200 lines), topic files need manual read

### 5.2 What Doesn't Work

- Text instructions without hook enforcement (pure "please do X" directives)
- Skills files (not auto-loaded)
- Diary system (Stop hook unreliable)

### 5.3 TeeShield Implementation

For TeeShield we adopt the minimum viable self-improvement:
1. **CLAUDE.md** -- project rules, evolution mode protocol, hard constraints
2. **MEMORY.md** -- cross-session memory (auto-loaded)
3. **docs/observations/** -- evolution documentation (read on demand)
4. **Rules** -- scanner-specific rules in `.claude/rules/`

---

## $6 Version History

| Version | Date | Changes |
|---------|------|---------|
| v0.1.0 | 2026-03-01 | Initial 4-stage scanner |
| v0.1.1 | 2026-03-03 | Unicode cleanup |
| v0.1.2 | 2026-03-04 | TypeScript extraction |
| v0.1.3 | 2026-03-05 | MCP server mode + Dockerfile |
| v0.2.0 | 2026-03-08 | Evolution: audit quality overhaul (this document) |
