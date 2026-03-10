# Training Findings -- Local Polish Cycle (2026-03-09)

## Overview

Manual training session covering MCP scan, agent-check, rewrite, and eval modules.
Goal: identify gaps and improve accuracy before submitting more PRs.

Dataset state after session: 61 scans (12 unique targets), 1970 descriptions,
1126 fixes, 34 agent scans (100 findings), 9 PRs tracked.

---

## Finding 1: Quality Gate Scoring Bug (Fixed)

**Problem**: Template rewriter quality gate returned `score=0.0` on rejection.
The `GateResult` model defaults `score` to 0.0, and rejection paths didn't set it.
This made template rewrites appear to *degrade* descriptions (e.g., 2.5 -> 0.8).

**Root cause**: `rewriter/quality_gate.py` had 6 rejection return paths, none
passed `score=orig_score`. The `record_rewrite` collector stored the 0.0 as
`rewritten_score`, polluting the dataset.

**Fix**: Moved `orig_score = _quick_score(original)` to top of function.
All `GateResult(passed=False, ...)` returns now include `score=orig_score`.

**Impact**: Cleaned 24 pytest noise records. Re-ran rewrites showed correct
scores: supabase 2.9->3.0, mcp-official 2.8->3.3, sdk 2.1->2.2.

---

## Finding 2: Heuristic Evaluator Accuracy (47% -> 87%)

**Problem**: Naive keyword matching in `evaluator/runner.py` scored poorly on
tool selection tasks. Common words like "the", "a", "get" matched everywhere,
and camelCase tool names weren't split.

**Improvements applied**:
1. **Stopword filtering**: 40+ common words excluded from matching
2. **IDF weighting**: `idf = log(N / (df + 1)) + 1` -- rare words score higher
3. **Verb synonym mapping**: "get" matches retrieve/fetch/show; "list" matches show/get
4. **camelCase splitting**: `postgrestRequest` -> `postgrest request`
5. **Verb alignment bonus**: +4.0 when tool name's leading verb matches intent verb family

**Result**: 47% -> 87% on test suite (15 scenarios x 1 model).

---

## Finding 3: Auto-Generated Eval Scenarios Are Too Simplistic

**Problem**: `_auto_generate_scenarios()` creates intents like
"I want to use the list_tables functionality". These trivially match by name,
giving 100% accuracy on original descriptions but penalizing LLM-rewritten
descriptions that add rich context (dilutes the name-matching signal).

**Evidence**: LLM rewrite on SDK tools: 97.1% -> 87.4% (decrease!).
Template rewrite: 86.7% -> 86.7% (no change -- template adds so little text).

**Lesson**: Realistic eval scenarios must describe the *task*, not the *tool name*.
Good: "Show me all database tables and their row counts"
Bad: "I want to use the list_tables functionality"

**Action needed**: Hand-craft realistic scenario sets per domain (database, git,
file system, API). Store in `test-targets/eval-scenarios/`.

---

## Finding 4: Template Rewriter Has Low Ceiling (~3.0/10)

**Problem**: Template rewriter can only prepend a verb and append parameter hints.
It cannot add scenario triggers, error guidance, or domain-specific context.
Maximum achievable score is approximately 3.0/10.

**Evidence**:
- supabase: 2.9 -> 3.0 (template)
- mcp-official: 2.8 -> 3.3 (template)
- sdk: 2.1 -> 2.2 (template)

Template transformations:
- Adds verb prefix: "List all X" -> "Lists all X. Use when..."
- Adds parameter hints: "Requires `table_name`, `query`."
- Cannot add: error conditions, side effects, scope boundaries, examples

**Conclusion**: Template rewrite is only useful as a baseline/fallback.
LLM rewrite is needed for meaningful quality improvement. Hand-crafted
descriptions remain the gold standard for PR submissions.

---

## Finding 5: Tool Extraction Gaps

**Problem**: Tool extraction only works for:
- Python: `@server.tool()` / `@mcp.tool()` decorator patterns
- TypeScript: specific `server.tool()` / `tool()` patterns

**Fails on**:
- Go servers (github-mcp-server): compiled, no source patterns
- Compiled TypeScript (playwright-mcp): bundled JS, patterns lost
- Servers using non-standard registration (manual JSON schemas)

**Impact**: `spidershield scan` reports 0 tools for these servers, making
description scoring impossible. Security scan and architecture check still work.

**Mitigation options** (not yet implemented):
1. Parse MCP `tools/list` JSON output instead of source code
2. Add Go AST extraction (function comments + MCP registration)
3. Accept pre-extracted tool JSON as input (`--tools-json`)

---

## Finding 6: `os.environ` AST Detection Gap (Fixed)

**Problem**: Toxic flow analysis missed `dict(os.environ)` and
`os.environ.items()` because `os.environ` resolves to `ast.Attribute`
(not Call or Subscript). The `_FlowVisitor` only had `visit_Call` and
`visit_Subscript` handlers.

**Fix**: Added `visit_Attribute` method with `_is_os_environ()` helper.
Refactored `visit_Subscript` to reuse the same helper.

**Tests added**: 3 new tests in `test_toxic_flow.py`:
- `test_dict_os_environ`: detects `dict(os.environ)` + `requests.post()`
- `test_os_environ_items`: detects `os.environ.items()` + `requests.post()`
- `test_os_environ_no_sink_safe`: no false positive without sink

---

## Agent-Check Test Scenarios Created

8 scenarios in `test-targets/agent-scenarios/` with ground truth:

| Scenario | Score Range | Key Detections |
|----------|------------|----------------|
| secure | 7-10 | sandbox.not_configured only |
| insecure | 0-3 | gateway.bind, gateway.no_auth, sandbox |
| partial | 6-9 | sandbox.not_configured only |
| with-skills | 2-5 | TS-W004, TS-E005/E006/E008/E014, TS-W006 |
| prompt-injection | 4-7 | TS-E005, TS-E007 |
| typosquat | 5-8 | TS-W007 x2 |
| exfil-ast | 5-8 | TS-W009 (toxic flow) |
| multi-vector | 0-1 | All config issues + TS-E002/E005/E006/E008 + TS-W004/W006 |

Ground truth file: `test-targets/agent-scenarios/ground-truth.yaml`

---

## Optimization Plan (2026-03-09)

### P0: Immediate (small effort, high impact) -- ALL DONE

**1. `--tools-json` input support** -- DONE (Finding 7a)

**2. LLM rewrite cache layer** -- DONE (Finding 7b)

**3. `temperature=0` for LLM providers** -- DONE (Finding 7c)

### P1: Short-term (medium effort, medium impact)

**4. Expand domain scenario templates**
- Problem: Template rewriter only has ~10 scenario triggers, ceiling ~3.0/10
- Solution: Expand to 50+ scenarios (database, git, network, auth, cloud, etc.)
- Also add disambiguation: "Unlike {sibling}, this tool..."
- Target: template ceiling 3.0 -> 4.5/10

**5. Hand-craft eval scenarios**
- Problem: Auto-generated "I want to use X" scenarios have name-matching bias
- Solution: Domain-specific realistic task descriptions
- Store in `test-targets/eval-scenarios/`

### P2: Medium-term (medium effort, lower priority)

**6. Parameter-driven example generation**
- Infer example values from `inputSchema` types and names
- Generate error guidance from `required` parameters
- Target: template ceiling 4.5 -> 6.0/10

**7. Ollama local model support**
- Add local LLM provider for offline rewriting
- Quality lower than cloud, but zero cost + full offline

**8. Automated ground-truth validation**
- Script to run agent-check on all 8 scenarios vs ground-truth.yaml
- CI integration for regression detection

## Finding 7: P0 Optimizations Implemented

### 7a: `--tools-json` Input Support (Implemented)

**Problem**: Tool extraction only worked for Python/TypeScript source patterns.
Go servers (github-mcp-server) and compiled TypeScript (playwright-mcp) reported
0 tools, making description scoring impossible.

**Solution**: Added `--tools-json` flag to `scan`, `rewrite`, and `eval` commands.
Accepts MCP `tools/list` JSON or rewrite output format.

**Changes**:
- `cli.py`: `--tools-json` option on scan/rewrite/eval commands
- `scanner/description_quality.py`: `load_tools_json()` function + `tools_json`
  parameter on `score_descriptions()`
- `evaluator/runner.py`: `tools_json` parameter threaded through `run_eval()`,
  `_auto_generate_scenarios()`, `_load_tools()`, `_evaluate_server()`

**Tests**: Existing tests pass. Cache/eval tests updated to use `use_cache=False`
where needed.

### 7b: LLM Rewrite Cache Layer (Implemented)

**Problem**: LLM rewrites are non-deterministic and costly. Same tool description
rewritten twice produces different output, violating G0 reproducibility spirit.

**Solution**: SHA-256 cache keyed on `(tool_name, original_desc, model)`.
- Location: `~/.spidershield/rewrite-cache/{hash}.json`
- `--no-cache` flag to force refresh
- Cache hit = free + offline + deterministic

**Changes**:
- `rewriter/cache.py` (NEW): `cache_key()`, `get_cached()`, `set_cached()`,
  `clear_cache()`
- `rewriter/runner.py`: `_rewrite_llm()` checks cache before LLM call,
  stores result after. `use_cache` parameter added.
- `tests/test_rewrite_cache.py` (NEW): 7 tests (key determinism, roundtrip,
  miss, clear)
- `tests/test_rewriter_v2.py`: 3 retry tests use `use_cache=False` to
  prevent cache interference with call counting

### 7c: `temperature=0` for LLM Providers (Implemented)

**Problem**: Same input produces different rewrites across runs due to
default temperature sampling.

**Solution**: Set `temperature=0` on all 3 provider calls.

**Changes**:
- `rewriter/providers.py`: Added `temperature=0` to Anthropic
  `messages.create()`, OpenAI `chat.completions.create()`, and Gemini
  `generate_content()` config.
- Not 100% deterministic (model updates change output), but dramatically
  reduces variance. Combined with cache layer, repeat runs are fully
  deterministic.

---

## Finding 8: SpiderRating Scoring Unification (Implemented)

**Problem**: SpiderShield used a custom scoring model (security 40% + desc 35% + arch 25%,
grades F/C/B/A/A+) that diverged from the SpiderRating standard used by the ecosystem.
This created friction when converting scan output for SpiderRating consumers and led to
code duplication between `scanner/runner.py` and `scripts/spidershield_to_spiderrating.py`.

**Changes**:
1. Rating enum: F/C/B/A/A+ → F/D/C/B/A (added D=Deficient, removed A+=A_PLUS)
2. Scoring formula: `desc*0.35 + security_adjusted*0.35 + arch*0.30`
3. Architecture bonus: `min(3.0, arch_score * 0.3)` folds into security
4. Low severity penalty: -0.5 → -0.25 (SpiderRating standard)
5. Hard constraints: critical→F, no_tools→F, license_banned→D cap
6. Grade thresholds: A≥8.5, B≥7.0, C≥5.0, D≥3.0, F<3.0
7. `spiderrating.py` library module: canonical conversion logic
8. `scripts/spidershield_to_spiderrating.py`: 458→99 lines (import wrapper)

**Design decisions**:
- Architecture bonus cap 3.0 (not 2.0) for more granular signal
- Metadata dimension (GitHub API) is optional, only for `--format spiderrating`
  — preserves G0 "no network-dependent scoring"
- Internal scan formula uses architecture directly (no GitHub API needed)

**Tests**: All 356 tests pass (34 new SpiderRating + cache tests).
`test_score_weights` and `test_rating_thresholds` updated to match new
formula and grade boundaries.

---

## Finding 9: Skill SpiderRating Conversion (Implemented)

**Problem**: SpiderRating conversion only worked for MCP server scans
(`convert()`). Agent-check skill findings had no SpiderRating output path.

**Solution**: Added `convert_skill()` and supporting functions to
`spiderrating.py` for agent-check → SpiderRating conversion.

**Changes**:
- `spiderrating.py`: `convert_skill()`, `score_skill_description()`,
  `skill_security_from_findings()`
- `score_skill_description()`: 5-dimension scoring for SKILL.md content
  (same dimensions as MCP tools: intent_clarity, permission_scope,
  side_effects, capability_disclosure, operational_boundaries)
- `skill_security_from_findings()`: maps SkillVerdict → security penalty
  (MALICIOUS=-3, SUSPICIOUS=-1, TAMPERED=-2)
- `cli.py`: `spidershield agent-check --format spiderrating` output path

---

## Stability Baseline (2026-03-09)

Pre-optimization baseline (before P0 work):

| Module | Metric | Value | Deterministic? |
|--------|--------|-------|----------------|
| Tests | Pass rate | 322/322 (100%) | Yes |
| MCP Scan | mcp-official issues | 3 (1H, 2M) | Yes |
| MCP Scan | supabase issues | 3 (3M) | Yes |
| Heuristic Eval | supabase accuracy | 94.9% | Yes |
| Agent-check | 8/8 ground truth | All in range | Yes |
| Template Rewrite | supabase score | 2.9->3.0 | Yes |
| Template Rewrite | mcp-official score | 2.8->3.3 | Yes |
| LLM Rewrite | Depends on API | Variable | No -> P0 fix |

Post-optimization baseline (after P0 + SpiderRating unification):

| Module | Metric | Value | Deterministic? |
|--------|--------|-------|----------------|
| Tests | Pass rate | 356/356 (100%) | Yes |
| Coverage | CI threshold | 62% (>60%) | Yes |
| Scoring | SpiderRating unified | 35/35/30 | Yes |
| Grades | F/D/C/B/A | 3.0/5.0/7.0/8.5 | Yes |
| LLM Rewrite | With cache | Deterministic | Yes (cache hit) |
| LLM Rewrite | Without cache | temperature=0 | Nearly (model-dependent) |

---

## Finding 10: Data Flywheel Infrastructure (Implemented)

**Problem**: Scan results were stored as flat records with no versioning,
no temporal tracking, and no way to measure scoring accuracy over time.
This blocked building a data moat: we couldn't tell if scoring changes
improved or degraded accuracy, and couldn't track server health trends.

**Solution**: Schema v4 migration with 6 new tables and enriched metadata:

1. **scoring_versions** -- Track scoring formula changes with semantic versioning
2. **server_timeline** -- Denormalized temporal view with precomputed deltas
3. **pattern_effectiveness** -- Track false positive rates per pattern
4. **scoring_calibration** -- Predicted vs ground truth ratings for accuracy
5. **benchmarks** -- Known-good/bad servers for regression testing
6. **pr_scan_links** -- Connect scan results to PR outcomes

**Enriched existing tables**:
- `scans` +5 columns: scoring_version, scanner_version, pattern_set_hash,
  scan_duration_ms, source_type
- `security_issues` +3 columns: pattern_name, false_positive, reviewed_at
- `agent_findings` +2 columns: false_positive, reviewed_at

**New CLI commands**:
- `spidershield dataset benchmark-add/list/run` -- Register and verify benchmarks
- `spidershield dataset calibrate` -- Label scans with ground truth ratings
- `spidershield dataset calibrate-report` -- Measure scoring accuracy

**Scanner integration**: `run_scan_report()` now computes scan_duration_ms
and pattern_set_hash. `run_scan()` passes scoring_version, pattern metadata,
and source_type to `record_scan()`. Each scan auto-inserts timeline and
calibration entries.

**Flywheel mechanics**:
- More scans -> better pattern effectiveness data -> fewer false positives
- Calibration labels -> scoring accuracy measurement -> formula improvements
- Benchmarks -> regression detection -> confidence in changes
- Timeline deltas -> before/after proof for PR campaigns

**Impact**: 641 tests passing. Schema v4 migration is backward-compatible
(auto-migrates from v3). All new columns have defaults, so existing data
is preserved.

---

## Finding 11: SDK Runtime Guard Telemetry (Implemented)

**Problem**: The data flywheel only covered static analysis (`spidershield scan`).
Runtime guard (`SpiderGuard.check()`) wrote to JSONL audit logs but NOT to
the SQLite dataset. This meant:
- No runtime decision data for pattern effectiveness analysis
- No deny/escalate statistics for policy tuning
- No PII detection rates for DLP improvement
- The SDK sensor network was silent to the flywheel

**Solution**: Schema v5 migration with 2 new tables + SDK wiring:

1. **guard_events** -- Every `before_call()` decision and `after_call()` DLP
   finding. Fields: tool_name, decision, reason, policy_matched, pii_types,
   policy_preset, framework, environment.
2. **guard_sessions** -- Aggregated per-session summaries. UPSERT on every
   event: total_calls, allowed, denied, escalated, pii_detections.

**Wiring**:
- `RuntimeGuard.__init__()` accepts `dataset=True` and `policy_preset`
- `_record_before()` and `_record_after()` call `_record_to_dataset()`
  when dataset is enabled
- `_record_to_dataset()` is wrapped in try/except (best-effort, never
  fails the guard check)
- `SpiderGuard.__init__()` exposes `dataset=True` kwarg

**Design decisions**:
- **opt-in** (`dataset=False` default): Zero overhead for users who don't
  want telemetry. No surprise disk writes.
- **best-effort**: SQLite failures are silently swallowed. Guard decisions
  must never depend on dataset writes succeeding.
- **auto-aggregation**: Session table uses UPSERT, no batch jobs needed.
- **dual logging**: JSONL audit (human-readable, streaming) + SQLite
  (queryable, aggregatable) coexist independently.

**Usage**:
```python
# Before: no data accumulation
guard = SpiderGuard(policy="balanced")

# After: every check feeds the flywheel
guard = SpiderGuard(policy="balanced", dataset=True)
```

**Impact**: 647 tests passing. Schema v5 auto-migrates from v4.
`get_stats()` now includes guard_events, guard_denied, guard_sessions.

**Flywheel completion**:
```
Static scan ─┐
             ├─→ SQLite dataset ─→ Pattern tuning + scoring calibration
Runtime guard┘
```
Both data sources now feed the same flywheel. The SDK is a sensor.
