# Observation 002: Deep Audit & Optimization

**Date**: 2026-03-08
**Trigger**: Pre-launch quality audit -- "cannot lose early users"
**Method**: 3-agent parallel audit (codebase, PR #232, open PR statuses)

## Issues Found & Fixed

### Critical (user-facing trust issues)

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 1 | README scoring weights wrong (40/30/20/10 vs actual 40/35/25/0) | **Critical** | Updated README to match code |
| 2 | PR #232 `list_extensions` said "all installed" but SQL returns available+installed | **Critical** | Fixed to "available...including install status" |
| 3 | PR #232 `pause_project` claimed "stop billing" -- unverified | **Critical** | Removed billing claim |
| 4 | Rewriter ERROR_GUIDANCE contained exact tautological patterns that got 4 PRs rejected | **Critical** | Removed entirely, added anti-tautology note |

### Serious (code quality)

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 5 | Duplicate dict key `"query": "Query"` in VERB_MAP | High | Removed duplicate |
| 6 | Rewriter fallback scenario `"Use when user wants to {name}"` = tautology | High | Removed fallback, scenario only from known SCENARIO_TRIGGERS |
| 7 | Mechanical disambiguation `"Unlike X, specifically handles Y"` | High | Removed template, deleted `_find_similar_tools()` |
| 8 | `prototype_pollution` pattern false positive on `result[key] = value[key]` in JSON.stringify | High | Narrowed to user-input variable names only |
| 9 | `Rating(str, Enum)` deprecated -- should use `StrEnum` | Medium | Changed to `StrEnum` |
| 10 | Unused variables `has_tests`, `has_error_handling` in architecture_check | Medium | Removed |
| 11 | `./tmp_scan/` clone not cleaned up, no error handling | Medium | Use `tempfile.mkdtemp`, add CalledProcessError handling |
| 12 | 51 ruff lint violations | Medium | Fixed to 15 (scanner core: 0) |

### Rewriter Anti-Tautology Tests Added

8 new regression tests encoding exact failure modes from rejected PRs:
- `test_rewrite_no_tautological_scenario` -- blocks "Use when the user wants to {name}"
- `test_rewrite_no_disambiguation_template` -- blocks "Unlike X, specifically handles Y"
- `test_rewrite_no_generic_error_guidance` -- blocks "verify the path is within allowed directories"
- Plus 5 more covering verb handling, duplication, preservation

## Metrics

### Before → After (supabase-mcp scan)

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Security score | 5.0/10 | 7.0/10 | +2.0 (false positive removed) |
| Security issues | 4 | 3 | -1 (prototype_pollution FP eliminated) |
| Overall | 4.8/10 | 5.5/10 | +0.7 |

### Ruff Violations

| Scope | Before | After |
|-------|--------|-------|
| All src/ | 51 | 15 |
| Scanner core | 15 | 0 |

### Test Count

| Before | After |
|--------|-------|
| 18 | 26 (+8 rewriter anti-tautology tests) |

## Lessons Learned

1. **Self-consistency is paramount**: Our rewriter contained the exact patterns that got PRs rejected. If a maintainer ran TeeShield on its own output, they'd see the quality gap.

2. **False positives destroy trust faster than missed detections**: The `[key] = value` prototype pollution pattern fired on safe code in every TS codebase. One false positive in a security report makes users question everything.

3. **README is the API contract**: If README says "Security 30%" but code uses 40%, early users will file issues and lose trust immediately.

4. **PR factual accuracy is non-negotiable**: "stop billing" and "all installed" in PR #232 would have been caught by any Supabase engineer. Domain claims must be verified against the actual code, not assumed.

## Status

- All critical/serious issues fixed
- 26 tests passing
- PR #232 corrected and force-pushed
- Remaining 15 E501 violations are in secondary modules (evaluator, hardener, server) -- cosmetic only
