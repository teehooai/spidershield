# Changelog

All notable changes to SpiderShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- DLP engine now preserves dict/list structure during redaction/masking
- Semgrep results now respect directory exclusion rules and monorepo scoping
- Tool name deduplication uses O(1) set lookup instead of O(n) list scan

### Added
- SECURITY.md with vulnerability disclosure policy
- CONTRIBUTING.md with development setup guide
- CODE_OF_CONDUCT.md (Contributor Covenant 2.1)
- conftest.py with shared test fixtures
- pyright type checking in CI pipeline
- `[project.urls]` in pyproject.toml for PyPI discoverability
- Centralized `BANNED_LICENSES` in scoring_spec.py
- Guard/firewall tests expanded from 22 to 40 cases
- `.pre-commit-config.yaml` with ruff, pyright, and standard hooks
- `docs/decisions/banned-licenses.md` documenting license ban rationale
- Performance benchmark tests for scanner pipeline (7 tests)
- SUPPORT.md with Python version matrix, deprecation policy, and stability guarantees
- Makefile with `make verify-oss` one-command OSS validation
- README "5-Minute Success Path" quickstart section
- `.github/CODEOWNERS` for automatic review routing
- `.github/ISSUE_TEMPLATE/` with bug report and feature request forms
- `.github/pull_request_template.md` with checklist

### Changed
- CI coverage floor raised from 60% to 75%
- `@_safe_record` decorator now uses `@functools.wraps`
- `_extract_tools()` refactored into per-language functions (`_extract_python_tools`, `_extract_ts_tools`, `_extract_go_tools`, `_extract_rust_tools`) with shared `_add_tool` helper
- CLI extracted from monolithic `cli.py` (1,359 LOC) into `commands/` subpackage (9 modules + thin orchestrator)
- `classify_capabilities()` in toxic_flow.py collapsed from 3 identical loops to shared `_match_keywords()` helper

## [0.3.1] - 2026-03-12

### Fixed
- All ruff lint errors resolved (E501, N806, unused imports)

## [0.3.0] - 2026-03-11

### Added
- Go language support for rewriter patcher + MustTool scanner pattern
- Rewriter v2.5 with mandatory disambiguation boundary + three-layer verification
- GitHub Actions deploy workflow for website
- SpiderShield official website (Next.js static export)

## [0.2.0] - 2026-03-08

### Changed
- Description quality: added `has_action_verb` and `has_param_docs` checks
- Description quality: recalibrated scoring weights (reduced disambiguation/length inflation)
- Security scanner: split exec/eval into `dangerous_eval` category
- Security scanner: narrowed `credential_exposure` to `hardcoded_credential`
- Security scanner: added `unsafe_deserialization` pattern
- Report output: per-tool description score table with color coding

## [0.1.3] - 2026-03-05

### Added
- MCP server mode + Dockerfile

## [0.1.2] - 2026-03-04

### Added
- TypeScript tool extraction

## [0.1.1] - 2026-03-03

### Fixed
- Unicode cleanup

## [0.1.0] - 2026-03-01

### Added
- Initial 4-stage scanner (license, security, description, architecture)
- CLI with scan, rewrite, harden, eval commands
- SpiderRating format conversion
- Agent security audit (config checks, skill scanning, toxic flow detection)

[Unreleased]: https://github.com/teehooai/spidershield/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/teehooai/spidershield/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/teehooai/spidershield/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/teehooai/spidershield/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/teehooai/spidershield/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/teehooai/spidershield/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/teehooai/spidershield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/teehooai/spidershield/releases/tag/v0.1.0
