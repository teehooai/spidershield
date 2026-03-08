# TeeShield Roadmap

## v0.1

- [x] 4-stage scanner (license, security, descriptions, architecture)
- [x] Template-based rewriter (zero API cost)
- [x] Claude API rewriter (optional, higher quality)
- [x] Auto-apply rewrites to source files
- [x] GitHub Action for CI integration
- [x] MCP server mode + Dockerfile
- [x] Python 3.11 / 3.12 / 3.13

## v0.2 (Current)

- [x] Description scoring: 7-criteria model (verb, scenario, params, examples, errors, disambiguation, length)
- [x] Security scanner: reduced false positives (narrowed credential/eval/input patterns)
- [x] Security scanner: TypeScript-specific patterns (prototype pollution, child_process, etc.)
- [x] Security scanner: unsafe deserialization detection (pickle, yaml.load, marshal)
- [x] Architecture checker: gradual scoring (count/coverage-based instead of binary)
- [x] Architecture checker: dependency management and env config checks
- [x] Report: per-tool description quality table
- [x] Report: color-coded scores and actionable recommendations
- [x] Evolution mode: observation-based improvement tracking
- [ ] Go language support
- [ ] Compiled JS support (for bundled servers)

## v0.3

- [ ] Badge service for README shields
- [ ] Curation leaderboard for MCP ecosystem
- [ ] GitHub Marketplace Action
- [ ] Scoring calibration against ground-truth dataset

## Future

- [ ] Web UI for online scanning
- [ ] API endpoint (POST /scan with GitHub URL)
- [ ] Auto-PR: scan + rewrite + submit improvement PRs
- [ ] Context-aware rewriter (LLM-powered scenario triggers)
