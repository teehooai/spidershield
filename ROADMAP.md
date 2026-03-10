# SpiderShield Roadmap

## v0.1 (completed)

- [x] 4-stage scanner (license, security, descriptions, architecture)
- [x] Template-based rewriter (zero API cost)
- [x] Claude API rewriter (optional, higher quality)
- [x] Auto-apply rewrites to source files
- [x] GitHub Action for CI integration
- [x] MCP server mode + Dockerfile
- [x] Python 3.11 / 3.12 / 3.13

## v0.2 (completed)

- [x] Description scoring: 7-criteria model (verb, scenario, params, examples, errors, disambiguation, length)
- [x] Security scanner: reduced false positives (narrowed credential/eval/input patterns)
- [x] Security scanner: TypeScript-specific patterns (prototype pollution, child_process, etc.)
- [x] Security scanner: unsafe deserialization detection (pickle, yaml.load, marshal)
- [x] Architecture checker: gradual scoring (count/coverage-based instead of binary)
- [x] Architecture checker: dependency management and env config checks
- [x] Report: per-tool description quality table
- [x] Report: color-coded scores and actionable recommendations
- [x] Evolution mode: observation-based improvement tracking
- [x] Agent security checker: 18 config checks, 15 malicious patterns
- [x] Toxic flow analysis: data source + public sink detection
- [x] Skill pinning: SHA-256 content hashing for rug pull detection
- [x] Allowlist mode: approved-only skills enforcement
- [x] SARIF output: GitHub Code Scanning compatible
- [x] 46 standardized issue codes (TS-E/W/C/P)

## v0.3 (current)

- [x] Runtime Guard SDK: pre/post-execution policy enforcement
- [x] Policy presets: strict / balanced / permissive + custom YAML
- [x] DLP engine: PII/secret detection and redaction in tool outputs
- [x] Audit logging: structured audit trail to disk
- [x] MCP Proxy: transparent guard between agent and server
- [x] SpiderRating formula: desc*0.35 + security*0.35 + arch*0.30
- [x] Data flywheel: SQLite dataset for scoring calibration
- [x] Dataset CLI: benchmark-add, benchmark-run, calibrate, calibrate-report
- [x] SDK telemetry: opt-in guard event recording to local dataset
- [ ] Go language support
- [ ] Compiled JS support (for bundled servers)

## v0.4

- [ ] Badge service for README shields
- [ ] Curation leaderboard for MCP ecosystem
- [ ] GitHub Marketplace Action
- [ ] Web UI for online scanning
- [ ] API endpoint (POST /scan with GitHub URL)

## Future

- [ ] Auto-PR: scan + rewrite + submit improvement PRs
- [ ] Context-aware rewriter (LLM-powered scenario triggers)
- [ ] Multi-language DLP patterns (i18n PII detection)
- [ ] Runtime anomaly detection (behavioral baselines)
