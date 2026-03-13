# Support

## Python Version Compatibility

| Python | SpiderShield | Status |
|--------|-------------|--------|
| 3.13 | 0.3.x | **Supported** (tested in CI) |
| 3.12 | 0.3.x | **Supported** (tested in CI) |
| 3.11 | 0.3.x | **Supported** (tested in CI, minimum version) |
| 3.10 | -- | Not supported (requires `X | Y` union syntax) |
| < 3.10 | -- | Not supported |

## Optional Dependencies

| Feature | Package | Install |
|---------|---------|---------|
| LLM rewrites (Claude) | `anthropic>=0.40` | `pip install spidershield[ai]` |
| LLM rewrites (OpenAI) | `openai>=1.0` | `pip install spidershield[ai]` |
| LLM rewrites (Gemini) | `google-generativeai>=0.5` | `pip install spidershield[ai]` |
| AST-aware scanning | `semgrep>=1.60` | `pip install spidershield[semgrep]` |
| Development tools | `pytest, ruff, pytest-asyncio` | `pip install spidershield[dev]` |

Core scanning, runtime guard, and DLP work with zero optional dependencies.

## Deprecation Policy

- **Minor versions** (0.x.0): May introduce breaking changes to CLI output format or scoring weights.
  We document all breaking changes in [CHANGELOG.md](CHANGELOG.md).
- **Patch versions** (0.x.y): Bug fixes and documentation only. No breaking changes.
- **Scoring formula changes**: Announced in CHANGELOG.md at least one minor version before enforcement.
  Run `spidershield dataset benchmark-run` to verify your benchmarks still pass.
- **Python version support**: We follow [NEP 29](https://numpy.org/neps/nep-0029-deprecation_policy.html)
  (support Python versions released in the prior 42 months). When we drop a Python version,
  it is announced one minor version in advance.

## Stability Guarantees (pre-1.0)

SpiderShield is pre-1.0. The following are **stable**:

- CLI command names and primary flags (`scan`, `rewrite`, `harden`, `agent-check`, `guard`, `proxy`)
- `SpiderGuard` SDK public API (`check()`, `after_check()`, `Decision`, `InterceptResult`)
- SpiderRating grade scale (F/D/C/B/A) and formula (35/35/30)
- Policy YAML format
- SARIF output schema

The following **may change** between minor versions:

- Scoring weights within the description quality scorer
- Security pattern set (new patterns may be added)
- Internal module structure (do not import from `spidershield.scanner.*` directly)
- Dataset SQLite schema (migrations are automatic)

## Getting Help

- **Bug reports**: [GitHub Issues](https://github.com/teehooai/spidershield/issues)
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) for responsible disclosure
- **Feature requests**: [GitHub Issues](https://github.com/teehooai/spidershield/issues) with `enhancement` label
- **Questions**: [GitHub Discussions](https://github.com/teehooai/spidershield/discussions)

## Release Cadence

We aim for biweekly patch releases and monthly minor releases. Critical security
fixes are released within 7 days of confirmation (see [SECURITY.md](SECURITY.md)).
