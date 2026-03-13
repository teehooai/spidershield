# Contributing to SpiderShield

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/teehooai/spidershield
cd spidershield

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Verify installation
spidershield --version
```

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=spidershield --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanner.py -v

# Run a specific test
pytest tests/test_scanner.py::test_security_benchmarks_excluded -xvs
```

## Linting

```bash
# Check for lint errors
ruff check src/ tests/

# Auto-fix lint errors
ruff check src/ tests/ --fix
```

## Quick Verification (all gates)

```bash
ruff check src/ tests/ && pytest tests/ -q --cov=spidershield --cov-fail-under=75
```

## Common Tasks

| Task | Where to look |
|------|--------------|
| Add a security pattern | `src/spidershield/scanner/security_scan.py` (`DANGEROUS_PATTERNS` dict) |
| Add a description criterion | `src/spidershield/scanner/description_quality.py` + `models.py` |
| Change scoring weights | `src/spidershield/scoring_spec.py` |
| Add an agent malware pattern | `src/spidershield/agent/skill_scanner.py` (`MALICIOUS_PATTERNS`) |
| Add a CLI command | `src/spidershield/cli.py` |
| Add a guard policy preset | `src/spidershield/guard/presets/` (YAML) |
| Add a DLP detector | `src/spidershield/dlp/` (pii.py, secrets.py, prompt_injection.py) |

## Pull Request Guidelines

1. **Keep PRs focused** -- one feature or fix per PR.
2. **Add tests** for new functionality.
3. **Run `ruff check`** before submitting -- CI will reject lint failures.
4. **Update docstrings** if you change function signatures.
5. **Don't break existing tests** -- 726 tests must pass.

## Code Style

- Python 3.11+ with type hints on all new functions
- Pydantic V2 for data models
- Rich console for CLI output
- Line length: 130 characters (configured in `pyproject.toml`)
- Follow existing patterns in the codebase

## Architecture Overview

See [CLAUDE.md](CLAUDE.md) for the full architecture map, scoring formula,
hard constraints, and key files table.

## Reporting Issues

- **Bugs**: Open a GitHub Issue with reproduction steps
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md)
- **Feature requests**: Open a GitHub Issue with use case description
