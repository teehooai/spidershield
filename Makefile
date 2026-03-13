# SpiderShield development Makefile
# Run `make help` to see available targets.

.PHONY: help install dev test lint typecheck verify-oss bench coverage clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install spidershield (production)
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

test: ## Run test suite
	pytest tests/ -v --tb=short

lint: ## Run ruff linter
	ruff check src/ tests/

typecheck: ## Run pyright type checker
	pyright src/spidershield/

bench: ## Run performance benchmarks only
	pytest tests/test_bench_scanner.py -v --tb=short

coverage: ## Run tests with coverage report
	pytest tests/ -v --cov=spidershield --cov-report=term-missing --cov-fail-under=75

verify-oss: ## One-command open-source readiness verification
	@echo "=== SpiderShield OSS Verification ==="
	@echo ""
	@echo "1/6 Install (editable)..."
	pip install -e ".[dev]" -q
	@echo "    OK"
	@echo ""
	@echo "2/6 CLI smoke test..."
	spidershield --version
	spidershield --help > /dev/null
	@echo "    OK"
	@echo ""
	@echo "3/6 Lint..."
	ruff check src/ tests/
	@echo "    OK"
	@echo ""
	@echo "4/6 Type check..."
	pip install pyright -q
	pyright src/spidershield/
	@echo "    OK"
	@echo ""
	@echo "5/6 Tests (with coverage)..."
	pytest tests/ -q --cov=spidershield --cov-fail-under=75
	@echo "    OK"
	@echo ""
	@echo "6/6 Example scan..."
	spidershield scan examples/insecure-server --format json > /dev/null
	@echo "    OK"
	@echo ""
	@echo "=== ALL 6 CHECKS PASSED ==="

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
