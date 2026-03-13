"""Architecture quality checks for MCP servers."""

from __future__ import annotations

import re
from pathlib import Path

# Directories to skip during file scanning
_SKIP_DIRS = {
    "node_modules", "__pycache__", ".venv", "venv", ".git", "dist",
    "build", ".tox", ".mypy_cache", ".next", ".nuxt",
}


def check_architecture(path: Path) -> tuple[float, bool, bool]:
    """Check architecture quality of an MCP server.

    Returns (score, has_tests, has_error_handling).

    Scoring (total = 10.0):
      Tests:          0-3.0  (gradual: count-based)
      Error handling:  0-2.5  (gradual: coverage-based)
      README:         0-1.5  (gradual: length-based)
      Type hints:     0-1.5  (gradual: coverage-based)
      Dependency mgmt: 0-1.0  (has lockfile / requirements)
      Env config:     0-0.5  (has .env.example or config docs)
    """
    source_files = _get_source_files(path)

    test_score, has_tests = _score_tests(path)
    error_score, has_error_handling = _score_error_handling(path, source_files)
    readme_score = _score_readme(path)
    type_score = _score_type_hints(path, source_files)
    dep_score = _score_dependency_management(path)
    env_score = _score_env_config(path)

    total = test_score + error_score + readme_score + type_score + dep_score + env_score

    return round(min(10.0, total), 1), has_tests, has_error_handling


def _get_source_files(path: Path) -> list[Path]:
    """Collect source files, excluding non-source directories."""
    files = []
    for ext in ("*.py", "*.ts", "*.js"):
        for f in path.rglob(ext):
            if any(part in _SKIP_DIRS for part in f.relative_to(path).parts):
                continue
            files.append(f)
    return files


def _score_tests(path: Path) -> tuple[float, bool]:
    """Score test coverage (0-3.0, gradual).

    0 test files = 0.0
    1 test file  = 1.0
    2-4 files    = 2.0
    5+ files     = 3.0
    """
    test_patterns = ["test_*.py", "*_test.py", "*.test.ts", "*.spec.ts", "*.test.js", "*.spec.js"]
    test_dirs = ["tests", "test", "__tests__", "spec"]

    test_file_count = 0
    for pattern in test_patterns:
        test_file_count += len([
            f for f in path.rglob(pattern)
            if not any(part in _SKIP_DIRS for part in f.relative_to(path).parts)
        ])

    # Also check for test directories with files inside
    if test_file_count == 0:
        for dirname in test_dirs:
            test_dir = path / dirname
            if test_dir.exists() and test_dir.is_dir():
                test_file_count += len([
                    f for f in test_dir.rglob("*")
                    if f.is_file() and f.suffix in (".py", ".ts", ".js", ".go")
                    and f.name not in ("__init__.py", "conftest.py")
                ])
                break

    if test_file_count == 0:
        return 0.0, False
    elif test_file_count == 1:
        return 1.0, True
    elif test_file_count <= 4:
        return 2.0, True
    else:
        return 3.0, True


def _score_error_handling(path: Path, source_files: list[Path]) -> tuple[float, bool]:
    """Score error handling coverage (0-2.5, gradual).

    Checks what fraction of source files contain error handling.
    0% = 0.0, 1-25% = 1.0, 25-60% = 1.5, 60%+ = 2.5
    """
    if not source_files:
        return 0.0, False

    files_with_handling = 0
    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        if "try:" in content or "try {" in content or "catch" in content:
            files_with_handling += 1

    ratio = files_with_handling / len(source_files)

    if ratio == 0:
        return 0.0, False
    elif ratio < 0.25:
        return 1.0, True
    elif ratio < 0.6:
        return 1.5, True
    else:
        return 2.5, True


def _score_readme(path: Path) -> float:
    """Score README quality (0-1.5, gradual).

    No README = 0.0
    Short (<200 chars) = 0.5
    Medium (200-1000) = 1.0
    Long (1000+) = 1.5
    """
    for name in ("README.md", "readme.md", "README.rst", "README"):
        readme = path / name
        if readme.exists():
            try:
                length = len(readme.read_text(errors="ignore"))
            except OSError:
                return 0.5  # exists but unreadable
            if length < 200:
                return 0.5
            elif length < 1000:
                return 1.0
            else:
                return 1.5
    return 0.0


def _score_type_hints(path: Path, source_files: list[Path]) -> float:
    """Score type hint coverage (0-1.5, gradual).

    TypeScript project = 1.5 (inherently typed)
    Python: checks fraction of functions with type annotations.
    """
    py_files = [f for f in source_files if f.suffix == ".py"]
    ts_files = [f for f in source_files if f.suffix == ".ts"]

    # Pure TypeScript projects get full score (inherently typed)
    if ts_files and not py_files:
        return 1.5

    if not py_files:
        return 0.0

    files_with_hints = 0
    for py_file in py_files:
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue
        # Check for return type annotations or parameter annotations
        has_return = re.search(r"def \w+\([\s\S]*?\)\s*->", content)
        has_type = re.search(
            r":\s*(?:str|int|float|bool|list|dict|tuple|Path|Optional)\b",
            content,
        )
        if has_return or has_type:
            files_with_hints += 1

    ratio = files_with_hints / len(py_files) if py_files else 0
    if ratio == 0:
        return 0.0
    elif ratio < 0.3:
        return 0.5
    elif ratio < 0.7:
        return 1.0
    else:
        return 1.5


def _score_dependency_management(path: Path) -> float:
    """Score dependency management (0-1.0).

    Checks for lockfiles, requirements files, or package manifests.
    """
    dep_files = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",  # JS
        "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",  # Python
        "pyproject.toml", "setup.py", "setup.cfg",  # Python config
        "package.json",  # JS config
    ]

    found = sum(1 for f in dep_files if (path / f).exists())
    if found == 0:
        return 0.0
    elif found == 1:
        return 0.5  # has manifest but maybe no lockfile
    else:
        return 1.0  # has both manifest and lockfile


def _score_env_config(path: Path) -> float:
    """Score environment configuration (0-0.5).

    Checks for .env.example, .env.template, or documented config.
    """
    env_files = [".env.example", ".env.template", ".env.sample", "env.example"]
    for f in env_files:
        if (path / f).exists():
            return 0.5

    # Check if README mentions environment variables
    for name in ("README.md", "readme.md"):
        readme = path / name
        if readme.exists():
            try:
                content = readme.read_text(errors="ignore")
                env_pat = r"(?:environment|env|config).{0,20}(?:variable|setting|key)"
                if re.search(env_pat, content, re.I):
                    return 0.3
            except OSError:
                pass

    return 0.0
