"""Tests for the scanner module."""

from pathlib import Path

from teeshield.scanner.license_check import check_license
from teeshield.scanner.security_scan import scan_security
from teeshield.scanner.description_quality import score_descriptions
from teeshield.scanner.architecture_check import check_architecture


def test_license_check_mit(tmp_path: Path):
    """Test MIT license detection."""
    license_file = tmp_path / "LICENSE"
    license_file.write_text("MIT License\n\nPermission is hereby granted, free of charge...")
    name, ok = check_license(tmp_path)
    assert name == "MIT"
    assert ok is True


def test_license_check_gpl(tmp_path: Path):
    """Test GPL license detection (should not be fork-safe)."""
    license_file = tmp_path / "LICENSE"
    license_file.write_text("GNU General Public License version 3")
    name, ok = check_license(tmp_path)
    assert name == "GPL"
    assert ok is False


def test_license_check_missing(tmp_path: Path):
    """Test missing license."""
    name, ok = check_license(tmp_path)
    assert name is None
    assert ok is False


def test_security_scan_clean(tmp_path: Path):
    """Test scanning a clean file."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score, issues = scan_security(tmp_path)
    assert score >= 8.0
    assert len(issues) == 0


def test_security_scan_sql_injection(tmp_path: Path):
    """Test detection of SQL injection."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def query(sql):\n    db.execute(f"SELECT * FROM {sql}")\n')
    score, issues = scan_security(tmp_path)
    assert score < 8.0
    assert any(i.category == "sql_injection" for i in issues)


def test_security_scan_command_injection(tmp_path: Path):
    """Test detection of command injection."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import os\ndef run(cmd):\n    os.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "command_injection" for i in issues)
    assert any(i.severity == "critical" for i in issues)


def test_security_scan_no_false_positive_environ(tmp_path: Path):
    """os.environ.get for secrets should NOT be flagged (it's the standard pattern)."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import os\napi_key = os.environ.get("API_KEY", "")\n')
    score, issues = scan_security(tmp_path)
    assert not any(i.category == "hardcoded_credential" for i in issues)


def test_security_scan_hardcoded_secret(tmp_path: Path):
    """Hardcoded secret string SHOULD be flagged."""
    py_file = tmp_path / "server.py"
    py_file.write_text('api_key = "sk-1234567890abcdef"\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "hardcoded_credential" for i in issues)


def test_security_scan_unsafe_deserialization(tmp_path: Path):
    """pickle.load and yaml.load without SafeLoader should be flagged."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import pickle\ndata = pickle.load(f)\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "unsafe_deserialization" for i in issues)


def test_security_scan_no_false_positive_str_param(tmp_path: Path):
    """Regular function with str param should NOT be flagged (only MCP tools)."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def helper(name: str):\n    return name.upper()\n')
    score, issues = scan_security(tmp_path)
    assert not any(i.category == "no_input_validation" for i in issues)


def test_description_quality_good(tmp_path: Path):
    """Test scoring of a well-described tool."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def list_tables():
    """List all tables in the database.

    Use when the user wants to see available tables.
    Accepts `schema` parameter to filter by schema name.
    Example: Returns ['users', 'orders', 'products'].
    If the connection fails, check your database URL.
    """
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert len(names) == 1
    assert names[0] == "list_tables"
    assert tool_scores[0].has_action_verb is True
    assert tool_scores[0].has_scenario_trigger is True
    assert tool_scores[0].has_param_examples is True
    assert tool_scores[0].has_error_guidance is True
    assert tool_scores[0].has_param_docs is True
    assert tool_scores[0].overall_score >= 8.0


def test_description_quality_poor(tmp_path: Path):
    """Test scoring of a poorly-described tool."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def query(sql):
    """Execute a query."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert tool_scores[0].has_scenario_trigger is False
    assert tool_scores[0].has_param_examples is False
    assert tool_scores[0].overall_score < 4.0


def test_description_quality_minimal(tmp_path: Path):
    """Test that a bare-minimum description scores very low."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def do_thing():
    """Does a thing."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    # No verb start, no scenario, no examples, no error guidance, no param docs
    # Should score near 1.0-2.0, NOT 3.5
    assert tool_scores[0].overall_score < 2.5


def test_architecture_check(tmp_path: Path):
    """Test architecture quality checks."""
    # No tests, no error handling
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score, has_tests, has_error = check_architecture(tmp_path)
    assert has_tests is False
    assert has_error is False

    # Add a test file
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_server.py").write_text("def test_hello(): pass")
    score2, has_tests2, _ = check_architecture(tmp_path)
    assert has_tests2 is True
    assert score2 > score


def test_architecture_gradual_scoring(tmp_path: Path):
    """Architecture scoring should be gradual, not binary."""
    # Minimal server: no tests, no error handling, no README
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score_bare, _, _ = check_architecture(tmp_path)

    # Add README (short)
    (tmp_path / "README.md").write_text("# Server\nA simple server.")
    score_readme, _, _ = check_architecture(tmp_path)
    assert score_readme > score_bare

    # Add 1 test file -> 1.0 for tests
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_a.py").write_text("def test_a(): pass")
    score_1test, _, _ = check_architecture(tmp_path)
    assert score_1test > score_readme

    # Add 5+ test files -> 3.0 for tests
    for i in range(5):
        (test_dir / f"test_{i}.py").write_text(f"def test_{i}(): pass")
    score_many_tests, _, _ = check_architecture(tmp_path)
    assert score_many_tests > score_1test


def test_security_ts_child_process(tmp_path: Path):
    """TypeScript child_process.exec should be flagged."""
    ts_file = tmp_path / "server.ts"
    ts_file.write_text('import { exec } from "child_process";\nexecSync(`ls ${dir}`);\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "child_process_injection" for i in issues)


def test_security_ts_sql_template_literal(tmp_path: Path):
    """Template literal interpolation in SQL queries should be flagged."""
    ts_file = tmp_path / "db.ts"
    ts_file.write_text('async function q(table: string) {\n  await pool.query(`SELECT * FROM ${table}`);\n}\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "ts_sql_injection" for i in issues)


def test_security_examples_excluded(tmp_path: Path):
    """Files in examples/ directory should not be scanned."""
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    py_file = examples_dir / "demo.py"
    py_file.write_text('import os\nos.system("ls")\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0
