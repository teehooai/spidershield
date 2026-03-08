"""Tests for the template rewriter -- verifying anti-tautology guarantees."""

from teeshield.rewriter.runner import _rewrite_local


def test_rewrite_adds_verb():
    """Template rewriter should prepend action verb from VERB_MAP."""
    result = _rewrite_local(
        {"name": "list_tables", "description": "all tables in the database"},
        [],
    )
    assert result.startswith("List ")


def test_rewrite_no_verb_duplication():
    """If description already starts with the verb, don't double it."""
    result = _rewrite_local(
        {"name": "list_tables", "description": "Lists all tables."},
        [],
    )
    # Should NOT produce "List Lists all tables"
    assert "List List" not in result
    assert "List list" not in result


def test_rewrite_no_tautological_scenario():
    """Template rewriter must NOT generate 'Use when the user wants to {name}'."""
    result = _rewrite_local(
        {"name": "pause_project", "description": "Pauses a project."},
        [],
    )
    # "pause project" tautology must not appear
    assert "Use when the user wants to pause project" not in result


def test_rewrite_known_scenario():
    """Tools matching SCENARIO_TRIGGERS keys should get a genuine scenario."""
    result = _rewrite_local(
        {"name": "search_files", "description": "Searches for files."},
        [],
    )
    assert "Use when" in result
    assert "criteria" in result or "patterns" in result


def test_rewrite_no_disambiguation_template():
    """Template rewriter must NOT produce 'Unlike X, this tool specifically handles Y'."""
    tools = [
        {"name": "list_tables", "description": "Lists tables."},
        {"name": "list_schemas", "description": "Lists schemas."},
    ]
    result = _rewrite_local(tools[0], tools)
    assert "Unlike" not in result
    assert "specifically handles" not in result


def test_rewrite_no_generic_error_guidance():
    """Template rewriter must NOT produce generic error boilerplate."""
    result = _rewrite_local(
        {"name": "read_file", "description": "Reads a file."},
        [],
    )
    # These are the exact phrases from the removed ERROR_GUIDANCE dict
    assert "verify the path is within allowed directories" not in result
    assert "Check file permissions if access is denied" not in result


def test_rewrite_empty_description():
    """Empty description should produce a minimal but valid output."""
    result = _rewrite_local(
        {"name": "get_status", "description": ""},
        [],
    )
    assert len(result) > 0
    assert result[0].isupper()  # Starts with capital letter


def test_rewrite_preserves_good_description():
    """A description with no matching verb should be preserved as-is."""
    original = "Analyze the repository for security vulnerabilities."
    result = _rewrite_local(
        {"name": "analyze_repo", "description": original},
        [],
    )
    # The core content should be preserved (verb stripping may adjust it)
    assert "vulnerabilities" in result
