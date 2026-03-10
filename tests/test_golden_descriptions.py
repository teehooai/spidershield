"""Golden set: 10/10 tool descriptions that serve as quality reference.

Each description hits all 7 scoring dimensions naturally -- not by gaming
the scorer, but by being genuinely excellent MCP tool descriptions.

These tests validate that:
1. The scorer correctly awards 10.0/10 to objectively great descriptions
2. The rewriter quality gate preserves them (does not degrade golden input)
3. The scoring formula is well-calibrated (no false ceilings)
"""

import pytest

from spidershield.rewriter.runner import _quality_gate, _rewrite_local
from spidershield.scanner.description_quality import score_descriptions

# ---------------------------------------------------------------------------
# Golden descriptions: domain-diverse, all should score 10.0/10
# ---------------------------------------------------------------------------

GOLDEN_TOOLS = [
    # --- Database domain ---
    {
        "name": "execute_sql",
        "description": (
            "Execute a SQL query against the project database. "
            "Use when the user wants to read or mutate data directly. "
            "Accepts `query` (e.g. \"SELECT * FROM users WHERE active = true\"). "
            "Returns an error if the query is syntactically invalid."
        ),
    },
    {
        "name": "list_tables",
        "description": (
            "List all tables in the specified schema. "
            "Use when the user wants to explore the database structure. "
            "Accepts `schemas` (e.g. [\"public\", \"auth\"]) and `verbose` flag. "
            "Returns an error if the schema does not exist."
        ),
    },
    # --- Git domain ---
    {
        "name": "git_diff",
        "description": (
            "Show the diff between the working tree and a commit reference. "
            "Use when the user wants to review uncommitted changes. "
            "Accepts `ref` (e.g. \"HEAD~3\" or \"main\") to compare against. "
            "Returns an error if the ref is invalid or the repo is bare."
        ),
    },
    {
        "name": "search_commits",
        "description": (
            "Search the commit history by message, author, or date range. "
            "Use when the user wants to find a specific past change. "
            "Accepts `query` (e.g. \"fix login bug\") and optional `author`. "
            "Returns an error if the repository has no commits."
        ),
    },
    # --- Filesystem domain ---
    {
        "name": "read_file",
        "description": (
            "Read the contents of a file at the given path. "
            "Use when the user wants to inspect source code or config. "
            "Accepts `path` (e.g. \"src/index.ts\" or \"/etc/nginx.conf\"). "
            "Returns an error if the file does not exist or is not readable."
        ),
    },
    {
        "name": "create_directory",
        "description": (
            "Create a new directory at the specified path, including parents. "
            "Use when the user wants to set up a project folder structure. "
            "Accepts `path` (e.g. \"src/components/auth\") to create. "
            "Returns an error if the path already exists as a file."
        ),
    },
    # --- API / platform domain ---
    {
        "name": "deploy_function",
        "description": (
            "Deploy an edge function to the production environment. "
            "Use when the user wants to publish a new or updated function. "
            "Requires `function_name` and `entrypoint` (e.g. \"handler.ts\"). "
            "Returns an error if the build fails or the entrypoint is invalid."
        ),
    },
    {
        "name": "list_projects",
        "description": (
            "Retrieve all projects associated with the current organization. "
            "Use when the user wants to see available projects and their status. "
            "Accepts optional `status` filter (e.g. \"active\", \"paused\"). "
            "Returns an error if the API token lacks organization-level scope."
        ),
    },
]


class TestGoldenScoring:
    """Verify that golden descriptions score 10.0/10."""

    @pytest.fixture
    def golden_scores(self, tmp_path):
        """Write golden tools as a Python MCP server and score them."""
        server_file = tmp_path / "server.py"
        lines = ["from mcp import Server", "", "server = Server('golden')", ""]
        for tool in GOLDEN_TOOLS:
            lines.append('@server.tool()')
            lines.append(f'def {tool["name"]}():')
            lines.append(f'    """{tool["description"]}"""')
            lines.append('    pass')
            lines.append("")
        server_file.write_text("\n".join(lines))
        avg_score, per_tool, _ = score_descriptions(tmp_path)
        return avg_score, per_tool

    def test_average_score_is_perfect(self, golden_scores):
        """Golden set average must be 10.0/10."""
        avg_score, _ = golden_scores
        assert avg_score == 10.0, f"Golden set average {avg_score}/10, expected 10.0"

    def test_each_tool_scores_perfect(self, golden_scores):
        """Every individual golden tool must score 10.0/10."""
        _, per_tool = golden_scores
        for ts in per_tool:
            assert ts.overall_score == 10.0, (
                f"{ts.tool_name} scored {ts.overall_score}/10 -- "
                f"verb={ts.has_action_verb}, scenario={ts.has_scenario_trigger}, "
                f"params={ts.has_param_docs}, examples={ts.has_param_examples}, "
                f"error={ts.has_error_guidance}, disambig={ts.disambiguation_score}"
            )

    def test_all_dimensions_present(self, golden_scores):
        """Every golden tool must have all scoring dimensions enabled."""
        _, per_tool = golden_scores
        for ts in per_tool:
            assert ts.has_action_verb, f"{ts.tool_name}: missing action verb"
            assert ts.has_scenario_trigger, f"{ts.tool_name}: missing scenario"
            assert ts.has_param_docs, f"{ts.tool_name}: missing param docs"
            assert ts.has_param_examples, f"{ts.tool_name}: missing examples"
            assert ts.has_error_guidance, f"{ts.tool_name}: missing error guidance"
            assert ts.disambiguation_score >= 0.8, (
                f"{ts.tool_name}: disambiguation too low ({ts.disambiguation_score})"
            )


class TestGoldenGatePreservation:
    """Golden descriptions must survive the quality gate unchanged."""

    @pytest.mark.parametrize("tool", GOLDEN_TOOLS, ids=[t["name"] for t in GOLDEN_TOOLS])
    def test_gate_preserves_golden(self, tool):
        """Quality gate must not degrade a golden description."""
        rewritten = _rewrite_local(tool, GOLDEN_TOOLS)
        gated = _quality_gate(tool["description"], rewritten)
        # The gate should either keep the golden original or produce
        # something equally good -- never worse
        from spidershield.rewriter.runner import _quick_score
        original_score = _quick_score(tool["description"])
        gated_score = _quick_score(gated)
        assert gated_score >= original_score, (
            f"{tool['name']}: gate degraded score {original_score} -> {gated_score}\n"
            f"  original:  {tool['description']}\n"
            f"  gated:     {gated}"
        )


class TestGoldenAsReference:
    """Use golden set to validate scorer calibration."""

    def test_mediocre_scores_lower(self):
        """A mediocre description must score strictly lower than golden."""
        from spidershield.rewriter.runner import _quick_score
        golden_score = _quick_score(GOLDEN_TOOLS[0]["description"])
        mediocre_score = _quick_score("Lists tables.")
        assert mediocre_score < golden_score, (
            f"Mediocre ({mediocre_score}) >= golden ({golden_score}) -- "
            f"scorer is not discriminating quality"
        )

    def test_empty_scores_much_lower(self):
        """An empty description must score far below golden."""
        from spidershield.rewriter.runner import _quick_score
        golden_score = _quick_score(GOLDEN_TOOLS[0]["description"])
        empty_score = _quick_score("")
        assert empty_score < golden_score * 0.3, (
            f"Empty ({empty_score}) too close to golden ({golden_score})"
        )


class TestAntiGaming:
    """Verify the scorer resists keyword-stuffing attacks."""

    def _golden_score(self):
        from spidershield.rewriter.runner import _quick_score
        return _quick_score(GOLDEN_TOOLS[0]["description"])

    def test_keyword_stuffed_scores_low(self):
        """Pure keyword stuffing must score far below golden."""
        from spidershield.rewriter.runner import _quick_score
        stuffed = (
            "List e.g. example. Use when error fail invalid. "
            "Accepts param: requires: expects: `x` such as like for instance."
        )
        assert _quick_score(stuffed) < self._golden_score() * 0.5

    def test_repeated_keywords_scores_low(self):
        """Repeated trigger words must score far below golden."""
        from spidershield.rewriter.runner import _quick_score
        repeated = (
            "Read read read. Use when use when use when. "
            "e.g. e.g. e.g. error error error. Accepts: accepts: requires:."
        )
        assert _quick_score(repeated) < self._golden_score() * 0.5

    def test_empty_semantic_scores_below_golden(self):
        """Vague descriptions with triggers must score below golden."""
        from spidershield.rewriter.runner import _quick_score
        vague = (
            'Get it. Use when you want it. Takes `thing` '
            '(e.g. "stuff"). Fails if invalid input error.'
        )
        assert _quick_score(vague) < self._golden_score()


class TestDiscriminationGradient:
    """Verify clear score gradient: golden > good > mediocre > poor > empty."""

    def test_score_gradient(self):
        """Scores must decrease monotonically across quality tiers."""
        from spidershield.rewriter.runner import _quick_score

        tiers = {
            "golden": GOLDEN_TOOLS[0]["description"],
            "good": (
                "Execute a SQL query against the database. "
                "Accepts `query` parameter for the SQL statement."
            ),
            "mediocre": "Executes raw SQL in the Postgres database.",
            "poor": "Database query tool.",
            "empty": "",
        }

        scores = {name: _quick_score(desc) for name, desc in tiers.items()}

        assert scores["golden"] > scores["good"], (
            f"golden ({scores['golden']}) should > good ({scores['good']})"
        )
        assert scores["good"] > scores["mediocre"], (
            f"good ({scores['good']}) should > mediocre ({scores['mediocre']})"
        )
        assert scores["mediocre"] > scores["poor"], (
            f"mediocre ({scores['mediocre']}) should > poor ({scores['poor']})"
        )
        assert scores["poor"] > scores["empty"], (
            f"poor ({scores['poor']}) should > empty ({scores['empty']})"
        )
