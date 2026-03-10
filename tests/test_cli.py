"""Tests for CLI commands using Click's test runner."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from spidershield.cli import main


class TestScanCommand:
    def test_scan_empty_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "SpiderShield" in result.output or "Scanning" in result.output

    def test_scan_json_format(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        assert '"target"' in result.output

    def test_scan_sarif_format(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path), "--format", "sarif"])
        assert result.exit_code == 0
        assert "sarifLog" in result.output or "$schema" in result.output

    def test_scan_output_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", str(tmp_path), "-o", str(out), "--format", "json"],
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_nonexistent_path(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/path/xyz"])
        assert result.exit_code != 0


class TestHardenCommand:
    def test_harden_empty_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["harden", str(tmp_path)])
        assert result.exit_code == 0
        assert "No issues found" in result.output or "suggestion" in result.output

    def test_harden_finds_issues(self, tmp_path: Path) -> None:
        (tmp_path / "server.py").write_text('key = os.environ["SECRET"]')
        runner = CliRunner()
        result = runner.invoke(main, ["harden", str(tmp_path)])
        assert result.exit_code == 0
        assert "credential" in result.output

    def test_harden_nonexistent(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["harden", "/nonexistent/xyz"])
        assert result.exit_code != 0


class TestRewriteCommand:
    def test_rewrite_empty_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["rewrite", str(tmp_path), "--engine", "template", "--dry-run"],
        )
        assert result.exit_code == 0

    def test_rewrite_template_mode(self, tmp_path: Path) -> None:
        (tmp_path / "server.py").write_text(
            'from mcp import Server\nserver = Server("test")\n\n'
            '@server.tool()\n'
            'def read_file(path: str) -> str:\n'
            '    """Read a file"""\n'
            '    return open(path).read()\n'
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["rewrite", str(tmp_path), "--engine", "template", "--dry-run"],
        )
        assert result.exit_code == 0


class TestVersionCommand:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or "." in result.output
