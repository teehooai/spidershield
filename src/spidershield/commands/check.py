"""Check command -- query SpiderRating Trust API for a server's security score."""

from __future__ import annotations

import json
import re
import sys
import urllib.request
import urllib.error
from typing import Any

import click

API_BASE = "https://api.spiderrating.com"

# Matches owner/repo or @scope/name
SLUG_RE = re.compile(r"^@?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")


def _parse_slug(raw: str) -> tuple[str, str]:
    """Parse owner/repo from various input formats.

    Accepts:
        owner/repo
        @scope/package-name
        https://github.com/owner/repo
    """
    # Strip GitHub URL prefix
    for prefix in (
        "https://github.com/",
        "http://github.com/",
        "github.com/",
    ):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break

    # Strip trailing slashes or .git
    raw = raw.rstrip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]

    # Remove leading @ for scoped npm packages
    if raw.startswith("@"):
        raw = raw[1:]

    match = SLUG_RE.match(raw)
    if not match:
        raise click.BadParameter(
            f"Cannot parse '{raw}'. Use owner/repo or @scope/package-name."
        )
    return match.group(1), match.group(2)


def _fetch_score(owner: str, repo: str, api_key: str | None = None) -> dict[str, Any]:
    """Query SpiderRating Trust API and return the JSON response."""
    if api_key:
        url = f"{API_BASE}/api/v1/trust/score/{owner}/{repo}"
        req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    else:
        url = f"{API_BASE}/v1/public/score/{owner}/{repo}"
        req = urllib.request.Request(url)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"score": None, "grade": None, "verdict": "unknown",
                    "message": "Not yet rated"}
        raise click.ClickException(
            f"API error {exc.code}: {exc.read().decode()[:200]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise click.ClickException(
            f"Cannot reach SpiderRating API: {exc.reason}"
        ) from exc


@click.command()
@click.argument("server")
@click.option(
    "--api-key", envvar="SPIDERRATING_API_KEY", default=None,
    help="SpiderRating API key (or set SPIDERRATING_API_KEY env var)",
)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON")
@click.option(
    "--fail-below", type=float, default=None,
    help="Exit 1 if score is below this threshold (0.0-10.0)",
)
def check(server: str, api_key: str | None, as_json: bool, fail_below: float | None) -> None:
    """Query the SpiderRating Trust API for a server's security score.

    SERVER can be owner/repo, @scope/package-name, or a GitHub URL.

    \b
    Examples:
        spidershield check modelcontextprotocol/server-github
        spidershield check @modelcontextprotocol/server-github
        spidershield check https://github.com/owner/repo
        spidershield check owner/repo --fail-below 5.0
    """
    owner, repo = _parse_slug(server)
    result = _fetch_score(owner, repo, api_key)

    report_url = f"https://spiderrating.com/servers/{owner}/{repo}"

    if as_json:
        # Include report URL in JSON output
        output = dict(result)
        output["report_url"] = report_url
        click.echo(json.dumps(output, indent=2))
    else:
        score_str = (
            f"{result['score']:.1f}/10" if result.get("score") is not None else "N/A"
        )
        grade = result.get("grade") or "?"
        verdict_map = {
            "safe": "Safe",
            "risky": "Risky",
            "malicious": "MALICIOUS",
            "unknown": "Unknown",
        }
        verdict = verdict_map.get(result.get("verdict", "unknown"), result.get("verdict", "Unknown"))

        click.echo(f"Score: {score_str} ({grade}) | {verdict} | {report_url}")

        risk_factors = result.get("risk_factors", [])
        if risk_factors:
            click.echo(f"Risks: {', '.join(risk_factors[:3])}")

        recommendation = result.get("recommendation")
        if recommendation:
            click.echo(recommendation)

    # Exit code 1 if malicious
    if result.get("verdict") == "malicious":
        sys.exit(1)

    # Exit code 1 if score below --fail-below threshold
    if fail_below is not None and result.get("score") is not None:
        if result["score"] < fail_below:
            click.echo(
                f"FAILED: score {result['score']:.1f} is below threshold {fail_below:.1f}",
                err=True,
            )
            sys.exit(1)
