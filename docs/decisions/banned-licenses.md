# Decision: Banned License List

> Date: 2026-03-13
> Status: Active
> Author: SpiderShield maintainers

## Context

SpiderShield scans MCP servers and flags certain open-source licenses as
incompatible with typical AI agent deployment scenarios. A banned license
triggers a grade cap (D maximum) in the SpiderRating system.

## Decision

The following licenses are banned:

| License | SPDX ID | Reason |
|---------|---------|--------|
| GNU Affero GPL v3 | `AGPL-3.0`, `AGPL-3.0-only`, `AGPL-3.0-or-later` | Network copyleft: any service using AGPL code must publish its complete source, including proprietary agent orchestration logic. Most commercial AI agent deployments cannot comply. |
| Server Side Public License | `SSPL-1.0` | Stronger than AGPL: requires publishing the entire "service" stack. MongoDB's SSPL is not OSI-approved and is rejected by most corporate legal teams. |
| Business Source License | `BSL-1.1` | Time-delayed open source with production-use restrictions. Agents deployed commercially may violate the "additional use grant" terms during the proprietary period. |

## Why not GPL-3.0?

GPL-3.0 (non-Affero) only triggers copyleft on distribution of modified
binaries. MCP servers are typically consumed over stdio/HTTP (SaaS), not
distributed as binaries. In practice, GPL-3.0 MCP tools can be used in
agent deployments without triggering the copyleft clause. If a user
distributes a modified GPL-3.0 MCP server binary, that's their
responsibility — SpiderShield flags the license as a warning, not a ban.

## Why not MIT/BSD/Apache-2.0?

These are permissive licenses with no copyleft obligations. They are fully
compatible with all deployment models and are never flagged.

## Configuration

The banned list is defined in `src/spidershield/scoring_spec.py` as
`BANNED_LICENSES` and consumed by both `scanner/runner.py` (grade cap)
and `spiderrating.py` (rating conversion).

```python
BANNED_LICENSES: frozenset[str] = frozenset({
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "BSL-1.1",
})
```

## Future Considerations

- **EUPL-1.2**: European copyleft with AGPL-like network clause. Currently
  not banned due to low prevalence in MCP ecosystem. Monitor adoption.
- **CPAL-1.0**: Attribution copyleft. Low risk but worth monitoring.
- **User-configurable bans**: Allow users to extend/override the list via
  `spidershield.toml` or `--banned-licenses` flag.
