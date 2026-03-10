# The MCP Tool Security Report

**We scanned 79 MCP tools across 7 production servers. Here's what we found.**

## What we scanned

We ran [SpiderShield](https://github.com/teehooai/spidershield) against the most widely used MCP servers in the ecosystem:

| Server | Type | Tools |
|--------|------|-------|
| filesystem | Official | 14 |
| git | Official | 12 |
| memory | Official | 9 |
| fetch | Official | 1 |
| time | Official | 0 |
| everything | SDK example | 13 |
| supabase | Community | 30 |

Each tool was scored on four dimensions: description quality, security patterns, architecture, and license compliance.

## The headline number

**Average description quality: 3.1 out of 10.**

This matters because AI agents choose which tool to call based entirely on the description text. A vague description gives the agent no boundaries.

## What's missing from tool descriptions

We checked every tool description for five critical attributes:

| Attribute | Present | Missing |
|-----------|---------|---------|
| Scenario triggers ("Use when...") | 0% | 100% |
| Parameter examples | 0% | 100% |
| Error handling guidance | <5% | >95% |
| Disambiguation vs similar tools | <10% | >90% |
| Adequate length (>50 chars) | ~40% | ~60% |

Not a single tool across all 79 had a scenario trigger. This means agents have zero guidance on *when* to pick one tool over another.

## Why this matters for agents

Consider the official Git MCP server. It has 12 tools, including three that show diffs:

```
git_diff_unstaged: "Shows changes in the working directory that are not yet staged"
git_diff_staged:   "Shows changes that are staged for commit"
git_diff:          "Shows differences between branches or commits"
```

An agent seeing these descriptions has to guess which one to call. There's no "Use when..." trigger, no examples, no disambiguation. The result: agents frequently call the wrong diff tool, waste context tokens, and produce incorrect results.

## What a good description looks like

Here's the same tool after SpiderShield rewrites it:

**Before (score 2.9):**
```
"Shows the working tree status"
```

**After (score 9.6):**
```
"Show the working tree status including modified, staged, and untracked files.
Use when the user wants to see the current state of the repository before
committing or staging changes. Unlike git_diff tools that show content changes,
this only shows which files have changed."
```

Three things changed:
1. **Scenario trigger** -- tells the agent *when* to use this tool
2. **What it returns** -- the agent knows what to expect
3. **Disambiguation** -- prevents confusion with similar tools

## The rewrite impact

We rewrote all 79 tool descriptions using SpiderShield's template engine (zero cost, no API calls):

| Server | Before | After | Gain |
|--------|--------|-------|------|
| git | 2.9 | 9.5 | +6.6 |
| supabase | 3.4 | 9.0 | +5.6 |
| filesystem | 3.7 | 8.5 | +4.8 |
| **Average** | **3.1** | **8.8** | **+5.7** |

Using Claude API for higher-quality rewrites: average gain of **+5.9 points**.

## Security is actually solid

Good news: the code-level security of MCP servers is generally strong.

| Server | Security Score |
|--------|---------------|
| filesystem | 10.0 |
| git | 10.0 |
| memory | 10.0 |
| time | 10.0 |
| everything | 10.0 |
| fetch | 9.0 |
| supabase | 9.0 |

The security risk in MCP isn't in the code. It's in the descriptions. A tool with perfect code but a vague description like "access filesystem" is still dangerous -- because the agent doesn't know what boundaries to respect.

## Top findings

1. **Description quality is the #1 security bottleneck.** Not code vulnerabilities. Not architecture. The descriptions.

2. **Zero tools have scenario triggers.** This is the single most impactful improvement. Adding "Use when..." costs nothing and immediately improves tool selection accuracy.

3. **Disambiguation is almost nonexistent.** Servers with similar tools (git has 3 diff tools, filesystem has 3 read tools) provide no guidance on which to choose.

4. **The fix is cheap.** Template-based rewriting is free and delivers +5.7 points on average. No API calls, no runtime overhead, no code changes.

## What server authors should do

1. **Add scenario triggers** to every tool description: "Use when the user wants to..."
2. **Add parameter examples** with concrete values, not just type annotations
3. **Disambiguate similar tools** explicitly: "Unlike X, this tool..."
4. **Declare side effects**: "This tool writes to disk" / "This tool is read-only"
5. **Run SpiderShield** before publishing: `pip install spidershield && spidershield scan .`

## Methodology

- Scanner: [SpiderShield v0.1.0](https://pypi.org/project/spidershield/)
- Description scoring: 5 criteria weighted to 10-point scale (scenario triggers 3.0, disambiguation 2.0, parameter examples 2.0, error guidance 1.5, length 1.5)
- Security scanning: pattern-based detection for path traversal, command injection, SSRF, credential exposure
- All scans are static analysis -- no runtime execution, no network calls
- Raw data: [batch-scan-results.json](batch-scan-results.json)

---

*This report was generated by [SpiderShield](https://github.com/teehooai/spidershield), a static security linter for MCP tools. Install: `pip install spidershield`*
