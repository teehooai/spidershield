# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in SpiderShield, please report it
responsibly:

1. **Do NOT open a public issue.**
2. Email **security@teehoo.ai** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. You will receive an acknowledgement within **48 hours**.
4. We aim to release a fix within **7 days** for critical issues.

## Scope

The following are in scope for security reports:

- Vulnerabilities in SpiderShield's scanning, guard, or DLP engine
- ReDoS in regex patterns used for security scanning
- Injection or bypass in the policy engine
- Unsafe deserialization or code execution in any module

The following are **out of scope**:

- Issues in scanned target repositories (report to those maintainers)
- Feature requests or non-security bugs (use GitHub Issues)

## Disclosure Policy

We follow coordinated disclosure:

- Reporter is credited in the release notes (unless they prefer anonymity)
- Public disclosure after the fix is released, or after 90 days
- CVE assignment for critical vulnerabilities when applicable

## Security Practices

SpiderShield itself follows the same security standards it enforces:

- No `eval()`, `exec()`, or `pickle` in core code
- YAML loaded only via `yaml.safe_load()`
- All regex patterns are pre-compiled, not built from user input
- Subprocess calls use explicit argument lists (no `shell=True`)
