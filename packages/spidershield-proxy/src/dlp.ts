/**
 * DLP Scanner — detect secrets and PII in tool parameters and outputs.
 *
 * Ported from spidershield Python DLP engine (dlp/secrets.py + dlp/pii.py).
 * Patterns kept in sync with the Python version.
 */

export type DLPFinding = {
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  matched: string; // redacted preview
};

export type DLPResult = {
  secrets: DLPFinding[];
  pii: DLPFinding[];
};

// ── Secret patterns (from spidershield dlp/secrets.py) ──────────────

const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high";
}> = [
  { name: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  {
    name: "aws_secret_key",
    pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}/i,
    severity: "critical",
  },
  { name: "openai_api_key", pattern: /sk-[A-Za-z0-9]{20,}/, severity: "critical" },
  { name: "anthropic_api_key", pattern: /sk-ant-[A-Za-z0-9\-_]{20,}/, severity: "critical" },
  { name: "github_token", pattern: /gh[ps]_[A-Za-z0-9_]{36,}/, severity: "critical" },
  { name: "github_fine_grained", pattern: /github_pat_[A-Za-z0-9_]{22,}/, severity: "critical" },
  {
    name: "private_key",
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
    severity: "critical",
  },
  {
    name: "jwt",
    pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/,
    severity: "high",
  },
  {
    name: "generic_api_key",
    pattern: /(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}/i,
    severity: "high",
  },
  {
    name: "db_connection",
    pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/i,
    severity: "critical",
  },
  {
    name: "slack_token",
    pattern: /xox[bpors]-[A-Za-z0-9\-]{10,}/,
    severity: "high",
  },
  {
    name: "stripe_key",
    pattern: /(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}/,
    severity: "critical",
  },
];

// ── PII patterns (from spidershield dlp/pii.py) ────────────────────

const PII_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: "high" | "medium";
}> = [
  {
    name: "email",
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,
    severity: "medium",
  },
  {
    name: "phone",
    pattern: /\+?1?\s*\(?[0-9]{3}\)?[\s\-.]?[0-9]{3}[\s\-.]?[0-9]{4}/,
    severity: "medium",
  },
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/, severity: "high" },
  {
    name: "credit_card",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/,
    severity: "high",
  },
  {
    name: "ip_address",
    pattern: /\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b/,
    severity: "medium",
  },
];

export class DLPScanner {
  /** Scan tool call parameters for secrets and PII */
  scanParams(params: Record<string, unknown>): DLPResult {
    const text = JSON.stringify(params);
    return this.scanText(text);
  }

  /** Scan arbitrary text for secrets and PII */
  scanText(text: string): DLPResult {
    const secrets: DLPFinding[] = [];
    const pii: DLPFinding[] = [];

    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        secrets.push({
          type: name,
          severity,
          matched: redact(match[0]),
        });
      }
    }

    for (const { name, pattern, severity } of PII_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        pii.push({
          type: name,
          severity,
          matched: redact(match[0]),
        });
      }
    }

    return { secrets, pii };
  }

  /** Redact secrets in parameters, return modified copy */
  redactParams(
    params: Record<string, unknown>,
    findings: DLPResult
  ): Record<string, unknown> {
    let text = JSON.stringify(params);
    for (const { type } of findings.secrets) {
      for (const { name, pattern } of SECRET_PATTERNS) {
        if (name === type) {
          text = text.replace(pattern, `[REDACTED:${name}]`);
        }
      }
    }
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      return params;
    }
  }
}

/** Show first 4 and last 4 chars, mask the rest */
function redact(value: string): string {
  if (value.length <= 12) return "****";
  return value.slice(0, 4) + "****" + value.slice(-4);
}
