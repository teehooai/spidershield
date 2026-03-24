/**
 * SpiderShield OpenClaw Plugin
 *
 * Three-phase runtime security for OpenClaw agents:
 *   1. before_tool_call — Trust Score check + DLP parameter scan
 *   2. after_tool_call  — Output DLP scan + audit logging
 *   3. message_sending  — Outbound DLP (prevent data leaks in replies)
 *
 * Policy modes:
 *   - audit-only: log everything, block nothing (for initial deployment)
 *   - balanced:   block malicious, warn risky, allow safe (default)
 *   - strict:     block unknown + risky + malicious
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { TrustScoreClient } from "./trust-client.js";
import { DLPScanner } from "./dlp.js";
import { AuditLogger } from "./audit.js";
import { PolicyClient } from "./policy-client.js";

type PluginConfig = {
  policy?: "balanced" | "strict" | "audit-only";
  apiUrl?: string;
  apiKey?: string;
  blockThreshold?: number;
  warnThreshold?: number;
};

const spidershieldPlugin = {
  id: "spidershield",
  name: "SpiderShield Runtime Guard",
  description:
    "Automatic security checks for every tool call — Trust Score, DLP, and audit logging.",

  register(api: OpenClawPluginApi) {
    const config: PluginConfig = (api.pluginConfig || {}) as PluginConfig;
    const policy = config.policy || "balanced";
    const apiUrl =
      config.apiUrl ||
      "https://spiderrating-api-production.up.railway.app";
    const blockThreshold = config.blockThreshold ?? 3.0;
    const warnThreshold = config.warnThreshold ?? 5.0;

    const trust = new TrustScoreClient(apiUrl);
    const policyClient = new PolicyClient(apiUrl);
    const dlp = new DLPScanner();
    const audit = new AuditLogger(apiUrl, config.apiKey);

    api.logger.info(
      `[SpiderShield] v0.1.0 loaded — policy: ${policy}, block < ${blockThreshold}, warn < ${warnThreshold}`
    );

    // ─── before_tool_call ─────────────────────────────────────────
    api.on("before_tool_call", async (event, ctx) => {
      const { toolName, params } = event;
      const startMs = Date.now();

      // 1. Trust Score check (only for MCP tools)
      let verdict: "safe" | "risky" | "malicious" | "unknown" = "unknown";
      let score: number | null = null;
      let grade: string | null = null;

      if (toolName.startsWith("mcp__")) {
        const trustResult = await trust.check(toolName);
        verdict = trustResult.verdict;
        score = trustResult.score;
        grade = trustResult.grade;
      } else {
        verdict = "safe"; // built-in tools are trusted
      }

      // 2. Policy template check (auto-generated rules from scan data)
      let policyDecision: string | null = null;
      let policyReason: string | undefined;

      if (toolName.startsWith("mcp__")) {
        const parts = toolName.split("__");
        const serverName = parts.length >= 2 ? (parts[0] === "mcp" ? parts[1] : parts[0]) : null;
        if (serverName) {
          const rule = await policyClient.getDecision(serverName, toolName);
          if (rule) {
            policyDecision = rule.decision;
            policyReason = rule.reason || rule.note;
          }
        }
      }

      // 3. DLP parameter scan
      const dlpFindings = dlp.scanParams(params);

      // 4. Combined policy decision (Trust Score + Policy Template + DLP)
      let block = false;
      let blockReason: string | undefined;
      let modifiedParams: Record<string, unknown> | undefined;

      if (policy !== "audit-only") {
        // 4a. Block malicious servers (score below block threshold)
        if (
          verdict === "malicious" ||
          (score !== null && score < blockThreshold)
        ) {
          block = true;
          blockReason = `SpiderShield: BLOCKED — ${toolName} rated ${grade} (${score?.toFixed(1)}/10). Grade F servers are not safe to use.`;
        }

        // 4b. Apply auto-generated policy rules (deny/escalate)
        if (!block && policyDecision === "deny") {
          block = true;
          blockReason = `SpiderShield: BLOCKED by policy — ${policyReason || "destructive operation"}`;
        }
        if (!block && policyDecision === "escalate") {
          api.logger.warn(
            `[SpiderShield] ESCALATE — ${toolName}: ${policyReason || "requires confirmation"}`
          );
          // Note: OpenClaw SDK doesn't support escalate (user prompt) yet
          // For now, treat as warn in balanced mode, block in strict
          if (policy === "strict") {
            block = true;
            blockReason = `SpiderShield: BLOCKED (strict) — ${policyReason || "escalation required"}`;
          }
        }

        // 4c. Warn on risky servers
        if (
          !block &&
          verdict === "risky" &&
          score !== null &&
          score < warnThreshold
        ) {
          api.logger.warn(
            `[SpiderShield] RISKY — ${toolName} rated ${grade} (${score.toFixed(1)}/10). Use with caution.`
          );
        }

        // 4d. Strict mode: block unknown
        if (policy === "strict" && verdict === "unknown") {
          block = true;
          blockReason = `SpiderShield: BLOCKED — ${toolName} is not rated. Strict policy requires known-safe tools.`;
        }

        // 4e. DLP: block or redact secrets in parameters
        if (!block && dlpFindings.secrets.length > 0) {
          if (policy === "strict") {
            block = true;
            blockReason = `SpiderShield: BLOCKED — secret detected in parameters (${dlpFindings.secrets.map((s) => s.type).join(", ")})`;
          } else {
            modifiedParams = dlp.redactParams(params, dlpFindings);
          }
        }
      }

      // 4. Log
      const latencyMs = Date.now() - startMs;
      if (verdict !== "safe" || dlpFindings.secrets.length > 0 || block) {
        const level = block ? "warn" : "info";
        api.logger[level](
          `[SpiderShield] ${block ? "BLOCKED" : verdict.toUpperCase()} ${toolName} — score: ${score ?? "?"}, DLP: ${dlpFindings.secrets.length} secrets, ${dlpFindings.pii.length} PII (${latencyMs}ms)`
        );
      }

      // 5. Audit event
      audit.log({
        phase: "before_tool_call",
        toolName,
        agentId: ctx.agentId,
        sessionId: ctx.sessionId,
        decision: block ? "deny" : "allow",
        verdict,
        score,
        grade,
        policyRule: policyDecision,
        policyReason: policyReason || null,
        dlpSecrets: dlpFindings.secrets.length,
        dlpPii: dlpFindings.pii.length,
        policy,
        latencyMs,
      });

      if (block) {
        return { block: true, blockReason };
      }
      if (modifiedParams) {
        return { params: modifiedParams };
      }
      return undefined;
    });

    // ─── after_tool_call ──────────────────────────────────────────
    api.on("after_tool_call", async (event, ctx) => {
      const { toolName, result, error, durationMs } = event;

      // DLP scan on output
      const outputText =
        typeof result === "string"
          ? result
          : result != null
            ? JSON.stringify(result)
            : "";
      const dlpFindings = dlp.scanText(outputText);

      if (dlpFindings.secrets.length > 0 || dlpFindings.pii.length > 0) {
        api.logger.warn(
          `[SpiderShield] OUTPUT DLP — ${toolName}: ${dlpFindings.secrets.length} secrets, ${dlpFindings.pii.length} PII found in result`
        );
      }

      audit.log({
        phase: "after_tool_call",
        toolName,
        agentId: ctx.agentId,
        sessionId: ctx.sessionId,
        decision: "allow",
        error: error || null,
        durationMs: durationMs || null,
        dlpSecrets: dlpFindings.secrets.length,
        dlpPii: dlpFindings.pii.length,
        policy,
      });
    });

    // ─── message_sending ──────────────────────────────────────────
    api.on("message_sending", async (event) => {
      // DLP scan on outbound message to prevent data leaks
      const content =
        typeof event === "object" && event !== null
          ? JSON.stringify(event)
          : String(event);
      const dlpFindings = dlp.scanText(content);

      if (dlpFindings.secrets.length > 0) {
        api.logger.warn(
          `[SpiderShield] OUTBOUND DLP — ${dlpFindings.secrets.length} secrets detected in outgoing message`
        );
        // Note: message_sending hook cannot block in current SDK
        // We log for audit; blocking requires future SDK support
      }
    });
  },
};

export default spidershieldPlugin;
