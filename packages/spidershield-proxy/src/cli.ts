#!/usr/bin/env node
/**
 * SpiderShield MCP Proxy CLI
 *
 * Usage:
 *   npx spidershield-proxy <mcp-server-command> [args...]
 *   npx spidershield-proxy npx @modelcontextprotocol/server-github
 *   npx spidershield-proxy -- node my-server.js --port 3000
 *
 * What it does:
 *   Sits between your MCP client and server, intercepting every tool call:
 *   1. Trust Score check — is this server known-safe?
 *   2. DLP scan — are there secrets/PII in parameters?
 *   3. Policy enforcement — allow/deny/escalate based on rules
 *   4. Audit logging — every decision logged to ~/.spidershield/audit/
 *
 * Like PolicyLayer Intercept, but with 15,923 rated servers backing the decisions.
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { TrustScoreClient } from "./trust-client.js";
import { DLPScanner } from "./dlp.js";
import { AuditLogger } from "./audit.js";
import { PolicyClient } from "./policy-client.js";

const API_URL =
  process.env.SPIDERSHIELD_API_URL ||
  "https://spiderrating-api-production.up.railway.app";
const POLICY_MODE = (process.env.SPIDERSHIELD_POLICY || "balanced") as
  | "balanced"
  | "strict"
  | "audit-only";
const API_KEY = process.env.SPIDERSHIELD_API_KEY;

// ── Parse CLI args ────────────────────────────────────────────────

const args = process.argv.slice(2);
const dashDash = args.indexOf("--");
const serverArgs = dashDash >= 0 ? args.slice(dashDash + 1) : args;

if (serverArgs.length === 0) {
  console.error(`
SpiderShield MCP Proxy v0.1.0

Usage:
  npx spidershield-proxy <mcp-server-command> [args...]

Examples:
  npx spidershield-proxy npx @modelcontextprotocol/server-github
  npx spidershield-proxy -- node my-server.js --port 3000

Environment variables:
  SPIDERSHIELD_POLICY    balanced (default) | strict | audit-only
  SPIDERSHIELD_API_KEY   Optional Pro API key for cloud audit
  SPIDERSHIELD_API_URL   API URL (default: SpiderRating public API)
`);
  process.exit(1);
}

// ── Initialize ────────────────────────────────────────────────────

const trust = new TrustScoreClient(API_URL);
const policyClient = new PolicyClient(API_URL);
const dlp = new DLPScanner();
const audit = new AuditLogger(API_URL, API_KEY);

console.error(
  `[SpiderShield Proxy] v0.1.0 — policy: ${POLICY_MODE}, server: ${serverArgs.join(" ")}`
);

// ── Spawn MCP server ──────────────────────────────────────────────

const serverProc = spawn(serverArgs[0], serverArgs.slice(1), {
  stdio: ["pipe", "pipe", "inherit"],
});

serverProc.on("error", (err) => {
  console.error(`[SpiderShield Proxy] Failed to start server: ${err.message}`);
  process.exit(1);
});

serverProc.on("exit", (code) => {
  process.exit(code ?? 0);
});

// ── Relay: Client (stdin) → Guard → Server ────────────────────────

const clientRL = createInterface({ input: process.stdin, crlfDelay: Infinity });

clientRL.on("line", async (line) => {
  try {
    const msg = JSON.parse(line);

    // Intercept tools/call requests
    if (
      msg.method === "tools/call" &&
      msg.params?.name
    ) {
      const toolName = msg.params.name as string;
      const toolParams = (msg.params.arguments || {}) as Record<string, unknown>;
      const decision = await evaluateToolCall(toolName, toolParams);

      if (decision.block) {
        // Send error response back to client
        const errorResponse = JSON.stringify({
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32600,
            message: decision.blockReason || "Blocked by SpiderShield",
          },
        });
        process.stdout.write(errorResponse + "\n");
        return; // Don't forward to server
      }

      // If params were modified (DLP redaction), update the message
      if (decision.modifiedParams) {
        msg.params.arguments = decision.modifiedParams;
      }
    }

    // Forward to server
    serverProc.stdin!.write(JSON.stringify(msg) + "\n");
  } catch {
    // Not JSON or parse error — forward raw
    serverProc.stdin!.write(line + "\n");
  }
});

// ── Relay: Server (stdout) → DLP scan → Client ───────────────────

const serverRL = createInterface({
  input: serverProc.stdout!,
  crlfDelay: Infinity,
});

serverRL.on("line", (line) => {
  try {
    const msg = JSON.parse(line);

    // Scan tool results for secrets/PII
    if (msg.result) {
      const resultText =
        typeof msg.result === "string"
          ? msg.result
          : JSON.stringify(msg.result);
      const findings = dlp.scanText(resultText);

      if (findings.secrets.length > 0 || findings.pii.length > 0) {
        console.error(
          `[SpiderShield Proxy] OUTPUT DLP — ${findings.secrets.length} secrets, ${findings.pii.length} PII detected`
        );

        audit.log({
          phase: "after_tool_call",
          toolName: "unknown", // tool name not in response
          decision: "allow",
          dlpSecrets: findings.secrets.length,
          dlpPii: findings.pii.length,
          policy: POLICY_MODE,
        });
      }
    }

    process.stdout.write(JSON.stringify(msg) + "\n");
  } catch {
    process.stdout.write(line + "\n");
  }
});

// ── Clean shutdown ────────────────────────────────────────────────

process.on("SIGINT", () => {
  serverProc.kill("SIGINT");
  audit.destroy();
});

process.on("SIGTERM", () => {
  serverProc.kill("SIGTERM");
  audit.destroy();
});

// ── Evaluate tool call ────────────────────────────────────────────

type EvalResult = {
  block: boolean;
  blockReason?: string;
  modifiedParams?: Record<string, unknown>;
};

async function evaluateToolCall(
  toolName: string,
  params: Record<string, unknown>
): Promise<EvalResult> {
  const startMs = Date.now();

  // 1. Trust Score
  const trustResult = await trust.check(toolName);
  const { verdict, score, grade } = trustResult;

  // 2. Policy rules
  let policyDecision: string | null = null;
  const parts = toolName.split("__");
  const serverName =
    parts.length >= 2 ? (parts[0] === "mcp" ? parts[1] : parts[0]) : null;
  if (serverName) {
    const rule = await policyClient.getDecision(serverName, toolName);
    if (rule) policyDecision = rule.decision;
  }

  // 3. DLP
  const dlpFindings = dlp.scanParams(params);

  // 4. Decision
  let block = false;
  let blockReason: string | undefined;
  let modifiedParams: Record<string, unknown> | undefined;

  if (POLICY_MODE !== "audit-only") {
    if (verdict === "malicious" || (score !== null && score < 3.0)) {
      block = true;
      blockReason = `SpiderShield: BLOCKED — ${toolName} rated ${grade} (${score?.toFixed(1)}/10)`;
    }

    if (!block && policyDecision === "deny") {
      block = true;
      blockReason = `SpiderShield: BLOCKED by policy — destructive operation`;
    }

    if (POLICY_MODE === "strict" && verdict === "unknown") {
      block = true;
      blockReason = `SpiderShield: BLOCKED — ${toolName} is not rated`;
    }

    if (!block && dlpFindings.secrets.length > 0) {
      if (POLICY_MODE === "strict") {
        block = true;
        blockReason = `SpiderShield: BLOCKED — secret in parameters`;
      } else {
        modifiedParams = dlp.redactParams(params, dlpFindings);
      }
    }
  }

  const latencyMs = Date.now() - startMs;
  const decision = block ? "deny" : "allow";

  if (block || verdict !== "safe" || dlpFindings.secrets.length > 0) {
    console.error(
      `[SpiderShield Proxy] ${block ? "BLOCKED" : verdict.toUpperCase()} ${toolName} — score: ${score ?? "?"}, policy: ${policyDecision ?? "-"}, DLP: ${dlpFindings.secrets.length}s/${dlpFindings.pii.length}p (${latencyMs}ms)`
    );
  }

  audit.log({
    phase: "before_tool_call",
    toolName,
    decision,
    verdict,
    score,
    grade,
    dlpSecrets: dlpFindings.secrets.length,
    dlpPii: dlpFindings.pii.length,
    policy: POLICY_MODE,
    latencyMs,
  });

  return { block, blockReason, modifiedParams };
}
