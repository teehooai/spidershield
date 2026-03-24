/**
 * Audit Logger — local JSONL + optional cloud upload (Pro tier).
 *
 * Local: ~/.spidershield/audit/YYYY-MM-DD.jsonl
 * Cloud: POST /api/v1/audit/events (batched, best-effort)
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export type AuditEvent = {
  phase: string;
  toolName: string;
  agentId?: string;
  sessionId?: string;
  decision: string;
  verdict?: string;
  score?: number | null;
  grade?: string | null;
  policyRule?: string | null;
  policyReason?: string | null;
  error?: string | null;
  durationMs?: number | null;
  dlpSecrets?: number;
  dlpPii?: number;
  policy?: string;
  latencyMs?: number;
};

const BATCH_SIZE = 20;
const FLUSH_INTERVAL_MS = 30_000;

export class AuditLogger {
  private logDir: string;
  private apiUrl: string;
  private apiKey: string | undefined;
  private buffer: Array<Record<string, unknown>> = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(apiUrl: string, apiKey?: string) {
    this.apiUrl = apiUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.logDir = join(homedir(), ".spidershield", "audit");

    try {
      mkdirSync(this.logDir, { recursive: true });
    } catch {
      // best-effort
    }

    // Periodic flush for cloud upload
    if (this.apiKey) {
      this.flushTimer = setInterval(() => this.flush(), FLUSH_INTERVAL_MS);
    }
  }

  log(event: AuditEvent): void {
    const record = {
      timestamp: new Date().toISOString(),
      ...event,
    };

    // 1. Local JSONL (always)
    this.writeLocal(record);

    // 2. Buffer for cloud upload (Pro only)
    if (this.apiKey) {
      this.buffer.push(record);
      if (this.buffer.length >= BATCH_SIZE) {
        this.flush();
      }
    }
  }

  private writeLocal(record: Record<string, unknown>): void {
    try {
      const date = new Date().toISOString().split("T")[0];
      const filePath = join(this.logDir, `${date}.jsonl`);
      appendFileSync(filePath, JSON.stringify(record) + "\n");
    } catch {
      // best-effort — don't crash the agent
    }
  }

  private flush(): void {
    if (this.buffer.length === 0 || !this.apiKey) return;

    const events = this.buffer.splice(0);

    // Fire and forget — don't block tool calls
    fetch(`${this.apiUrl}/api/v1/audit/events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": this.apiKey,
      },
      body: JSON.stringify({ events }),
    }).catch(() => {
      // best-effort — local log is the source of truth
    });
  }

  destroy(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    this.flush();
  }
}
