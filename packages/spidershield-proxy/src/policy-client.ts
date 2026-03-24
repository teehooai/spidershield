/**
 * Policy Client — fetches auto-generated policy templates from SpiderRating API.
 *
 * When the plugin encounters a new MCP server, it queries the Policy API
 * to get recommended allow/deny/escalate rules based on scan data.
 * Results are cached locally to avoid repeated API calls.
 *
 * Flow:
 *   1. before_tool_call sees mcp__stripe__create_charge
 *   2. Extract server name: "stripe"
 *   3. Check local cache → miss
 *   4. Query /v1/public/policy?server=stripe/stripe-agent-toolkit
 *   5. Cache rules locally (24h TTL)
 *   6. Apply rule: create_charge → "write" → allow
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export type PolicyRule = {
  tool: string;
  decision: "allow" | "deny" | "escalate";
  category: string;
  reason?: string;
  note?: string;
};

export type ServerPolicy = {
  server: string;
  score: number | null;
  grade: string | null;
  rules: PolicyRule[];
  warnings: string[];
  fetchedAt: number;
};

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const TIMEOUT_MS = 3000;

export class PolicyClient {
  private cache = new Map<string, ServerPolicy>();
  private apiUrl: string;
  private cacheDir: string;

  constructor(apiUrl: string) {
    this.apiUrl = apiUrl.replace(/\/$/, "");
    this.cacheDir = join(homedir(), ".spidershield", "policies");
    try {
      mkdirSync(this.cacheDir, { recursive: true });
    } catch {
      // best-effort
    }
    this.loadLocalCache();
  }

  /**
   * Get the policy decision for a specific tool on a server.
   * Returns the matching rule, or null if no policy/rule found.
   */
  async getDecision(
    serverName: string,
    toolName: string
  ): Promise<PolicyRule | null> {
    const policy = await this.getServerPolicy(serverName);
    if (!policy || policy.rules.length === 0) return null;

    // Extract short tool name: mcp__stripe__create_charge → create_charge
    const shortName = toolName.includes("__")
      ? toolName.split("__").slice(-1)[0]
      : toolName;

    // Find matching rule (exact match or wildcard)
    for (const rule of policy.rules) {
      if (rule.tool === shortName) return rule;
      if (rule.tool.endsWith("*")) {
        const prefix = rule.tool.slice(0, -1);
        if (shortName.startsWith(prefix)) return rule;
      }
    }

    return null;
  }

  /**
   * Get full server policy, fetching from API if not cached.
   */
  async getServerPolicy(serverName: string): Promise<ServerPolicy | null> {
    // 1. Memory cache
    const cached = this.cache.get(serverName);
    if (cached && cached.fetchedAt + CACHE_TTL_MS > Date.now()) {
      return cached;
    }

    // 2. API fetch
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      // Try server name as repo (most common pattern)
      const res = await fetch(
        `${this.apiUrl}/v1/public/policy?server=${encodeURIComponent(serverName)}`,
        { signal: controller.signal }
      );
      clearTimeout(timeout);

      if (!res.ok) return null;

      const data = (await res.json()) as Record<string, unknown>;
      if (data.error || !Array.isArray(data.rules)) return null;

      const policy: ServerPolicy = {
        server: (data.server as string) || serverName,
        score: typeof data.score === "number" ? data.score : null,
        grade: typeof data.grade === "string" ? data.grade : null,
        rules: (data.rules as PolicyRule[]) || [],
        warnings: (data.warnings as string[]) || [],
        fetchedAt: Date.now(),
      };

      // 3. Cache
      this.cache.set(serverName, policy);
      this.saveToLocal(serverName, policy);

      return policy;
    } catch {
      // Timeout/network error — check local file cache
      return this.loadFromLocal(serverName);
    }
  }

  private saveToLocal(serverName: string, policy: ServerPolicy): void {
    try {
      const fileName = serverName.replace(/\//g, "__") + ".json";
      const filePath = join(this.cacheDir, fileName);
      writeFileSync(filePath, JSON.stringify(policy, null, 2));
    } catch {
      // best-effort
    }
  }

  private loadFromLocal(serverName: string): ServerPolicy | null {
    try {
      const fileName = serverName.replace(/\//g, "__") + ".json";
      const filePath = join(this.cacheDir, fileName);
      const data = JSON.parse(readFileSync(filePath, "utf-8")) as ServerPolicy;
      if (data && data.fetchedAt + CACHE_TTL_MS > Date.now()) {
        this.cache.set(serverName, data);
        return data;
      }
    } catch {
      // no local cache
    }
    return null;
  }

  private loadLocalCache(): void {
    try {
      const { readdirSync } = require("node:fs") as typeof import("node:fs");
      const files = readdirSync(this.cacheDir).filter((f: string) =>
        f.endsWith(".json")
      );
      for (const file of files) {
        try {
          const data = JSON.parse(
            readFileSync(join(this.cacheDir, file), "utf-8")
          ) as ServerPolicy;
          if (data?.server && data.fetchedAt + CACHE_TTL_MS > Date.now()) {
            const key = file.replace(/__/g, "/").replace(/\.json$/, "");
            this.cache.set(key, data);
          }
        } catch {
          // skip corrupt files
        }
      }
    } catch {
      // no cache dir yet
    }
  }
}
