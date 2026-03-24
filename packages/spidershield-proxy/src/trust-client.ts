/**
 * Trust Score Client — queries SpiderRating API with in-memory cache.
 *
 * Cache TTL: 24 hours (scores don't change faster than daily pipeline scans).
 * Timeout: 2 seconds (if API is down, tool call proceeds with "unknown" verdict).
 */

export type TrustResult = {
  verdict: "safe" | "risky" | "malicious" | "unknown";
  score: number | null;
  grade: string | null;
  message: string;
};

type CacheEntry = {
  result: TrustResult;
  expiresAt: number;
};

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const TIMEOUT_MS = 2000;

export class TrustScoreClient {
  private cache = new Map<string, CacheEntry>();
  private apiUrl: string;

  constructor(apiUrl: string) {
    this.apiUrl = apiUrl.replace(/\/$/, "");
  }

  async check(toolName: string): Promise<TrustResult> {
    // 1. Cache hit
    const cached = this.cache.get(toolName);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.result;
    }

    // 2. API call
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const res = await fetch(
        `${this.apiUrl}/v1/public/check?tool=${encodeURIComponent(toolName)}`,
        { signal: controller.signal }
      );
      clearTimeout(timeout);

      if (!res.ok) {
        return this.unknown("API returned " + res.status);
      }

      const data = (await res.json()) as Record<string, unknown>;
      const result: TrustResult = {
        verdict: (data.verdict as TrustResult["verdict"]) || "unknown",
        score: typeof data.score === "number" ? data.score : null,
        grade: typeof data.grade === "string" ? data.grade : null,
        message: typeof data.message === "string" ? data.message : "",
      };

      // 3. Cache write
      this.cache.set(toolName, {
        result,
        expiresAt: Date.now() + CACHE_TTL_MS,
      });

      return result;
    } catch {
      // Timeout or network error — don't block
      return this.unknown("API unreachable");
    }
  }

  private unknown(reason: string): TrustResult {
    return {
      verdict: "unknown",
      score: null,
      grade: null,
      message: reason,
    };
  }
}
