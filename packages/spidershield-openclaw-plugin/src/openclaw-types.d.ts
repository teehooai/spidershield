/**
 * Minimal type declarations for OpenClaw Plugin SDK.
 * Extracted from openclaw@2026.3.22 plugin-sdk/src/plugins/types.d.ts
 *
 * These types allow compilation without installing the full openclaw package.
 * At runtime, openclaw provides the real implementations.
 */

declare module "openclaw/plugin-sdk" {
  export type PluginLogger = {
    debug?: (message: string) => void;
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
  };

  export type PluginHookToolContext = {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    toolName: string;
    toolCallId?: string;
  };

  export type PluginHookBeforeToolCallEvent = {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
  };

  export type PluginHookBeforeToolCallResult = {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
  };

  export type PluginHookAfterToolCallEvent = {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
    result?: unknown;
    error?: string;
    durationMs?: number;
  };

  export type OpenClawPluginApi = {
    id: string;
    name: string;
    pluginConfig?: Record<string, unknown>;
    logger: PluginLogger;
    registerTool: (tool: unknown, opts?: { name?: string }) => void;
    registerHook: (
      events: string | string[],
      handler: (...args: unknown[]) => unknown,
      opts?: { name?: string; description?: string }
    ) => void;
    on: {
      (
        hookName: "before_tool_call",
        handler: (
          event: PluginHookBeforeToolCallEvent,
          ctx: PluginHookToolContext
        ) =>
          | Promise<PluginHookBeforeToolCallResult | void>
          | PluginHookBeforeToolCallResult
          | void,
        opts?: { priority?: number }
      ): void;
      (
        hookName: "after_tool_call",
        handler: (
          event: PluginHookAfterToolCallEvent,
          ctx: PluginHookToolContext
        ) => Promise<void> | void,
        opts?: { priority?: number }
      ): void;
      (
        hookName: "message_sending",
        handler: (event: unknown) => Promise<void> | void,
        opts?: { priority?: number }
      ): void;
      (
        hookName: string,
        handler: (...args: unknown[]) => unknown,
        opts?: { priority?: number }
      ): void;
    };
  };
}
