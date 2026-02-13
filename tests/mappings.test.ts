import { describe, it, expect, beforeEach } from "vitest";
import {
  resolveMappings,
  applyMappings,
  clearTransformCache,
} from "../src/mappings.js";
import type {
  WebhooksConfig,
  HookMappingResolved,
  HookMappingContext,
} from "../src/types.js";

// ============================================================================
// Test Helpers
// ============================================================================

function makeMappingCtx(overrides: Partial<HookMappingContext> = {}): HookMappingContext {
  return {
    payload: {},
    headers: {},
    url: new URL("http://localhost/hooks"),
    path: "",
    ...overrides,
  };
}

// ============================================================================
// resolveMappings
// ============================================================================

describe("resolveMappings", () => {
  it("returns empty array when no mappings or presets", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
    };
    const result = resolveMappings(config, "/data");
    expect(result).toEqual([]);
  });

  it("resolves user-defined mappings", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      mappings: [
        {
          id: "my-hook",
          match: { path: "custom" },
          action: "agent",
          messageTemplate: "Event: {{event}}",
        },
      ],
    };
    const result = resolveMappings(config, "/data");
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("my-hook");
    expect(result[0].matchPath).toBe("custom");
    expect(result[0].action).toBe("agent");
    expect(result[0].messageTemplate).toBe("Event: {{event}}");
  });

  it("resolves gmail preset", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      presets: ["gmail"],
    };
    const result = resolveMappings(config, "/data");
    expect(result.length).toBeGreaterThan(0);
    expect(result.some((m) => m.id === "gmail")).toBe(true);
  });

  it("resolves github preset", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      presets: ["github"],
    };
    const result = resolveMappings(config, "/data");
    expect(result.length).toBeGreaterThan(0);
    expect(result.some((m) => m.id === "github-push")).toBe(true);
    expect(result.some((m) => m.id === "github-pr")).toBe(true);
    expect(result.some((m) => m.id === "github-issue")).toBe(true);
  });

  it("resolves slack preset", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      presets: ["slack"],
    };
    const result = resolveMappings(config, "/data");
    expect(result.some((m) => m.id === "slack-event")).toBe(true);
  });

  it("ignores unknown presets", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      presets: ["nonexistent"],
    };
    const result = resolveMappings(config, "/data");
    expect(result).toEqual([]);
  });

  it("puts user mappings before preset mappings", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      presets: ["gmail"],
      mappings: [
        {
          id: "user-first",
          match: { path: "custom" },
          action: "agent",
        },
      ],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].id).toBe("user-first");
  });

  it("assigns default IDs to mappings without ids", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      mappings: [
        { match: { path: "a" }, action: "agent" },
        { match: { path: "b" }, action: "agent" },
      ],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].id).toBe("mapping-1");
    expect(result[1].id).toBe("mapping-2");
  });

  it("defaults action to agent", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      mappings: [{ match: { path: "test" } }],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].action).toBe("agent");
  });

  it("defaults wakeMode to now", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      mappings: [{ match: { path: "test" } }],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].wakeMode).toBe("now");
  });

  it("normalizes match path (strips slashes)", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      mappings: [{ match: { path: "/custom/" } }],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].matchPath).toBe("custom");
  });

  it("applies gmail allowUnsafeExternalContent to preset", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      presets: ["gmail"],
      gmail: { allowUnsafeExternalContent: true },
    };
    const result = resolveMappings(config, "/data");
    const gmailMapping = result.find((m) => m.id === "gmail");
    expect(gmailMapping?.allowUnsafeExternalContent).toBe(true);
  });

  it("resolves transform paths relative to transformsDir", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      transformsDir: "hooks",
      mappings: [
        {
          match: { path: "test" },
          transform: { module: "my-transform.js" },
        },
      ],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].transform?.modulePath).toBe("/data/hooks/my-transform.js");
  });

  it("resolves absolute transform paths as-is", () => {
    const config: WebhooksConfig = {
      enabled: true,
      token: "test",
      mappings: [
        {
          match: { path: "test" },
          transform: { module: "/absolute/path/transform.js" },
        },
      ],
    };
    const result = resolveMappings(config, "/data");
    expect(result[0].transform?.modulePath).toBe("/absolute/path/transform.js");
  });
});

// ============================================================================
// applyMappings
// ============================================================================

describe("applyMappings", () => {
  beforeEach(() => {
    clearTransformCache();
  });

  it("returns null when no mappings", async () => {
    const result = await applyMappings([], makeMappingCtx());
    expect(result).toBeNull();
  });

  it("returns null when no mapping matches", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "gmail",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "test",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "slack" })
    );
    expect(result).toBeNull();
  });

  it("matches by path", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "gmail",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Got email",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "gmail" })
    );
    expect(result).not.toBeNull();
    expect(result?.ok).toBe(true);
    if (result?.ok && "action" in result && result.action) {
      expect(result.action.kind).toBe("agent");
      if (result.action.kind === "agent") {
        expect(result.action.message).toBe("Got email");
      }
    }
  });

  it("matches by source", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "github",
        matchSource: "push",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Push event",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "github", payload: { source: "push" } })
    );
    expect(result?.ok).toBe(true);
  });

  it("rejects source mismatch", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "github",
        matchSource: "push",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Push event",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "github", payload: { source: "issues" } })
    );
    expect(result).toBeNull();
  });

  it("renders template with payload values", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "custom",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Hello {{user}}, event: {{event}}",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({
        path: "custom",
        payload: { user: "alice", event: "login" },
      })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.message).toBe("Hello alice, event: login");
    }
  });

  it("renders nested payload values in template", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "custom",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Repo: {{repository.full_name}}",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({
        path: "custom",
        payload: { repository: { full_name: "org/repo" } },
      })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.message).toBe("Repo: org/repo");
    }
  });

  it("renders array index in template", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "custom",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "First: {{items[0]}}",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({
        path: "custom",
        payload: { items: ["apple", "banana"] },
      })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.message).toBe("First: apple");
    }
  });

  it("renders missing template vars as empty string", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "custom",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Name: {{name}}, Missing: {{nonexistent}}",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({
        path: "custom",
        payload: { name: "test" },
      })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.message).toBe("Name: test, Missing: ");
    }
  });

  it("builds wake action with session", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "notify",
        action: "wake",
        wakeMode: "now",
        session: "main",
        textTemplate: "Alert: {{msg}}",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({
        path: "notify",
        payload: { msg: "fire" },
      })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "wake") {
      expect(result.action.text).toBe("Alert: fire");
      expect(result.action.session).toBe("main");
      expect(result.action.mode).toBe("now");
    }
  });

  it("returns error when wake action has no session", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "m1",
        matchPath: "notify",
        action: "wake",
        wakeMode: "now",
        textTemplate: "Alert",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "notify" })
    );
    expect(result?.ok).toBe(false);
    if (result && !result.ok) {
      expect(result.error).toContain("session");
    }
  });

  it("uses first matching mapping and ignores rest", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "first",
        matchPath: "test",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "First match",
      },
      {
        id: "second",
        matchPath: "test",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Second match",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "test" })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.message).toBe("First match");
    }
  });

  it("matches mapping without matchPath (wildcard)", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "catchall",
        action: "agent",
        wakeMode: "now",
        messageTemplate: "Caught: {{data}}",
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "anything", payload: { data: "value" } })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.message).toBe("Caught: value");
    }
  });

  it("carries through agent action options", async () => {
    const mappings: HookMappingResolved[] = [
      {
        id: "full",
        matchPath: "test",
        action: "agent",
        wakeMode: "next-heartbeat",
        messageTemplate: "msg",
        name: "TestHook",
        sessionKey: "session-{{id}}",
        deliver: true,
        channel: "discord",
        to: "user",
        model: "gpt-4",
        thinking: "high",
        timeoutSeconds: 60,
        allowUnsafeExternalContent: true,
      },
    ];
    const result = await applyMappings(
      mappings,
      makeMappingCtx({ path: "test", payload: { id: "123" } })
    );
    expect(result?.ok).toBe(true);
    if (result?.ok && result.action && result.action.kind === "agent") {
      expect(result.action.wakeMode).toBe("next-heartbeat");
      expect(result.action.name).toBe("TestHook");
      expect(result.action.sessionKey).toBe("session-123");
      expect(result.action.deliver).toBe(true);
      expect(result.action.channel).toBe("discord");
      expect(result.action.to).toBe("user");
      expect(result.action.model).toBe("gpt-4");
      expect(result.action.thinking).toBe("high");
      expect(result.action.timeoutSeconds).toBe(60);
      expect(result.action.allowUnsafeExternalContent).toBe(true);
    }
  });
});
