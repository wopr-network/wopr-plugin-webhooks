import { describe, it, expect } from "vitest";

// ============================================================================
// Plugin Smoke Test
// ============================================================================

describe("webhooks plugin", () => {
  it("exports a valid WOPRPlugin object as default", async () => {
    const mod = await import("../src/index.js");
    const plugin = mod.default;

    expect(plugin).toBeDefined();
    expect(plugin.name).toBe("wopr-plugin-webhooks");
    expect(plugin.version).toBe("1.0.0");
    expect(typeof plugin.init).toBe("function");
    expect(typeof plugin.shutdown).toBe("function");
  });

  it("has a description", async () => {
    const mod = await import("../src/index.js");
    expect(mod.default.description).toBeDefined();
    expect(typeof mod.default.description).toBe("string");
  });

  it("registers webhooks command", async () => {
    const mod = await import("../src/index.js");
    const plugin = mod.default;

    expect(plugin.commands).toBeDefined();
    expect(Array.isArray(plugin.commands)).toBe(true);
    expect(plugin.commands!.length).toBeGreaterThan(0);

    const webhooksCmd = plugin.commands!.find((c) => c.name === "webhooks");
    expect(webhooksCmd).toBeDefined();
    expect(webhooksCmd!.description).toBeDefined();
    expect(typeof webhooksCmd!.handler).toBe("function");
  });
});
