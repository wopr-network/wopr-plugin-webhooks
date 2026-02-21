import { createServer } from "node:http";
import { describe, it, expect, vi, afterEach } from "vitest";

// Import the plugin default export
import plugin from "../src/index.js";

/**
 * Find a free port by letting the OS pick one.
 */
function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

/**
 * Create a minimal mock WOPRPluginContext for testing.
 */
function createMockContext(overrides: Record<string, unknown> = {}) {
  const events = {
    on: vi.fn().mockReturnValue(() => {}),
    off: vi.fn(),
    emit: vi.fn().mockResolvedValue(undefined),
    emitCustom: vi.fn().mockResolvedValue(undefined),
  };

  return {
    log: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
    events,
    getConfig: vi.fn().mockReturnValue(undefined),
    getMainConfig: vi.fn().mockReturnValue(undefined),
    registerConfigSchema: vi.fn(),
    registerExtension: vi.fn(),
    unregisterExtension: vi.fn(),
    getExtension: vi.fn(),
    inject: vi.fn().mockResolvedValue("ok"),
    logMessage: vi.fn(),
    getChannelProviders: vi.fn().mockReturnValue([]),
    getChannelProvider: vi.fn(),
    ...overrides,
  };
}

describe("wopr-plugin-webhooks lifecycle", () => {
  afterEach(async () => {
    // Always shut down between tests to reset module state
    await plugin.shutdown?.();
  });

  it("exports a valid WOPRPlugin object", () => {
    expect(plugin).toBeDefined();
    expect(plugin.name).toBe("wopr-plugin-webhooks");
    expect(plugin.version).toBe("1.0.0");
    expect(typeof plugin.init).toBe("function");
    expect(typeof plugin.shutdown).toBe("function");
  });

  it("has a default export (not named)", async () => {
    // The module's default export should be the plugin
    const mod = await import("../src/index.js");
    expect(mod.default).toBe(plugin);
  });

  it("has a manifest with required fields", () => {
    expect(plugin.manifest).toBeDefined();
    expect(plugin.manifest!.capabilities).toContain("webhooks");
    expect(plugin.manifest!.category).toBe("integration");
    expect(plugin.manifest!.tags).toEqual(expect.arrayContaining(["webhooks", "http"]));
    expect(plugin.manifest!.icon).toBe("🪝");
    expect(plugin.manifest!.lifecycle).toBeDefined();
    expect(plugin.manifest!.configSchema).toBeDefined();
  });

  it("has a configSchema with fields (via manifest)", () => {
    expect(plugin.manifest).toBeDefined();
    const schema = plugin.manifest!.configSchema as { fields: { name: string }[] } | undefined;
    expect(schema).toBeDefined();
    const fields = schema!.fields;
    expect(fields.length).toBeGreaterThanOrEqual(3);
    const names = fields.map((f) => f.name);
    expect(names).toContain("enabled");
    expect(names).toContain("token");
    expect(names).toContain("port");
  });

  it("init() registers config schema when called (disabled mode)", async () => {
    const mockCtx = createMockContext();
    await plugin.init!(mockCtx as never);

    expect(mockCtx.registerConfigSchema).toHaveBeenCalledWith(
      "wopr-plugin-webhooks",
      expect.objectContaining({ title: "Webhooks" }),
    );
  });

  it("init() logs disabled message when webhooks not enabled", async () => {
    const mockCtx = createMockContext();
    await plugin.init!(mockCtx as never);

    expect(mockCtx.log.info).toHaveBeenCalledWith(expect.stringContaining("disabled"));
  });

  it("shutdown() can be called without init()", async () => {
    // Should not throw
    await expect(plugin.shutdown!()).resolves.not.toThrow();
  });

  it("shutdown() resets state after init()", async () => {
    const mockCtx = createMockContext();
    await plugin.init!(mockCtx as never);
    await plugin.shutdown!();

    // After shutdown, re-init should work cleanly
    const mockCtx2 = createMockContext();
    await plugin.init!(mockCtx2 as never);
    expect(mockCtx2.registerConfigSchema).toHaveBeenCalled();
  });

  it("shutdown() unregisters extension when webhooks were enabled", async () => {
    const port = await getFreePort();
    const mockCtx = createMockContext({
      getMainConfig: vi.fn().mockReturnValue({
        enabled: true,
        token: "test-secret-token",
        port,
      }),
    });

    await plugin.init!(mockCtx as never);
    await plugin.shutdown!();

    expect(mockCtx.unregisterExtension).toHaveBeenCalledWith("webhooks");
  });

  it("shutdown() unsubscribes event listeners when enabled", async () => {
    const port = await getFreePort();
    let capturedHandler: ((...args: unknown[]) => void) | undefined;
    const unsubscribeSpy = vi.fn();
    const mockCtx = createMockContext({
      getMainConfig: vi.fn().mockReturnValue({
        enabled: true,
        token: "test-secret-token",
        port,
      }),
      events: {
        on: vi.fn().mockImplementation((_event: string, handler: (...args: unknown[]) => void) => {
          capturedHandler = handler;
          return unsubscribeSpy;
        }),
        off: vi.fn(),
        emit: vi.fn().mockResolvedValue(undefined),
        emitCustom: vi.fn().mockResolvedValue(undefined),
      },
    });

    await plugin.init!(mockCtx as never);

    // events.on should have been called during init
    expect((mockCtx.events as { on: ReturnType<typeof vi.fn> }).on).toHaveBeenCalled();
    expect(capturedHandler).toBeDefined();

    await plugin.shutdown!();

    // The unsubscribe function returned by events.on("*", ...) should have been called
    expect(unsubscribeSpy).toHaveBeenCalled();
    expect(mockCtx.unregisterExtension).toHaveBeenCalled();
  });
});
