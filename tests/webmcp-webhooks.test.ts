/**
 * Tests for WebMCP Webhooks tool registration.
 *
 * Validates correct API endpoints, auth headers, query parameter encoding,
 * and error handling for the browser-side WebMCP tool layer.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  type AuthContext,
  type WebMCPRegistry,
  registerWebhooksTools,
} from "../src/webmcp-webhooks.js";

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function mockJsonResponse(data: unknown, ok = true, status = 200) {
  return {
    ok,
    status,
    json: vi.fn().mockResolvedValue(data),
  };
}

function createRegistry(): WebMCPRegistry {
  const tools = new Map<string, { name: string; handler: Function; [k: string]: unknown }>();
  return {
    register(tool: { name: string; handler: Function }) {
      tools.set(tool.name, tool);
    },
    get(name: string) {
      return tools.get(name) as any;
    },
    list() {
      return [...tools.keys()];
    },
  };
}

function getTool(registry: WebMCPRegistry, name: string) {
  const tool = registry.get(name);
  if (!tool) throw new Error(`Tool "${name}" not registered`);
  return tool;
}

describe("registerWebhooksTools", () => {
  let registry: WebMCPRegistry;
  const API_BASE = "/api";

  beforeEach(() => {
    registry = createRegistry();
    mockFetch.mockReset();
  });

  it("should register all 3 tools", () => {
    registerWebhooksTools(registry, API_BASE);

    const names = registry.list();
    expect(names).toHaveLength(3);
    expect(names).toContain("listWebhooks");
    expect(names).toContain("getWebhookHistory");
    expect(names).toContain("getWebhookUrl");
  });

  it("should use default apiBase when not provided", () => {
    registerWebhooksTools(registry);

    expect(registry.list()).toHaveLength(3);
  });

  describe("listWebhooks", () => {
    it("should GET /plugins/webhooks/endpoints", async () => {
      const endpoints = [
        { id: "gmail", action: "agent", matchPath: "gmail" },
      ];
      mockFetch.mockResolvedValue(mockJsonResponse(endpoints));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "listWebhooks");
      const result = await tool.handler({}, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/endpoints",
        expect.any(Object),
      );
      expect(result).toEqual(endpoints);
    });

    it("should include bearer token when auth.token is present", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse([]));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "listWebhooks");
      const auth: AuthContext = { token: "my-token" };
      await tool.handler({}, auth);

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBe("Bearer my-token");
    });

    it("should not include Authorization header when no token", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse([]));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "listWebhooks");
      await tool.handler({}, {});

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBeUndefined();
    });
  });

  describe("getWebhookHistory", () => {
    it("should GET /plugins/webhooks/history with no params", async () => {
      const history = { deliveries: [] };
      mockFetch.mockResolvedValue(mockJsonResponse(history));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      const result = await tool.handler({}, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history",
        expect.any(Object),
      );
      expect(result).toEqual(history);
    });

    it("should include webhookId query parameter", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({ webhookId: "gmail" }, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history?webhookId=gmail",
        expect.any(Object),
      );
    });

    it("should include limit query parameter", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({ limit: 10 }, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history?limit=10",
        expect.any(Object),
      );
    });

    it("should include both webhookId and limit", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({ webhookId: "github", limit: 5 }, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history?webhookId=github&limit=5",
        expect.any(Object),
      );
    });

    it("should URL-encode webhookId", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({ webhookId: "hook with spaces&special=chars" }, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history?webhookId=hook%20with%20spaces%26special%3Dchars",
        expect.any(Object),
      );
    });

    it("should ignore empty webhookId", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({ webhookId: "" }, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history",
        expect.any(Object),
      );
    });

    it("should floor limit to integer", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({ limit: 7.8 }, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/history?limit=7",
        expect.any(Object),
      );
    });

    it("should include bearer token in auth header", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ deliveries: [] }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");
      await tool.handler({}, { token: "tok-history" });

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBe("Bearer tok-history");
    });
  });

  describe("getWebhookUrl", () => {
    it("should GET /plugins/webhooks/url", async () => {
      const urlInfo = { url: "http://localhost:7438/hooks", basePath: "/hooks", port: 7438, isPublic: false };
      mockFetch.mockResolvedValue(mockJsonResponse(urlInfo));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookUrl");
      const result = await tool.handler({}, {});

      expect(mockFetch).toHaveBeenCalledWith(
        "/api/plugins/webhooks/url",
        expect.any(Object),
      );
      expect(result).toEqual(urlInfo);
    });

    it("should include bearer token in auth header", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({ url: null }));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookUrl");
      await tool.handler({}, { token: "tok-url" });

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers.Authorization).toBe("Bearer tok-url");
    });
  });

  describe("error handling", () => {
    it("should throw on non-ok response with error from body", async () => {
      mockFetch.mockResolvedValue(
        mockJsonResponse({ error: "Webhooks plugin not loaded" }, false, 404),
      );
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "listWebhooks");

      await expect(tool.handler({}, {})).rejects.toThrow("Webhooks plugin not loaded");
    });

    it("should throw with status code when body has no error field", async () => {
      mockFetch.mockResolvedValue(mockJsonResponse({}, false, 500));
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookUrl");

      await expect(tool.handler({}, {})).rejects.toThrow("Request failed (500)");
    });

    it("should handle json parse failure on error response", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 502,
        json: vi.fn().mockRejectedValue(new Error("invalid json")),
      });
      registerWebhooksTools(registry, API_BASE);

      const tool = getTool(registry, "getWebhookHistory");

      await expect(tool.handler({}, {})).rejects.toThrow("Request failed");
    });
  });
});
