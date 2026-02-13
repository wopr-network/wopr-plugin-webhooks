/**
 * Tests for WebhooksWebMCPExtension methods.
 *
 * Validates structured data output, null config handling,
 * delivery history recording, and sensitive data redaction.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
  createWebhooksExtension,
  recordDelivery,
  clearDeliveryHistory,
} from "../src/webhooks-extension.js";
import type { WebhooksConfigResolved } from "../src/types.js";

function createMockConfig(overrides?: Partial<WebhooksConfigResolved>): WebhooksConfigResolved {
  return {
    basePath: "/hooks",
    token: "test-token",
    maxBodyBytes: 262144,
    mappings: [
      {
        id: "gmail",
        matchPath: "gmail",
        action: "agent",
        wakeMode: "now",
        name: "Gmail",
      },
      {
        id: "github-pr",
        matchPath: "github",
        matchSource: "pull_request",
        action: "agent",
        wakeMode: "now",
        name: "GitHub PR",
        transform: { modulePath: "/transforms/github.js" },
      },
      {
        id: "slack-wake",
        action: "wake",
        wakeMode: "next-heartbeat",
        session: "main",
        name: "Slack Wake",
      },
    ],
    ...overrides,
  };
}

afterEach(() => {
  clearDeliveryHistory();
});

describe("createWebhooksExtension", () => {
  describe("listWebhooks", () => {
    it("should return empty array when config is null", () => {
      const ext = createWebhooksExtension(
        () => null,
        () => null,
        () => null,
      );
      expect(ext.listWebhooks()).toEqual([]);
    });

    it("should return endpoint info for all configured mappings", () => {
      const config = createMockConfig();
      const ext = createWebhooksExtension(
        () => config,
        () => 7438,
        () => null,
      );

      const webhooks = ext.listWebhooks();
      expect(webhooks).toHaveLength(3);
      expect(webhooks[0]).toEqual({
        id: "gmail",
        action: "agent",
        matchPath: "gmail",
        matchSource: undefined,
        name: "Gmail",
        wakeMode: "now",
        hasTransform: false,
      });
      expect(webhooks[1]).toEqual({
        id: "github-pr",
        action: "agent",
        matchPath: "github",
        matchSource: "pull_request",
        name: "GitHub PR",
        wakeMode: "now",
        hasTransform: true,
      });
      expect(webhooks[2]).toEqual({
        id: "slack-wake",
        action: "wake",
        matchPath: undefined,
        matchSource: undefined,
        name: "Slack Wake",
        wakeMode: "next-heartbeat",
        hasTransform: false,
      });
    });

    it("should return empty array when config has no mappings", () => {
      const config = createMockConfig({ mappings: [] });
      const ext = createWebhooksExtension(
        () => config,
        () => 7438,
        () => null,
      );
      expect(ext.listWebhooks()).toEqual([]);
    });
  });

  describe("getWebhookHistory", () => {
    it("should return empty array with no deliveries", () => {
      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );
      expect(ext.getWebhookHistory()).toEqual([]);
    });

    it("should return recorded deliveries in reverse chronological order", () => {
      recordDelivery({
        webhookId: "gmail",
        timestamp: "2026-01-01T00:00:00Z",
        status: "success",
        httpStatus: 200,
        path: "gmail",
        action: "agent",
        payload: { from: "user@example.com" },
      });
      recordDelivery({
        webhookId: "slack",
        timestamp: "2026-01-01T00:01:00Z",
        status: "error",
        httpStatus: 400,
        path: "slack",
        action: "agent",
        payload: { text: "hello" },
        error: "No mapping found",
      });

      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      const history = ext.getWebhookHistory();
      expect(history).toHaveLength(2);
      // Most recent first
      expect(history[0].webhookId).toBe("slack");
      expect(history[0].status).toBe("error");
      expect(history[0].error).toBe("No mapping found");
      expect(history[1].webhookId).toBe("gmail");
      expect(history[1].status).toBe("success");
    });

    it("should filter by webhookId when provided", () => {
      recordDelivery({
        webhookId: "gmail",
        timestamp: "2026-01-01T00:00:00Z",
        status: "success",
        httpStatus: 200,
        path: "gmail",
        action: "agent",
        payload: {},
      });
      recordDelivery({
        webhookId: "slack",
        timestamp: "2026-01-01T00:01:00Z",
        status: "success",
        httpStatus: 200,
        path: "slack",
        action: "agent",
        payload: {},
      });
      recordDelivery({
        webhookId: "gmail",
        timestamp: "2026-01-01T00:02:00Z",
        status: "success",
        httpStatus: 200,
        path: "gmail",
        action: "agent",
        payload: {},
      });

      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      const history = ext.getWebhookHistory("gmail");
      expect(history).toHaveLength(2);
      expect(history.every((d) => d.webhookId === "gmail")).toBe(true);
    });

    it("should respect limit parameter", () => {
      for (let i = 0; i < 10; i++) {
        recordDelivery({
          webhookId: "test",
          timestamp: `2026-01-01T00:0${i}:00Z`,
          status: "success",
          httpStatus: 200,
          path: "test",
          action: "agent",
          payload: { index: i },
        });
      }

      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      const history = ext.getWebhookHistory(undefined, 3);
      expect(history).toHaveLength(3);
    });

    it("should redact sensitive fields in payload", () => {
      recordDelivery({
        webhookId: "test",
        timestamp: "2026-01-01T00:00:00Z",
        status: "success",
        httpStatus: 200,
        path: "test",
        action: "agent",
        payload: {
          message: "hello",
          token: "secret-value",
          api_key: "key-123",
          nested: {
            password: "p@ssw0rd",
            data: "safe-data",
          },
        },
      });

      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      const history = ext.getWebhookHistory();
      expect(history[0].payload.message).toBe("hello");
      expect(history[0].payload.token).toBe("[REDACTED]");
      expect(history[0].payload.api_key).toBe("[REDACTED]");
      const nested = history[0].payload.nested as Record<string, unknown>;
      expect(nested.password).toBe("[REDACTED]");
      expect(nested.data).toBe("safe-data");
    });

    it("should redact sensitive fields in arrays", () => {
      recordDelivery({
        webhookId: "test",
        timestamp: "2026-01-01T00:00:00Z",
        status: "success",
        httpStatus: 200,
        path: "test",
        action: "agent",
        payload: {
          items: [
            { name: "item1", secret: "s3cret" },
            { name: "item2", access_token: "tok123" },
          ],
        },
      });

      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      const history = ext.getWebhookHistory();
      const items = history[0].payload.items as Record<string, unknown>[];
      expect(items[0].name).toBe("item1");
      expect(items[0].secret).toBe("[REDACTED]");
      expect(items[1].access_token).toBe("[REDACTED]");
    });
  });

  describe("getWebhookUrl", () => {
    it("should return local URL when no public URL is available", () => {
      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      const urlInfo = ext.getWebhookUrl();
      expect(urlInfo).toEqual({
        url: "http://localhost:7438/hooks",
        basePath: "/hooks",
        port: 7438,
        isPublic: false,
      });
    });

    it("should return public URL when available", () => {
      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => "https://my-host.tailnet.ts.net/hooks",
      );

      const urlInfo = ext.getWebhookUrl();
      expect(urlInfo).toEqual({
        url: "https://my-host.tailnet.ts.net/hooks",
        basePath: "/hooks",
        port: 7438,
        isPublic: true,
      });
    });

    it("should return null URL when port is null and no public URL", () => {
      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => null,
        () => null,
      );

      const urlInfo = ext.getWebhookUrl();
      expect(urlInfo.url).toBeNull();
      expect(urlInfo.port).toBeNull();
      expect(urlInfo.isPublic).toBe(false);
    });

    it("should return default basePath when config is null", () => {
      const ext = createWebhooksExtension(
        () => null,
        () => null,
        () => null,
      );

      const urlInfo = ext.getWebhookUrl();
      expect(urlInfo.basePath).toBe("/hooks");
    });

    it("should use custom basePath from config", () => {
      const ext = createWebhooksExtension(
        () => createMockConfig({ basePath: "/webhooks" }),
        () => 9000,
        () => null,
      );

      const urlInfo = ext.getWebhookUrl();
      expect(urlInfo.url).toBe("http://localhost:9000/webhooks");
      expect(urlInfo.basePath).toBe("/webhooks");
    });
  });

  describe("clearDeliveryHistory", () => {
    it("should clear all recorded deliveries", () => {
      recordDelivery({
        webhookId: "test",
        timestamp: "2026-01-01T00:00:00Z",
        status: "success",
        httpStatus: 200,
        path: "test",
        action: "agent",
        payload: {},
      });

      const ext = createWebhooksExtension(
        () => createMockConfig(),
        () => 7438,
        () => null,
      );

      expect(ext.getWebhookHistory()).toHaveLength(1);
      clearDeliveryHistory();
      expect(ext.getWebhookHistory()).toHaveLength(0);
    });
  });
});
