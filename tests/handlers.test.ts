import { describe, it, expect, vi } from "vitest";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Socket } from "node:net";
import {
  extractToken,
  normalizeHeaders,
  validateWakePayload,
  validateAgentPayload,
  handleWake,
  handleAgent,
  handleMapped,
  handleGitHub,
  sendJson,
  sendError,
  type WebhookHandlerContext,
  type Logger,
} from "../src/handlers.js";
import { createHmac } from "node:crypto";

// ============================================================================
// Test Helpers
// ============================================================================

function makeReq(overrides: Partial<IncomingMessage> = {}): IncomingMessage {
  return {
    headers: {},
    url: "/",
    method: "POST",
    ...overrides,
  } as IncomingMessage;
}

function makeUrl(path: string = "/"): URL {
  return new URL(path, "http://localhost");
}

function makeLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
}

function makeHandlerCtx(overrides: Partial<WebhookHandlerContext> = {}): WebhookHandlerContext {
  return {
    config: {
      basePath: "/hooks",
      token: "test-token",
      maxBodyBytes: 256 * 1024,
      mappings: [],
    },
    inject: vi.fn().mockResolvedValue("ok"),
    logMessage: vi.fn(),
    emit: vi.fn().mockResolvedValue(undefined),
    logger: makeLogger(),
    ...overrides,
  };
}

function makeRes(): ServerResponse & { _status?: number; _body?: string; _headers?: Record<string, string> } {
  const res = {
    _status: undefined as number | undefined,
    _body: undefined as string | undefined,
    _headers: {} as Record<string, string>,
    writeHead(status: number, headers?: Record<string, string>) {
      res._status = status;
      if (headers) {
        Object.assign(res._headers, headers);
      }
      return res;
    },
    end(body?: string) {
      res._body = body;
      return res;
    },
  };
  return res as unknown as ServerResponse & { _status?: number; _body?: string; _headers?: Record<string, string> };
}

// ============================================================================
// extractToken
// ============================================================================

describe("extractToken", () => {
  it("extracts Bearer token from Authorization header", () => {
    const req = makeReq({
      headers: { authorization: "Bearer my-token-123" },
    });
    const result = extractToken(req, makeUrl());
    expect(result.token).toBe("my-token-123");
    expect(result.fromQuery).toBe(false);
  });

  it("extracts token from x-wopr-token header", () => {
    const req = makeReq({
      headers: { "x-wopr-token": "custom-token" },
    });
    const result = extractToken(req, makeUrl());
    expect(result.token).toBe("custom-token");
    expect(result.fromQuery).toBe(false);
  });

  it("extracts token from query param (deprecated)", () => {
    const req = makeReq();
    const url = makeUrl("/?token=query-token");
    const result = extractToken(req, url);
    expect(result.token).toBe("query-token");
    expect(result.fromQuery).toBe(true);
  });

  it("prefers Bearer token over x-wopr-token", () => {
    const req = makeReq({
      headers: {
        authorization: "Bearer bearer-token",
        "x-wopr-token": "custom-token",
      },
    });
    const result = extractToken(req, makeUrl());
    expect(result.token).toBe("bearer-token");
  });

  it("prefers x-wopr-token over query param", () => {
    const req = makeReq({
      headers: { "x-wopr-token": "header-token" },
    });
    const url = makeUrl("/?token=query-token");
    const result = extractToken(req, url);
    expect(result.token).toBe("header-token");
    expect(result.fromQuery).toBe(false);
  });

  it("returns undefined when no token present", () => {
    const req = makeReq();
    const result = extractToken(req, makeUrl());
    expect(result.token).toBeUndefined();
    expect(result.fromQuery).toBe(false);
  });

  it("trims whitespace from Bearer token", () => {
    const req = makeReq({
      headers: { authorization: "Bearer   spaced-token   " },
    });
    const result = extractToken(req, makeUrl());
    expect(result.token).toBe("spaced-token");
  });

  it("handles case-insensitive Bearer prefix", () => {
    const req = makeReq({
      headers: { authorization: "bearer lowercase-token" },
    });
    const result = extractToken(req, makeUrl());
    expect(result.token).toBe("lowercase-token");
  });

  it("returns undefined for empty Bearer value", () => {
    const req = makeReq({
      headers: { authorization: "Bearer " },
    });
    const result = extractToken(req, makeUrl());
    expect(result.token).toBeUndefined();
  });
});

// ============================================================================
// normalizeHeaders
// ============================================================================

describe("normalizeHeaders", () => {
  it("lowercases header keys", () => {
    const req = makeReq({
      headers: { "Content-Type": "application/json" } as unknown as IncomingMessage["headers"],
    });
    const result = normalizeHeaders(req);
    expect(result["content-type"]).toBe("application/json");
  });

  it("joins array header values", () => {
    const req = makeReq({
      headers: { "set-cookie": ["a=1", "b=2"] } as unknown as IncomingMessage["headers"],
    });
    const result = normalizeHeaders(req);
    expect(result["set-cookie"]).toBe("a=1, b=2");
  });

  it("handles empty headers", () => {
    const req = makeReq({ headers: {} });
    const result = normalizeHeaders(req);
    expect(Object.keys(result)).toHaveLength(0);
  });
});

// ============================================================================
// validateWakePayload
// ============================================================================

describe("validateWakePayload", () => {
  it("validates a valid payload", () => {
    const result = validateWakePayload({ text: "hello", session: "main" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.text).toBe("hello");
      expect(result.value.session).toBe("main");
      expect(result.value.mode).toBe("now");
    }
  });

  it("requires text field", () => {
    const result = validateWakePayload({ session: "main" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("text required");
    }
  });

  it("requires session field", () => {
    const result = validateWakePayload({ text: "hello" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("session required");
    }
  });

  it("rejects empty text", () => {
    const result = validateWakePayload({ text: "", session: "main" });
    expect(result.ok).toBe(false);
  });

  it("rejects empty session", () => {
    const result = validateWakePayload({ text: "hello", session: " " });
    expect(result.ok).toBe(false);
  });

  it("accepts next-heartbeat mode", () => {
    const result = validateWakePayload({
      text: "hello",
      session: "main",
      mode: "next-heartbeat",
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.mode).toBe("next-heartbeat");
    }
  });

  it("defaults mode to now", () => {
    const result = validateWakePayload({ text: "hello", session: "main" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.mode).toBe("now");
    }
  });
});

// ============================================================================
// validateAgentPayload
// ============================================================================

describe("validateAgentPayload", () => {
  it("validates minimal payload", () => {
    const result = validateAgentPayload({ message: "do something" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.message).toBe("do something");
      expect(result.value.name).toBe("Hook");
      expect(result.value.wakeMode).toBe("now");
      expect(result.value.deliver).toBe(true);
      expect(result.value.sessionKey).toMatch(/^hook:/);
    }
  });

  it("requires message field", () => {
    const result = validateAgentPayload({});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("message required");
    }
  });

  it("rejects empty message", () => {
    const result = validateAgentPayload({ message: "" });
    expect(result.ok).toBe(false);
  });

  it("accepts all optional fields", () => {
    const result = validateAgentPayload({
      message: "do something",
      name: "MyHook",
      sessionKey: "my-session",
      wakeMode: "next-heartbeat",
      deliver: false,
      channel: "discord",
      to: "user@example.com",
      model: "gpt-4",
      thinking: "high",
      timeoutSeconds: 30,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.name).toBe("MyHook");
      expect(result.value.sessionKey).toBe("my-session");
      expect(result.value.wakeMode).toBe("next-heartbeat");
      expect(result.value.deliver).toBe(false);
      expect(result.value.channel).toBe("discord");
      expect(result.value.to).toBe("user@example.com");
      expect(result.value.model).toBe("gpt-4");
      expect(result.value.thinking).toBe("high");
      expect(result.value.timeoutSeconds).toBe(30);
    }
  });

  it("floors timeoutSeconds", () => {
    const result = validateAgentPayload({
      message: "test",
      timeoutSeconds: 10.7,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.timeoutSeconds).toBe(10);
    }
  });

  it("ignores negative timeoutSeconds", () => {
    const result = validateAgentPayload({
      message: "test",
      timeoutSeconds: -5,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.timeoutSeconds).toBeUndefined();
    }
  });

  it("ignores non-finite timeoutSeconds", () => {
    const result = validateAgentPayload({
      message: "test",
      timeoutSeconds: Infinity,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.timeoutSeconds).toBeUndefined();
    }
  });
});

// ============================================================================
// handleWake
// ============================================================================

describe("handleWake", () => {
  it("injects message into session on valid payload", async () => {
    const ctx = makeHandlerCtx();
    const result = await handleWake(
      { text: "event happened", session: "main" },
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("wake");
    expect(result.sessionKey).toBe("main");
    expect(ctx.inject).toHaveBeenCalledOnce();
    expect(ctx.emit).toHaveBeenCalledWith("webhook:wake", expect.objectContaining({
      text: "event happened",
      session: "main",
    }));
  });

  it("returns error on invalid payload", async () => {
    const ctx = makeHandlerCtx();
    const result = await handleWake({ text: "" }, ctx);
    expect(result.ok).toBe(false);
    expect(result.error).toBe("text required");
  });

  it("wraps content with safety boundaries", async () => {
    const ctx = makeHandlerCtx();
    await handleWake({ text: "unsafe content", session: "main" }, ctx);
    const injectedMessage = (ctx.inject as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(injectedMessage).toContain("<external-content");
    expect(injectedMessage).toContain("unsafe content");
  });

  it("handles inject failure", async () => {
    const ctx = makeHandlerCtx({
      inject: vi.fn().mockRejectedValue(new Error("session not found")),
    });
    const result = await handleWake(
      { text: "hello", session: "nonexistent" },
      ctx
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe("Injection failed");
  });
});

// ============================================================================
// handleAgent
// ============================================================================

describe("handleAgent", () => {
  it("returns accepted with sessionKey on valid payload", async () => {
    const ctx = makeHandlerCtx();
    const result = await handleAgent(
      { message: "run analysis" },
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("agent");
    expect(result.sessionKey).toBeDefined();
  });

  it("returns error on invalid payload", async () => {
    const ctx = makeHandlerCtx();
    const result = await handleAgent({}, ctx);
    expect(result.ok).toBe(false);
    expect(result.error).toBe("message required");
  });

  it("uses provided sessionKey", async () => {
    const ctx = makeHandlerCtx();
    const result = await handleAgent(
      { message: "test", sessionKey: "custom-key" },
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.sessionKey).toBe("custom-key");
  });
});

// ============================================================================
// handleMapped
// ============================================================================

describe("handleMapped", () => {
  it("returns error when no mappings match", async () => {
    const ctx = makeHandlerCtx();
    const result = await handleMapped(
      "unknown",
      { source: "test" },
      {},
      makeUrl("/hooks/unknown"),
      ctx
    );
    expect(result.ok).toBe(false);
    expect(result.error).toContain("No mapping found");
  });

  it("applies matching mapping with agent action", async () => {
    const ctx = makeHandlerCtx({
      config: {
        basePath: "/hooks",
        token: "test-token",
        maxBodyBytes: 256 * 1024,
        mappings: [
          {
            id: "test-mapping",
            matchPath: "custom",
            action: "agent",
            wakeMode: "now" as const,
            messageTemplate: "Event: {{event}}",
          },
        ],
      },
    });
    const result = await handleMapped(
      "custom",
      { event: "test-event" },
      {},
      makeUrl("/hooks/custom"),
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("agent");
  });

  it("applies matching mapping with wake action", async () => {
    const ctx = makeHandlerCtx({
      config: {
        basePath: "/hooks",
        token: "test-token",
        maxBodyBytes: 256 * 1024,
        mappings: [
          {
            id: "wake-mapping",
            matchPath: "notify",
            action: "wake",
            wakeMode: "now" as const,
            session: "main",
            textTemplate: "Notification: {{msg}}",
          },
        ],
      },
    });
    const result = await handleMapped(
      "notify",
      { msg: "hello" },
      {},
      makeUrl("/hooks/notify"),
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("wake");
  });
});

// ============================================================================
// handleGitHub
// ============================================================================

describe("handleGitHub", () => {
  it("handles ping event", async () => {
    const ctx = makeHandlerCtx({ githubConfig: {} });
    const result = await handleGitHub(
      {},
      "{}",
      { "x-github-event": "ping" },
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("skipped");
  });

  it("rejects missing x-github-event header", async () => {
    const ctx = makeHandlerCtx({ githubConfig: {} });
    const result = await handleGitHub({}, "{}", {}, ctx);
    expect(result.ok).toBe(false);
    expect(result.error).toContain("Missing X-GitHub-Event");
  });

  it("verifies signature when secret is configured", async () => {
    const secret = "gh-secret";
    const body = '{"action":"opened"}';
    const sig =
      "sha256=" +
      createHmac("sha256", secret).update(Buffer.from(body, "utf-8")).digest("hex");
    const ctx = makeHandlerCtx({
      githubConfig: {
        webhookSecret: secret,
        prReviewSession: "pr-review",
      },
    });
    const result = await handleGitHub(
      {
        action: "opened",
        pull_request: {
          number: 1,
          title: "Test PR",
          user: { login: "dev" },
          html_url: "https://github.com/org/repo/pull/1",
        },
        repository: { full_name: "org/repo", owner: { login: "org" } },
      },
      body,
      {
        "x-hub-signature-256": sig,
        "x-github-event": "pull_request",
      },
      ctx
    );
    expect(result.ok).toBe(true);
  });

  it("rejects invalid signature", async () => {
    const ctx = makeHandlerCtx({
      githubConfig: { webhookSecret: "real-secret" },
    });
    const result = await handleGitHub(
      {},
      '{"action":"opened"}',
      {
        "x-hub-signature-256": "sha256=" + "a".repeat(64),
        "x-github-event": "pull_request",
      },
      ctx
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("rejects unauthorized organization", async () => {
    const ctx = makeHandlerCtx({
      githubConfig: {
        allowedOrgs: ["allowed-org"],
        prReviewSession: "pr-review",
      },
    });
    const result = await handleGitHub(
      {
        action: "opened",
        organization: { login: "bad-org" },
        repository: { full_name: "bad-org/repo", owner: { login: "bad-org" } },
      },
      "{}",
      { "x-github-event": "pull_request" },
      ctx
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe("Unauthorized organization");
  });

  it("accepts allowed organization", async () => {
    const ctx = makeHandlerCtx({
      githubConfig: {
        allowedOrgs: ["good-org"],
        prReviewSession: "pr-review",
      },
    });
    const result = await handleGitHub(
      {
        action: "opened",
        organization: { login: "good-org" },
        pull_request: {
          number: 1,
          title: "Test",
          user: { login: "dev" },
          html_url: "https://github.com/good-org/repo/pull/1",
        },
        repository: { full_name: "good-org/repo", owner: { login: "good-org" } },
      },
      "{}",
      { "x-github-event": "pull_request" },
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("wake");
  });

  it("returns no_target_session when no session configured for event", async () => {
    const ctx = makeHandlerCtx({ githubConfig: {} });
    const result = await handleGitHub(
      {
        action: "created",
        release: { tag_name: "v1.0", name: "Release", html_url: "https://github.com" },
        repository: { full_name: "org/repo", owner: { login: "org" } },
      },
      "{}",
      { "x-github-event": "release" },
      ctx
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe("no_target_session");
  });

  it("routes release events to releaseSession", async () => {
    const ctx = makeHandlerCtx({
      githubConfig: { releaseSession: "releases" },
    });
    const result = await handleGitHub(
      {
        action: "published",
        release: { tag_name: "v1.0", name: "Release 1.0", html_url: "https://github.com" },
        repository: { full_name: "org/repo", owner: { login: "org" } },
      },
      "{}",
      { "x-github-event": "release" },
      ctx
    );
    expect(result.ok).toBe(true);
    expect(result.action).toBe("wake");
    expect(result.sessionKey).toBe("releases");
  });

  it("handles injection failure", async () => {
    const ctx = makeHandlerCtx({
      githubConfig: { prReviewSession: "pr-review" },
      inject: vi.fn().mockRejectedValue(new Error("inject failed")),
    });
    const result = await handleGitHub(
      {
        action: "opened",
        pull_request: {
          number: 1,
          title: "Test",
          user: { login: "dev" },
          html_url: "https://github.com",
        },
        repository: { full_name: "org/repo", owner: { login: "org" } },
      },
      "{}",
      { "x-github-event": "pull_request" },
      ctx
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe("Injection failed");
  });
});

// ============================================================================
// sendJson / sendError
// ============================================================================

describe("sendJson", () => {
  it("sets status and JSON content-type", () => {
    const res = makeRes();
    sendJson(res, 200, { ok: true });
    expect(res._status).toBe(200);
    expect(res._headers?.["Content-Type"]).toBe("application/json");
    expect(JSON.parse(res._body!)).toEqual({ ok: true });
  });

  it("serializes body as JSON", () => {
    const res = makeRes();
    sendJson(res, 202, { ok: true, sessionKey: "abc" });
    const body = JSON.parse(res._body!);
    expect(body.sessionKey).toBe("abc");
  });
});

describe("sendError", () => {
  it("sends error response with ok: false", () => {
    const res = makeRes();
    sendError(res, 401, "Unauthorized");
    expect(res._status).toBe(401);
    const body = JSON.parse(res._body!);
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Unauthorized");
  });
});
