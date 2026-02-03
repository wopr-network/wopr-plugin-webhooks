/**
 * WOPR Webhooks Plugin - HTTP Handlers
 *
 * Core webhook request handling logic.
 */

import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type {
  WebhooksConfigResolved,
  WakePayload,
  AgentPayload,
  HookMappingContext,
  HookAction,
  WebhookResponse,
} from "./types.js";
import { applyMappings } from "./mappings.js";
import { wrapExternalContent, sanitizeString, secureCompare } from "./security.js";

// ============================================================================
// Types
// ============================================================================

export interface WebhookHandlerContext {
  config: WebhooksConfigResolved;
  inject: (session: string, message: string, options?: InjectOptions) => Promise<string>;
  logMessage: (session: string, message: string, options?: LogOptions) => void;
  emit: (event: string, payload: Record<string, unknown>) => Promise<void>;
  logger: Logger;
}

export interface InjectOptions {
  from?: string;
  model?: string;
  thinking?: string;
  timeout?: number;
}

export interface LogOptions {
  from?: string;
}

export interface Logger {
  info(msg: string | object): void;
  warn(msg: string | object): void;
  error(msg: string | object): void;
  debug(msg: string | object): void;
}

// ============================================================================
// Token Extraction
// ============================================================================

export interface TokenResult {
  token: string | undefined;
  fromQuery: boolean;
}

export function extractToken(req: IncomingMessage, url: URL): TokenResult {
  // Bearer token (preferred)
  const auth =
    typeof req.headers.authorization === "string"
      ? req.headers.authorization.trim()
      : "";
  if (auth.toLowerCase().startsWith("bearer ")) {
    const token = auth.slice(7).trim();
    if (token) {
      return { token, fromQuery: false };
    }
  }

  // Custom header
  const headerToken =
    typeof req.headers["x-wopr-token"] === "string"
      ? req.headers["x-wopr-token"].trim()
      : "";
  if (headerToken) {
    return { token: headerToken, fromQuery: false };
  }

  // Query param (deprecated)
  const queryToken = url.searchParams.get("token");
  if (queryToken) {
    return { token: queryToken.trim(), fromQuery: true };
  }

  return { token: undefined, fromQuery: false };
}

// ============================================================================
// Body Reading
// ============================================================================

export async function readJsonBody(
  req: IncomingMessage,
  maxBytes: number
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  return await new Promise((resolve) => {
    let done = false;
    let total = 0;
    const chunks: Buffer[] = [];

    req.on("data", (chunk: Buffer) => {
      if (done) return;
      total += chunk.length;
      if (total > maxBytes) {
        done = true;
        resolve({ ok: false, error: "payload too large" });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(chunks).toString("utf-8").trim();
      if (!raw) {
        resolve({ ok: true, value: {} });
        return;
      }
      try {
        const parsed = JSON.parse(raw) as unknown;
        resolve({ ok: true, value: parsed });
      } catch (err) {
        resolve({ ok: false, error: String(err) });
      }
    });

    req.on("error", (err) => {
      if (done) return;
      done = true;
      resolve({ ok: false, error: String(err) });
    });
  });
}

// ============================================================================
// Header Normalization
// ============================================================================

export function normalizeHeaders(req: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === "string") {
      headers[key.toLowerCase()] = value;
    } else if (Array.isArray(value) && value.length > 0) {
      headers[key.toLowerCase()] = value.join(", ");
    }
  }
  return headers;
}

// ============================================================================
// Payload Validation
// ============================================================================

export function validateWakePayload(
  payload: Record<string, unknown>
): { ok: true; value: WakePayload } | { ok: false; error: string } {
  const text = typeof payload.text === "string" ? payload.text.trim() : "";
  if (!text) {
    return { ok: false, error: "text required" };
  }

  const session = typeof payload.session === "string" ? payload.session.trim() : "";
  if (!session) {
    return { ok: false, error: "session required" };
  }

  const mode = payload.mode === "next-heartbeat" ? "next-heartbeat" : "now";
  return { ok: true, value: { text, session, mode } };
}

export function validateAgentPayload(
  payload: Record<string, unknown>
): { ok: true; value: AgentPayload } | { ok: false; error: string } {
  const message = typeof payload.message === "string" ? payload.message.trim() : "";
  if (!message) {
    return { ok: false, error: "message required" };
  }

  const name =
    typeof payload.name === "string" && payload.name.trim()
      ? payload.name.trim()
      : "Hook";

  const wakeMode = payload.wakeMode === "next-heartbeat" ? "next-heartbeat" : "now";

  const sessionKey =
    typeof payload.sessionKey === "string" && payload.sessionKey.trim()
      ? payload.sessionKey.trim()
      : `hook:${randomUUID()}`;

  const deliver = payload.deliver !== false;

  const channel =
    typeof payload.channel === "string" && payload.channel.trim()
      ? payload.channel.trim()
      : undefined;

  const to =
    typeof payload.to === "string" && payload.to.trim()
      ? payload.to.trim()
      : undefined;

  const model =
    typeof payload.model === "string" && payload.model.trim()
      ? payload.model.trim()
      : undefined;

  const thinking =
    typeof payload.thinking === "string" && payload.thinking.trim()
      ? payload.thinking.trim()
      : undefined;

  const timeoutSeconds =
    typeof payload.timeoutSeconds === "number" &&
    Number.isFinite(payload.timeoutSeconds) &&
    payload.timeoutSeconds > 0
      ? Math.floor(payload.timeoutSeconds)
      : undefined;

  return {
    ok: true,
    value: {
      message,
      name,
      sessionKey,
      wakeMode,
      deliver,
      channel,
      to,
      model,
      thinking,
      timeoutSeconds,
    },
  };
}

// ============================================================================
// Core Handlers
// ============================================================================

/**
 * Handle POST /hooks/wake
 *
 * Injects a message into the specified session. Unlike /agent which runs
 * asynchronously, /wake waits for the response.
 */
export async function handleWake(
  payload: Record<string, unknown>,
  ctx: WebhookHandlerContext
): Promise<WebhookResponse> {
  const validated = validateWakePayload(payload);
  if (!validated.ok) {
    return { ok: false, error: validated.error };
  }

  const { text, session, mode } = validated.value;

  ctx.logger.info({
    msg: "Wake hook triggered",
    text: text.slice(0, 100),
    mode,
    session,
  });

  // Wrap external content with safety boundaries
  const safeText = wrapExternalContent(text, "webhook");

  // Inject into the specified session
  try {
    const response = await ctx.inject(session, safeText, { from: "webhook" });

    // Emit event
    await ctx.emit("webhook:wake", { text, session, mode, response });

    return { ok: true, action: "wake", sessionKey: session };
  } catch (err) {
    ctx.logger.error({ msg: "Wake hook failed", session, error: String(err) });
    return { ok: false, error: String(err) };
  }
}

/**
 * Handle POST /hooks/agent
 */
export async function handleAgent(
  payload: Record<string, unknown>,
  ctx: WebhookHandlerContext
): Promise<WebhookResponse> {
  const validated = validateAgentPayload(payload);
  if (!validated.ok) {
    return { ok: false, error: validated.error };
  }

  const {
    message,
    name,
    sessionKey,
    wakeMode,
    deliver,
    channel,
    to,
    model,
    thinking,
    timeoutSeconds,
  } = validated.value;

  ctx.logger.info({
    msg: "Agent hook triggered",
    name,
    sessionKey,
    wakeMode,
    deliver,
    channel,
  });

  // Run agent in background (async)
  runAgentAsync(
    {
      message,
      name,
      sessionKey,
      deliver,
      channel,
      to,
      model,
      thinking,
      timeoutSeconds,
    },
    ctx
  ).catch((err) => {
    ctx.logger.error({ msg: "Agent hook failed", sessionKey, error: String(err) });
  });

  return { ok: true, action: "agent", sessionKey };
}

/**
 * Handle POST /hooks/<name> (mapped)
 */
export async function handleMapped(
  path: string,
  payload: Record<string, unknown>,
  headers: Record<string, string>,
  url: URL,
  ctx: WebhookHandlerContext
): Promise<WebhookResponse> {
  const mappingCtx: HookMappingContext = {
    payload,
    headers,
    url,
    path,
  };

  const result = await applyMappings(ctx.config.mappings, mappingCtx);

  if (result === null) {
    return { ok: false, error: `No mapping found for path: ${path}` };
  }

  if (!result.ok) {
    return { ok: false, error: result.error };
  }

  if ("skipped" in result && result.skipped) {
    ctx.logger.debug({ msg: "Hook skipped by transform", path });
    return { ok: true, action: "skipped" };
  }

  const action = result.action;
  if (!action) {
    return { ok: true, action: "skipped" };
  }

  // Execute the resolved action
  return executeAction(action, ctx);
}

// ============================================================================
// Action Execution
// ============================================================================

async function executeAction(
  action: HookAction,
  ctx: WebhookHandlerContext
): Promise<WebhookResponse> {
  if (action.kind === "wake") {
    ctx.logger.info({
      msg: "Mapped wake hook",
      text: action.text.slice(0, 100),
      session: action.session,
      mode: action.mode,
    });

    // Wrap external content with safety boundaries
    const safeText = wrapExternalContent(action.text, "webhook");

    try {
      const response = await ctx.inject(action.session, safeText, { from: "webhook" });
      await ctx.emit("webhook:wake", {
        text: action.text,
        session: action.session,
        mode: action.mode,
        response,
      });
      return { ok: true, action: "wake", sessionKey: action.session };
    } catch (err) {
      ctx.logger.error({ msg: "Mapped wake hook failed", session: action.session, error: String(err) });
      return { ok: false, error: String(err) };
    }
  }

  // Agent action
  const sessionKey = action.sessionKey ?? `hook:${randomUUID()}`;

  ctx.logger.info({
    msg: "Mapped agent hook",
    name: action.name,
    sessionKey,
    wakeMode: action.wakeMode,
    deliver: action.deliver,
  });

  runAgentAsync(
    {
      message: action.message,
      name: action.name,
      sessionKey,
      deliver: action.deliver,
      channel: action.channel,
      to: action.to,
      model: action.model,
      thinking: action.thinking,
      timeoutSeconds: action.timeoutSeconds,
      allowUnsafeExternalContent: action.allowUnsafeExternalContent,
    },
    ctx
  ).catch((err) => {
    ctx.logger.error({ msg: "Mapped agent hook failed", sessionKey, error: String(err) });
  });

  return { ok: true, action: "agent", sessionKey };
}

// ============================================================================
// Async Agent Runner
// ============================================================================

interface AgentRunConfig {
  message: string;
  name?: string;
  sessionKey: string;
  deliver?: boolean;
  channel?: string;
  to?: string;
  model?: string;
  thinking?: string;
  timeoutSeconds?: number;
  allowUnsafeExternalContent?: boolean;
}

async function runAgentAsync(
  config: AgentRunConfig,
  ctx: WebhookHandlerContext
): Promise<void> {
  const {
    message,
    name,
    sessionKey,
    deliver,
    channel,
    to,
    model,
    thinking,
    timeoutSeconds,
    allowUnsafeExternalContent,
  } = config;

  ctx.logger.info({ msg: "Starting agent run", sessionKey, name });

  // Wrap external content with safety boundaries unless explicitly disabled
  const safeMessage = allowUnsafeExternalContent
    ? message
    : wrapExternalContent(message, name || "webhook");

  try {
    // Inject the message and get response
    const response = await ctx.inject(sessionKey, safeMessage, {
      from: "webhook",
      model,
      thinking,
      timeout: timeoutSeconds ? timeoutSeconds * 1000 : undefined,
    });

    ctx.logger.info({
      msg: "Agent run completed",
      sessionKey,
      responseLength: response.length,
    });

    // Emit event for channel delivery (if deliver=true and channel specified)
    if (deliver && channel) {
      await ctx.emit("webhook:agent:response", {
        sessionKey,
        name,
        message,
        response,
        channel,
        to,
      });
    }
  } catch (err) {
    ctx.logger.error({
      msg: "Agent run failed",
      sessionKey,
      error: String(err),
    });

    // Emit error event for interested listeners
    await ctx.emit("webhook:agent:error", {
      sessionKey,
      name,
      message,
      error: String(err),
    });
  }
}

// ============================================================================
// HTTP Response Helpers
// ============================================================================

export function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown
): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

export function sendError(
  res: ServerResponse,
  status: number,
  error: string
): void {
  sendJson(res, status, { ok: false, error });
}
