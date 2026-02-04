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
import { wrapExternalContent, sanitizeString, secureCompare, verifyGitHubSignature } from "./security.js";
import type { GitHubHookConfig } from "./types.js";

// ============================================================================
// Types
// ============================================================================

export interface WebhookHandlerContext {
  config: WebhooksConfigResolved;
  githubConfig?: GitHubHookConfig;
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

export interface RawBodyResult {
  ok: true;
  value: unknown;
  raw: string;
}

export async function readJsonBody(
  req: IncomingMessage,
  maxBytes: number
): Promise<RawBodyResult | { ok: false; error: string }> {
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
      const raw = Buffer.concat(chunks).toString("utf-8");
      const trimmed = raw.trim();
      if (!trimmed) {
        resolve({ ok: true, value: {}, raw });
        return;
      }
      try {
        const parsed = JSON.parse(trimmed) as unknown;
        resolve({ ok: true, value: parsed, raw });
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
// GitHub Webhook Handler
// ============================================================================

/**
 * Handle GitHub webhooks with signature verification and config-based routing.
 *
 * This handler:
 * 1. Verifies the X-Hub-Signature-256 header using the configured webhook secret
 * 2. Routes PR events to the configured prReviewSession
 * 3. Optionally filters by allowed organizations
 */
export async function handleGitHub(
  payload: Record<string, unknown>,
  rawBody: string,
  headers: Record<string, string>,
  ctx: WebhookHandlerContext
): Promise<WebhookResponse> {
  const githubConfig = ctx.githubConfig;

  // Verify signature if secret is configured
  if (githubConfig?.webhookSecret) {
    const signature = headers["x-hub-signature-256"];
    if (!verifyGitHubSignature(rawBody, signature, githubConfig.webhookSecret)) {
      ctx.logger.warn({ msg: "GitHub webhook signature verification failed" });
      return { ok: false, error: "Invalid signature" };
    }
    ctx.logger.debug({ msg: "GitHub webhook signature verified" });
  }

  // Get event type from header
  const eventType = headers["x-github-event"];
  if (!eventType) {
    return { ok: false, error: "Missing X-GitHub-Event header" };
  }

  // Check allowed orgs if configured
  const org = (payload.organization as Record<string, unknown>)?.login as string | undefined
    ?? ((payload.repository as Record<string, unknown>)?.owner as Record<string, unknown> | undefined)?.login as string | undefined;

  if (githubConfig?.allowedOrgs && githubConfig.allowedOrgs.length > 0) {
    const normalizedOrg = (org || "").trim().toLowerCase();
    const allowed = githubConfig.allowedOrgs.map((o) => o.trim().toLowerCase());

    if (!normalizedOrg || !allowed.includes(normalizedOrg)) {
      ctx.logger.warn({ msg: "GitHub webhook from unauthorized org", org });
      return { ok: false, error: "Unauthorized organization" };
    }
  }

  // Determine target session based on event type
  let targetSession: string | undefined;
  let message: string;

  // GitHub webhook "ping" (sent on creation/edit) should succeed without routing
  if (eventType === "ping") {
    ctx.logger.info({ msg: "GitHub webhook ping received" });
    await ctx.emit("webhook:github", { event: "ping" });
    return { ok: true, action: "skipped" };
  }

  if (eventType === "pull_request" || eventType === "pull_request_review") {
    targetSession = githubConfig?.prReviewSession;
    const pr = payload.pull_request as Record<string, unknown> | undefined;
    const action = payload.action as string;
    const repo = (payload.repository as Record<string, unknown>)?.full_name as string;

    const safeAction = sanitizeString(action, 200);
    const safeRepo = sanitizeString(repo, 500);
    const safePrNumber = sanitizeString(pr?.number, 50);
    const safeTitle = sanitizeString(pr?.title, 2000);
    const safeUser = sanitizeString((pr?.user as Record<string, unknown>)?.login, 200);
    const safeUrl = sanitizeString(pr?.html_url, 2000);

    message = `GitHub ${eventType}: ${safeAction}\n` +
      `Repository: ${safeRepo}\n` +
      `PR #${safePrNumber}: ${safeTitle}\n` +
      `By: ${safeUser}\n` +
      `URL: ${safeUrl}`;
  } else if (eventType === "release") {
    targetSession = githubConfig?.releaseSession;
    const release = payload.release as Record<string, unknown> | undefined;
    const repo = (payload.repository as Record<string, unknown>)?.full_name as string;

    message = `GitHub release: ${payload.action}\n` +
      `Repository: ${repo}\n` +
      `Release: ${release?.tag_name} - ${release?.name}\n` +
      `URL: ${release?.html_url}`;
  } else {
    // Fall back to generic preset handling
    message = `GitHub ${eventType}: ${payload.action || "event"}\n` +
      `Repository: ${(payload.repository as Record<string, unknown>)?.full_name}`;
  }

  if (!targetSession) {
    ctx.logger.debug({ msg: "No target session configured for GitHub event", eventType });
    // Fall through to standard mapped handler
    return { ok: false, error: "no_target_session" };
  }

  ctx.logger.info({
    msg: "GitHub webhook received",
    event: eventType,
    action: payload.action,
    targetSession,
  });

  // Wrap content safely and inject
  const safeMessage = wrapExternalContent(message, "github");

  try {
    await ctx.inject(targetSession, safeMessage, { from: "github" });
    await ctx.emit("webhook:github", {
      event: eventType,
      action: payload.action,
      repository: (payload.repository as Record<string, unknown>)?.full_name,
      targetSession,
    });
    return { ok: true, action: "wake", sessionKey: targetSession };
  } catch (err) {
    ctx.logger.error({ msg: "GitHub webhook injection failed", error: String(err) });
    return { ok: false, error: String(err) };
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
