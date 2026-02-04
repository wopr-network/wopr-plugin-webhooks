/**
 * WOPR Webhooks Plugin
 *
 * HTTP webhook ingress for triggering agent runs from external systems.
 * Inspired by OpenClaw's webhooks system.
 *
 * Features:
 * - POST /hooks/wake - Notify main session of external event
 * - POST /hooks/agent - Run isolated agent with optional channel delivery
 * - POST /hooks/<name> - Custom mappings with templates and transforms
 * - Token-based authentication
 * - Payload safety wrappers
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type {
  WebhooksConfig,
  WebhooksConfigResolved,
  WebhooksExtension,
  HookMappingResolved,
  WebhookResponse,
  HookMappingContext,
  HookMappingResult,
} from "./types.js";
import { resolveMappings, clearTransformCache, applyMappings } from "./mappings.js";
import type { GitHubHookConfig } from "./types.js";
import {
  extractToken,
  readJsonBody,
  normalizeHeaders,
  handleWake,
  handleAgent,
  handleMapped,
  handleGitHub,
  sendJson,
  sendError,
  type WebhookHandlerContext,
  type Logger,
} from "./handlers.js";

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_PORT = 7438;
const DEFAULT_PATH = "/hooks";
const DEFAULT_MAX_BODY_BYTES = 256 * 1024; // 256KB

// ============================================================================
// Plugin State
// ============================================================================

let server: ReturnType<typeof createServer> | null = null;
let resolvedConfig: WebhooksConfigResolved | null = null;
let pluginContext: any = null;

// ============================================================================
// Config Resolution
// ============================================================================

function resolveConfig(
  config: WebhooksConfig,
  woprHome: string
): WebhooksConfigResolved | null {
  if (!config.enabled) {
    return null;
  }

  const token = config.token?.trim();
  if (!token) {
    throw new Error("webhooks.enabled requires webhooks.token");
  }

  const rawPath = config.path?.trim() || DEFAULT_PATH;
  const withSlash = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  const basePath = withSlash.length > 1 ? withSlash.replace(/\/+$/, "") : withSlash;

  if (basePath === "/") {
    throw new Error("webhooks.path may not be '/'");
  }

  const maxBodyBytes =
    config.maxBodyBytes && config.maxBodyBytes > 0
      ? config.maxBodyBytes
      : DEFAULT_MAX_BODY_BYTES;

  const mappings = resolveMappings(config, woprHome);

  return {
    basePath,
    token,
    maxBodyBytes,
    mappings,
  };
}

// ============================================================================
// HTTP Server
// ============================================================================

function createWebhookServer(
  config: WebhooksConfigResolved,
  githubConfig: GitHubHookConfig | undefined,
  ctx: any,
  logger: Logger
): ReturnType<typeof createServer> {
  const handlerCtx: WebhookHandlerContext = {
    config,
    githubConfig,
    inject: async (session, message, options) => {
      return ctx.inject(session, message, {
        from: "webhook",
        ...options,
      });
    },
    logMessage: (session, message, options) => {
      ctx.logMessage(session, message, { from: "webhook", ...options });
    },
    emit: async (event, payload) => {
      await ctx.events.emit(event, payload);
    },
    logger,
  };

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // Parse URL
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;

    // Only handle requests under basePath
    if (!pathname.startsWith(config.basePath)) {
      sendError(res, 404, "Not found");
      return;
    }

    // Only POST allowed
    if (req.method !== "POST") {
      sendError(res, 405, "Method not allowed");
      return;
    }

    // Extract and validate token
    const { token, fromQuery } = extractToken(req, url);

    if (!token) {
      sendError(res, 401, "Authorization required");
      return;
    }

    if (token !== config.token) {
      sendError(res, 401, "Invalid token");
      return;
    }

    if (fromQuery) {
      logger.warn("Token passed via query param (deprecated)");
    }

    // Read body
    const bodyResult = await readJsonBody(req, config.maxBodyBytes);
    if (!bodyResult.ok) {
      if (bodyResult.error === "payload too large") {
        sendError(res, 413, "Payload too large");
      } else {
        sendError(res, 400, bodyResult.error);
      }
      return;
    }

    const payload =
      typeof bodyResult.value === "object" && bodyResult.value !== null
        ? (bodyResult.value as Record<string, unknown>)
        : {};
    const rawBody = bodyResult.raw;

    // Route to handler
    const subPath = pathname.slice(config.basePath.length);
    const normalizedSubPath = subPath.replace(/^\/+/, "").replace(/\/+$/, "");

    try {
      let result: WebhookResponse;

      if (normalizedSubPath === "wake") {
        result = await handleWake(payload, handlerCtx);
        sendJson(res, 200, result);
      } else if (normalizedSubPath === "agent") {
        result = await handleAgent(payload, handlerCtx);
        sendJson(res, 202, result); // 202 Accepted for async
      } else if (normalizedSubPath === "github") {
        // GitHub webhook with signature verification
        const headers = normalizeHeaders(req);
        result = await handleGitHub(payload, rawBody, headers, handlerCtx);

        // If no target session configured, fall through to mapped handler
        if (!result.ok && result.error === "no_target_session") {
          result = await handleMapped(normalizedSubPath, payload, headers, url, handlerCtx);
        }

        if (!result.ok) {
          sendError(res, 400, result.error || "Unknown error");
        } else {
          sendJson(res, 200, result);
        }
      } else if (normalizedSubPath) {
        // Mapped hook
        const headers = normalizeHeaders(req);
        result = await handleMapped(normalizedSubPath, payload, headers, url, handlerCtx);

        if (!result.ok) {
          sendError(res, 400, result.error || "Unknown error");
        } else if (result.action === "agent") {
          sendJson(res, 202, result);
        } else {
          sendJson(res, 200, result);
        }
      } else {
        sendError(res, 400, "Missing hook path");
      }
    } catch (err) {
      logger.error({ msg: "Webhook handler error", error: String(err) });
      sendError(res, 500, "Internal server error");
    }
  });
}

// ============================================================================
// Plugin Definition
// ============================================================================

interface WOPRPlugin {
  name: string;
  version: string;
  description?: string;
  commands?: Array<{
    name: string;
    description: string;
    usage?: string;
    handler: (ctx: any, args: string[]) => Promise<void>;
  }>;
  init?(ctx: any): Promise<void>;
  shutdown?(): Promise<void>;
}

const plugin: WOPRPlugin = {
  name: "wopr-plugin-webhooks",
  version: "1.0.0",
  description: "HTTP webhook ingress for external triggers",

  commands: [
    {
      name: "webhooks",
      description: "Webhook management commands",
      usage: "wopr webhooks <status|test|mappings>",
      async handler(ctx: any, args: string[]) {
        const [subcommand, ...rest] = args;

        if (subcommand === "status") {
          if (!resolvedConfig) {
            ctx.log.info("Webhooks: disabled");
            return;
          }
          ctx.log.info(`Webhooks: enabled`);
          ctx.log.info(`  Path: ${resolvedConfig.basePath}`);
          ctx.log.info(`  Mappings: ${resolvedConfig.mappings.length}`);
          return;
        }

        if (subcommand === "mappings") {
          if (!resolvedConfig) {
            ctx.log.info("Webhooks: disabled");
            return;
          }
          ctx.log.info(`Configured mappings:`);
          for (const m of resolvedConfig.mappings) {
            ctx.log.info(`  - ${m.id}: ${m.action} (path: ${m.matchPath || "*"})`);
          }
          return;
        }

        if (subcommand === "test") {
          const [hookPath, jsonPayload] = rest;
          if (!hookPath) {
            ctx.log.error("Usage: wopr webhooks test <path> [json-payload]");
            return;
          }

          if (!resolvedConfig) {
            ctx.log.error("Webhooks not enabled");
            return;
          }

          const payload = jsonPayload ? JSON.parse(jsonPayload) : {};
          const extension = ctx.getExtension("webhooks") as WebhooksExtension | undefined;
          if (!extension) {
            ctx.log.error("Webhooks extension not registered");
            return;
          }

          const result = await extension.handleWebhook(hookPath, payload);
          ctx.log.info(`Result: ${JSON.stringify(result, null, 2)}`);
          return;
        }

        ctx.log.info("Usage: wopr webhooks <status|test|mappings>");
      },
    },
  ],

  async init(ctx: any) {
    pluginContext = ctx;
    const logger: Logger = {
      info: (msg) => ctx.log.info(typeof msg === "string" ? msg : JSON.stringify(msg)),
      warn: (msg) => ctx.log.warn(typeof msg === "string" ? msg : JSON.stringify(msg)),
      error: (msg) => ctx.log.error(typeof msg === "string" ? msg : JSON.stringify(msg)),
      debug: (msg) => ctx.log.debug?.(typeof msg === "string" ? msg : JSON.stringify(msg)),
    };

    // Load config
    const config = ctx.getConfig() as WebhooksConfig | undefined;
    if (!config?.enabled) {
      logger.info("Webhooks plugin loaded (disabled - set webhooks.enabled: true in config)");
      return;
    }

    // Get WOPR_HOME for transform path resolution
    const woprHome = process.env.WOPR_HOME || "/data";

    try {
      resolvedConfig = resolveConfig(config, woprHome);
    } catch (err) {
      logger.error(`Failed to resolve webhooks config: ${err}`);
      return;
    }

    if (!resolvedConfig) {
      logger.info("Webhooks plugin loaded (disabled)");
      return;
    }

    // Load GitHub config from main WOPR config (set by onboard wizard)
    // The onboard wizard saves github.webhookSecret and github.prReviewSession
    // to wopr.config.json, which we read here for signature verification and routing
    let githubConfig: GitHubHookConfig | undefined;
    try {
      const mainConfig = ctx.getMainConfig?.() || {};
      if (mainConfig.github) {
        githubConfig = {
          webhookSecret: mainConfig.github.webhookSecret,
          prReviewSession: mainConfig.github.prReviewSession,
          releaseSession: mainConfig.github.releaseSession,
          allowedOrgs: mainConfig.github.orgs,
        };
        logger.info({
          msg: "GitHub webhook config loaded",
          hasSecret: !!githubConfig.webhookSecret,
          prSession: githubConfig.prReviewSession,
        });
      }
    } catch {
      // No main config access, use plugin config
      githubConfig = config.github;
    }

    // Fall back to plugin-level github config
    if (!githubConfig && config.github) {
      githubConfig = config.github;
    }

    // Start HTTP server
    const port = config.port || DEFAULT_PORT;
    const host = config.host || "127.0.0.1";

    server = createWebhookServer(resolvedConfig, githubConfig, ctx, logger);
    server.listen(port, host, () => {
      logger.info(`Webhooks server listening on http://${host}:${port}${resolvedConfig!.basePath}`);
    });

    // Register extension for CLI and other plugins
    const extension: WebhooksExtension = {
      getConfig: () => resolvedConfig,

      async handleWebhook(
        path: string,
        payload: Record<string, unknown>,
        headers?: Record<string, string>
      ): Promise<WebhookResponse> {
        if (!resolvedConfig) {
          return { ok: false, error: "Webhooks not enabled" };
        }

        const handlerCtx: WebhookHandlerContext = {
          config: resolvedConfig,
          githubConfig,
          inject: async (session, message, options) => {
            return ctx.inject(session, message, {
              from: "webhook",
              ...options,
            });
          },
          logMessage: (session, message, options) => {
            ctx.logMessage(session, message, { from: "webhook", ...options });
          },
          emit: async (event, eventPayload) => {
            await ctx.events.emit(event, eventPayload);
          },
          logger,
        };

        const url = new URL(`http://localhost${resolvedConfig.basePath}/${path}`);

        // Special handling for GitHub webhooks
        if (path === "github" && githubConfig) {
          const result = await handleGitHub(payload, JSON.stringify(payload), headers || {}, handlerCtx);
          if (result.ok || result.error !== "no_target_session") {
            return result;
          }
        }

        return handleMapped(path, payload, headers || {}, url, handlerCtx);
      },

      async testMapping(
        mappingId: string,
        payload: Record<string, unknown>
      ): Promise<HookMappingResult | null> {
        if (!resolvedConfig) {
          return null;
        }

        const mapping = resolvedConfig.mappings.find((m) => m.id === mappingId);
        if (!mapping) {
          return null;
        }

        const ctx: HookMappingContext = {
          payload,
          headers: {},
          url: new URL(`http://localhost${resolvedConfig.basePath}/${mapping.matchPath || ""}`),
          path: mapping.matchPath || "",
        };

        return applyMappings([mapping], ctx);
      },
    };

    ctx.registerExtension("webhooks", extension);

    // Subscribe to events for channel delivery
    ctx.events.on("webhook:agent:response", async (event: any) => {
      const { sessionKey, name, response, channel, to } = event;

      if (!channel || channel === "last") {
        // Use default channel provider if available
        const providers = ctx.getChannelProviders();
        if (providers.length > 0) {
          try {
            await providers[0].send(to || "", response);
            logger.info({ msg: "Delivered webhook response to channel", sessionKey, channel: providers[0].id });
          } catch (err) {
            logger.error({ msg: "Failed to deliver webhook response", sessionKey, error: String(err) });
          }
        }
        return;
      }

      // Find specific channel provider
      const provider = ctx.getChannelProvider(channel);
      if (provider) {
        try {
          await provider.send(to || "", response);
          logger.info({ msg: "Delivered webhook response", sessionKey, channel });
        } catch (err) {
          logger.error({ msg: "Failed to deliver webhook response", sessionKey, channel, error: String(err) });
        }
      } else {
        logger.warn({ msg: "Channel provider not found for webhook delivery", channel });
      }
    });

    logger.info(`Webhooks plugin initialized with ${resolvedConfig.mappings.length} mappings`);
  },

  async shutdown() {
    if (server) {
      server.close();
      server = null;
    }
    resolvedConfig = null;
    clearTransformCache();
    pluginContext?.unregisterExtension("webhooks");
    pluginContext = null;
  },
};

export default plugin;
