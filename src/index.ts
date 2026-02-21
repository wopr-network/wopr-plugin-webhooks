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
import type { AddressInfo } from "node:net";
import type { WOPRPlugin, WOPRPluginContext } from "@wopr-network/plugin-types";
import {
	extractToken,
	handleAgent,
	handleGitHub,
	handleMapped,
	handleWake,
	type Logger,
	normalizeHeaders,
	readJsonBody,
	sendError,
	sendJson,
	type WebhookHandlerContext,
} from "./handlers.js";
import { applyMappings, clearTransformCache, resolveMappings } from "./mappings.js";
import { secureCompare } from "./security.js";
import type {
	FunnelExtension,
	GitHubHookConfig,
	HookMappingContext,
	HookMappingResult,
	WebhookResponse,
	WebhooksConfig,
	WebhooksConfigResolved,
	WebhooksExtension,
} from "./types.js";
import {
	clearDeliveryHistory,
	createWebhooksExtension,
	recordDelivery,
} from "./webhooks-extension.js";

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
let ctx: WOPRPluginContext | null = null;
let listeningPort: number | null = null;
let publicUrl: string | null = null;
const cleanups: Array<() => void | Promise<void>> = [];

// ============================================================================
// Config Resolution
// ============================================================================

function resolveConfig(config: WebhooksConfig, woprHome: string): WebhooksConfigResolved | null {
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
		config.maxBodyBytes && config.maxBodyBytes > 0 ? config.maxBodyBytes : DEFAULT_MAX_BODY_BYTES;

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
/**
 * Create an HTTP server that accepts and routes webhook POST requests under the configured base path.
 *
 * The server enforces token-based authorization, applies the configured maximum request body size, and
 * dispatches requests to built-in handlers ("wake", "agent", "github") or configured mappings. It also
 * integrates GitHub signature verification and organization checks when `githubConfig` is provided.
 *
 * @param config - Resolved webhook configuration containing `basePath`, `token`, `maxBodyBytes`, and mappings
 * @param githubConfig - Optional GitHub webhook configuration used for signature verification and org restrictions
 * @param ctx - Plugin context used for injecting messages, emitting events, and routing logs/messages
 * @param logger - Logger used for server-level warnings and errors
 * @returns The created HTTP server instance that handles incoming webhook requests according to the configuration
 */

function createWebhookServer(
	config: WebhooksConfigResolved,
	githubConfig: GitHubHookConfig | undefined,
	ctx: WOPRPluginContext,
	logger: Logger,
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
			await ctx.events.emitCustom(event, payload);
		},
		logger,
	};

	return createServer(async (req: IncomingMessage, res: ServerResponse) => {
		// Parse URL
		const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
		const pathname = url.pathname;

		// Health check endpoint
		if (pathname === "/healthz") {
			if (req.method !== "GET") {
				sendError(res, 405, "Method not allowed");
				return;
			}
			sendJson(res, 200, { ok: true });
			return;
		}

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

		// Extract and validate token (Authorization: Bearer, X-WOPR-Token, or ?token query param)
		const { token, fromQuery } = extractToken(req, url);

		if (fromQuery) {
			logger.warn({
				msg: "Token passed as query parameter; use Authorization: Bearer or X-WOPR-Token header instead (query tokens appear in server logs)",
				path: pathname,
			});
		}

		if (!token) {
			sendError(res, 401, "Authorization required");
			return;
		}

		if (!secureCompare(token, config.token)) {
			sendError(res, 401, "Invalid token");
			return;
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
				recordDelivery({
					webhookId: "wake",
					timestamp: new Date().toISOString(),
					status: result.ok ? "success" : "error",
					httpStatus: 200,
					path: normalizedSubPath,
					action: "wake",
					payload,
					error: result.ok ? undefined : result.error,
				});
				sendJson(res, 200, result);
			} else if (normalizedSubPath === "agent") {
				result = await handleAgent(payload, handlerCtx);
				recordDelivery({
					webhookId: "agent",
					timestamp: new Date().toISOString(),
					status: result.ok ? "success" : "error",
					httpStatus: 202,
					path: normalizedSubPath,
					action: "agent",
					payload,
					error: result.ok ? undefined : result.error,
				});
				sendJson(res, 202, result); // 202 Accepted for async
			} else if (normalizedSubPath === "github") {
				// GitHub webhook with signature verification
				const headers = normalizeHeaders(req);
				result = await handleGitHub(payload, rawBody, headers, handlerCtx);

				// If no target session configured, fall through to mapped handler
				if (!result.ok && result.error === "no_target_session") {
					result = await handleMapped(normalizedSubPath, payload, headers, url, handlerCtx);
				}

				const ghStatus =
					!result.ok && result.error === "Invalid signature"
						? 401
						: !result.ok && result.error === "Unauthorized organization"
							? 403
							: !result.ok
								? 400
								: 200;
				recordDelivery({
					webhookId: "github",
					timestamp: new Date().toISOString(),
					status: result.ok ? "success" : "error",
					httpStatus: ghStatus,
					path: normalizedSubPath,
					action: result.action || "github",
					payload,
					error: result.ok ? undefined : result.error,
				});

				if (!result.ok) {
					sendError(res, ghStatus, result.error || "Unknown error");
				} else {
					sendJson(res, 200, result);
				}
			} else if (normalizedSubPath) {
				// Mapped hook
				const headers = normalizeHeaders(req);
				result = await handleMapped(normalizedSubPath, payload, headers, url, handlerCtx);

				const mappedStatus = !result.ok ? 400 : result.action === "agent" ? 202 : 200;
				recordDelivery({
					webhookId: normalizedSubPath,
					timestamp: new Date().toISOString(),
					status: result.ok ? "success" : "error",
					httpStatus: mappedStatus,
					path: normalizedSubPath,
					action: result.action || normalizedSubPath,
					payload,
					error: result.ok ? undefined : result.error,
				});

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
// Config Schema & Manifest
// ============================================================================

const configSchema = {
	title: "Webhooks",
	description: "HTTP webhook ingress for external triggers",
	fields: [
		{
			name: "enabled",
			type: "boolean" as const,
			label: "Enable Webhooks",
			description: "Enable HTTP webhook endpoints",
			default: false,
		},
		{
			name: "token",
			type: "password" as const,
			label: "Webhook Token",
			description: "Shared secret token for webhook authentication",
			required: true,
			secret: true,
		},
		{
			name: "port",
			type: "number" as const,
			label: "Port",
			description: "HTTP server port (default: 7438)",
			default: 7438,
		},
		{
			name: "host",
			type: "text" as const,
			label: "Host",
			description: "HTTP server bind address (default: 127.0.0.1)",
			default: "127.0.0.1",
		},
		{
			name: "path",
			type: "text" as const,
			label: "Base Path",
			description: "Base path for webhook endpoints (default: /hooks)",
			default: "/hooks",
		},
	],
};

// ============================================================================
// Plugin Definition
// ============================================================================

const plugin: WOPRPlugin = {
	name: "wopr-plugin-webhooks",
	version: "1.0.0",
	description: "HTTP webhook ingress for external triggers",

	manifest: {
		name: "wopr-plugin-webhooks",
		version: "1.0.0",
		description: "HTTP webhook ingress for triggering agent runs from external systems",
		author: "WOPR",
		license: "MIT",
		capabilities: ["webhooks", "http-ingress"],
		category: "integration",
		tags: ["webhooks", "http", "automation", "github", "gmail", "slack"],
		icon: "🪝",
		requires: {
			network: {
				inbound: true,
				ports: [7438],
			},
		},
		provides: {
			capabilities: [
				{
					type: "webhooks",
					id: "webhooks-http",
					displayName: "HTTP Webhooks",
					tier: "wopr",
				},
			],
		},
		lifecycle: {
			healthEndpoint: "/healthz",
			shutdownBehavior: "graceful",
			shutdownTimeoutMs: 5000,
		},
		configSchema,
	},

	commands: [
		{
			name: "webhooks",
			description: "Webhook management commands",
			usage: "wopr webhooks <status|test|mappings>",
			async handler(ctx: WOPRPluginContext, args: string[]) {
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

	async init(pluginCtx: WOPRPluginContext) {
		ctx = pluginCtx;

		// Register config schema
		if (pluginCtx.registerConfigSchema) {
			pluginCtx.registerConfigSchema("wopr-plugin-webhooks", configSchema);
		}

		const logger: Logger = {
			info: (msg) => pluginCtx.log.info(typeof msg === "string" ? msg : JSON.stringify(msg)),
			warn: (msg) => pluginCtx.log.warn(typeof msg === "string" ? msg : JSON.stringify(msg)),
			error: (msg) => pluginCtx.log.error(typeof msg === "string" ? msg : JSON.stringify(msg)),
			debug: (msg) => pluginCtx.log.debug?.(typeof msg === "string" ? msg : JSON.stringify(msg)),
		};

		// Load config from main config (webhooks section, not plugin-specific)
		const config = pluginCtx.getMainConfig?.("webhooks") as WebhooksConfig | undefined;
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
			const mainConfig = pluginCtx.getMainConfig?.() as Record<string, unknown> | undefined;
			const github = mainConfig?.github;
			if (github && typeof github === "object" && github !== null) {
				const gh = github as Record<string, unknown>;
				githubConfig = {
					webhookSecret: typeof gh.webhookSecret === "string" ? gh.webhookSecret : undefined,
					prReviewSession: typeof gh.prReviewSession === "string" ? gh.prReviewSession : undefined,
					releaseSession: typeof gh.releaseSession === "string" ? gh.releaseSession : undefined,
					allowedOrgs:
						Array.isArray(gh.orgs) && gh.orgs.every((o: unknown) => typeof o === "string")
							? (gh.orgs as string[])
							: undefined,
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

		const srv = createWebhookServer(resolvedConfig, githubConfig, pluginCtx, logger);
		server = srv;

		await new Promise<void>((resolve, reject) => {
			srv.once("error", reject);
			srv.listen(port, host, () => {
				srv.removeListener("error", reject);
				listeningPort = (srv.address() as AddressInfo).port;
				logger.info(
					`Webhooks server listening on http://${host}:${listeningPort}${resolvedConfig?.basePath}`,
				);
				resolve();
			});
		});

		// Auto-expose via tailscale funnel if available
		try {
			const funnel = pluginCtx.getExtension?.("funnel") as FunnelExtension | undefined;
			if (funnel && (await funnel.isAvailable())) {
				const url = await funnel.expose(listeningPort ?? 0);
				if (url) {
					publicUrl = `${url}${resolvedConfig.basePath}`;
					logger.info(`Webhooks publicly accessible at ${publicUrl}`);
				}
			} else {
				logger.debug("Funnel extension not available; webhooks accessible locally only");
			}
		} catch (err) {
			logger.debug(`Funnel auto-expose failed (non-fatal): ${err}`);
		}

		// Register extension for CLI and other plugins (before emitting ready event
		// so downstream listeners can call ctx.getExtension('webhooks') immediately)
		const extension: WebhooksExtension = {
			getConfig: () => resolvedConfig,
			getPort: () => listeningPort,
			getPublicUrl: () => publicUrl,

			async handleWebhook(
				path: string,
				payload: Record<string, unknown>,
				headers?: Record<string, string>,
			): Promise<WebhookResponse> {
				if (!resolvedConfig) {
					return { ok: false, error: "Webhooks not enabled" };
				}

				const handlerCtx: WebhookHandlerContext = {
					config: resolvedConfig,
					githubConfig,
					inject: async (session, message, options) => {
						return pluginCtx.inject(session, message, {
							from: "webhook",
							...options,
						});
					},
					logMessage: (session, message, options) => {
						pluginCtx.logMessage(session, message, { from: "webhook", ...options });
					},
					emit: async (event, eventPayload) => {
						await pluginCtx.events.emitCustom(event, eventPayload);
					},
					logger,
				};

				const url = new URL(`http://localhost${resolvedConfig.basePath}/${path}`);

				// Special handling for GitHub webhooks
				if (path === "github") {
					// Extension calls don't have the original raw body bytes needed for signature verification.
					// If a secret is configured, fail closed to avoid signature-bypass via the extension path.
					if (githubConfig?.webhookSecret) {
						return {
							ok: false,
							error: "GitHub webhooks with signature verification must use HTTP endpoint",
						};
					}

					if (githubConfig) {
						const result = await handleGitHub(
							payload,
							JSON.stringify(payload),
							headers || {},
							handlerCtx,
						);
						if (result.ok || result.error !== "no_target_session") {
							return result;
						}
					}
				}

				return handleMapped(path, payload, headers || {}, url, handlerCtx);
			},

			async testMapping(
				mappingId: string,
				payload: Record<string, unknown>,
			): Promise<HookMappingResult | null> {
				if (!resolvedConfig) {
					return null;
				}

				const mapping = resolvedConfig.mappings.find((m) => m.id === mappingId);
				if (!mapping) {
					return null;
				}

				const mappingCtx: HookMappingContext = {
					payload,
					headers: {},
					url: new URL(`http://localhost${resolvedConfig.basePath}/${mapping.matchPath || ""}`),
					path: mapping.matchPath || "",
				};

				return applyMappings([mapping], mappingCtx);
			},
		};

		pluginCtx.registerExtension("webhooks", extension);
		cleanups.push(() => {
			ctx?.unregisterExtension("webhooks");
		});

		// Register WebMCP extension for daemon API routes
		const webmcpExtension = createWebhooksExtension(
			() => resolvedConfig,
			() => listeningPort,
			() => publicUrl,
		);
		pluginCtx.registerExtension("webhooks-webmcp", webmcpExtension);
		cleanups.push(() => {
			ctx?.unregisterExtension("webhooks-webmcp");
		});
		logger.info("Registered webhooks-webmcp extension");

		// Emit ready event for downstream plugins
		await pluginCtx.events.emitCustom("webhooks:ready", {
			port: listeningPort,
			basePath: resolvedConfig.basePath,
			publicUrl,
		});

		// Subscribe to custom events for channel delivery via the wildcard listener,
		// since WOPREventBus.on() only accepts typed WOPREventMap keys.
		const agentResponseHandler = async (woprEvent: { type: string; payload: unknown }) => {
			if (woprEvent.type !== "webhook:agent:response") return;

			const p = (
				woprEvent.payload && typeof woprEvent.payload === "object" ? woprEvent.payload : {}
			) as Record<string, unknown>;
			const sessionKey = typeof p.sessionKey === "string" ? p.sessionKey : undefined;
			const response = typeof p.response === "string" ? p.response : "";
			const channel = typeof p.channel === "string" ? p.channel : undefined;
			const to = typeof p.to === "string" ? p.to : "";

			if (!channel || channel === "last") {
				// Use default channel provider if available
				const providers = pluginCtx.getChannelProviders();
				if (providers.length > 0) {
					try {
						await providers[0].send(to, response);
						logger.info({
							msg: "Delivered webhook response to channel",
							sessionKey,
							channel: providers[0].id,
						});
					} catch (err) {
						logger.error({
							msg: "Failed to deliver webhook response",
							sessionKey,
							error: String(err),
						});
					}
				}
				return;
			}

			// Find specific channel provider
			const provider = pluginCtx.getChannelProvider(channel);
			if (provider) {
				try {
					await provider.send(to, response);
					logger.info({
						msg: "Delivered webhook response",
						sessionKey,
						channel,
					});
				} catch (err) {
					logger.error({
						msg: "Failed to deliver webhook response",
						sessionKey,
						channel,
						error: String(err),
					});
				}
			} else {
				logger.warn({
					msg: "Channel provider not found for webhook delivery",
					channel,
				});
			}
		};

		// biome-ignore lint/suspicious/noExplicitAny: WOPREvent wildcard handler
		const unsubscribe = pluginCtx.events.on("*", agentResponseHandler as any);
		cleanups.push(() => {
			if (typeof unsubscribe === "function") {
				unsubscribe();
			}
		});

		// Clear caches on shutdown
		cleanups.push(() => {
			clearTransformCache();
			clearDeliveryHistory();
		});

		logger.info(`Webhooks plugin initialized with ${resolvedConfig.mappings.length} mappings`);
	},

	async shutdown() {
		// Run cleanups in LIFO order
		while (cleanups.length > 0) {
			const fn = cleanups.pop();
			if (!fn) break;
			try {
				await fn();
			} catch {
				// best-effort cleanup
			}
		}

		if (server) {
			server.close();
			server = null;
		}
		resolvedConfig = null;
		listeningPort = null;
		publicUrl = null;
		ctx = null;
	},
};

export type {
	WebhookDeliveryInfo,
	WebhookEndpointInfo,
	WebhooksWebMCPExtension,
	WebhookUrlInfo,
} from "./webhooks-extension.js";
export {
	clearDeliveryHistory,
	createWebhooksExtension,
	recordDelivery,
} from "./webhooks-extension.js";
export type {
	AuthContext,
	WebMCPRegistry,
	WebMCPTool,
} from "./webmcp-webhooks.js";
export { registerWebhooksTools } from "./webmcp-webhooks.js";
export default plugin;
