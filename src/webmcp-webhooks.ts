/**
 * WebMCP Webhooks Tools
 *
 * Registers 3 read-only browser-side WebMCP tools for webhook management:
 * - listWebhooks: configured endpoints and mapping rules
 * - getWebhookHistory: recent deliveries with redacted payloads
 * - getWebhookUrl: receiver URL for this instance
 *
 * These tools call the WOPR daemon REST API via fetch() and are only
 * meaningful when the webhooks plugin is loaded on the instance.
 */

// ============================================================================
// Types (mirrors WebMCPRegistry from wopr-plugin-webui)
// ============================================================================

export interface AuthContext {
	token?: string;
	[key: string]: unknown;
}

export interface ParameterSchema {
	type: string;
	description: string;
	required?: boolean;
}

export interface WebMCPTool {
	name: string;
	description: string;
	parameters: Record<string, ParameterSchema>;
	handler: (params: Record<string, unknown>, auth: AuthContext) => Promise<unknown>;
}

export interface WebMCPRegistry {
	register(tool: WebMCPTool): void;
	get(name: string): WebMCPTool | undefined;
	list(): string[];
}

// ============================================================================
// Internal helpers
// ============================================================================

interface RequestOptions {
	method?: string;
	body?: string;
	headers?: Record<string, string>;
}

async function daemonRequest<T>(
	apiBase: string,
	path: string,
	auth: AuthContext,
	options?: RequestOptions,
): Promise<T> {
	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		...options?.headers,
	};
	if (auth.token) {
		headers.Authorization = `Bearer ${auth.token as string}`;
	}
	const res = await fetch(`${apiBase}${path}`, {
		...options,
		headers,
	});
	if (!res.ok) {
		const err = await res.json().catch(() => ({ error: "Request failed" }));
		throw new Error((err as { error?: string }).error || `Request failed (${res.status})`);
	}
	return res.json() as Promise<T>;
}

// ============================================================================
// Tool registration
// ============================================================================

/**
 * Register all 3 Webhooks WebMCP tools on the given registry.
 *
 * The tools proxy to the Webhooks plugin extension via daemon API endpoints
 * at `/plugins/webhooks/endpoints`, `/plugins/webhooks/history`, etc.
 *
 * @param registry - The WebMCPRegistry instance to register tools on
 * @param apiBase  - Base URL of the WOPR daemon API (e.g. "/api" or "http://localhost:7437")
 */
export function registerWebhooksTools(registry: WebMCPRegistry, apiBase = "/api"): void {
	// 1. listWebhooks
	registry.register({
		name: "listWebhooks",
		description:
			"List configured webhook endpoints with their mapping rules. Returns endpoint IDs, action types, match paths, and whether transforms are applied.",
		parameters: {},
		handler: async (_params: Record<string, unknown>, auth: AuthContext) => {
			return daemonRequest(apiBase, "/plugins/webhooks/endpoints", auth);
		},
	});

	// 2. getWebhookHistory
	registry.register({
		name: "getWebhookHistory",
		description:
			"Get recent webhook deliveries with payloads and status. Sensitive payload data is automatically redacted. Optionally filter by webhook ID and limit results.",
		parameters: {
			webhookId: {
				type: "string",
				description: "Filter deliveries to a specific webhook endpoint ID",
				required: false,
			},
			limit: {
				type: "number",
				description: "Maximum number of deliveries to return (default: 50, max: 200)",
				required: false,
			},
		},
		handler: async (params: Record<string, unknown>, auth: AuthContext) => {
			const queryParts: string[] = [];
			if (typeof params.webhookId === "string" && params.webhookId) {
				queryParts.push(`webhookId=${encodeURIComponent(params.webhookId)}`);
			}
			if (typeof params.limit === "number" && params.limit > 0) {
				queryParts.push(`limit=${Math.floor(params.limit)}`);
			}
			const query = queryParts.length > 0 ? `?${queryParts.join("&")}` : "";
			return daemonRequest(apiBase, `/plugins/webhooks/history${query}`, auth);
		},
	});

	// 3. getWebhookUrl
	registry.register({
		name: "getWebhookUrl",
		description:
			"Get the webhook receiver URL for this WOPR instance. Returns the public URL if exposed via Tailscale Funnel, otherwise the local URL.",
		parameters: {},
		handler: async (_params: Record<string, unknown>, auth: AuthContext) => {
			return daemonRequest(apiBase, "/plugins/webhooks/url", auth);
		},
	});
}
