/**
 * Webhooks Extension (cross-plugin API)
 *
 * Provides the extension object registered with core for other plugins
 * and daemon API routes to expose webhook management data via WebMCP tools.
 *
 * All methods are read-only. Configuration changes happen via the dashboard.
 */

import type { HookMappingResolved, WebhooksConfigResolved } from "./types.js";

// ============================================================================
// Structured return types for WebMCP-facing extension methods
// ============================================================================

export interface WebhookEndpointInfo {
	id: string;
	action: "wake" | "agent";
	matchPath?: string;
	matchSource?: string;
	name?: string;
	wakeMode: "now" | "next-heartbeat";
	hasTransform: boolean;
}

export interface WebhookDeliveryInfo {
	id: string;
	webhookId: string;
	timestamp: string;
	status: "success" | "error";
	httpStatus?: number;
	path: string;
	action: string;
	payload: Record<string, unknown>;
	error?: string;
}

export interface WebhookUrlInfo {
	url: string | null;
	basePath: string;
	port: number | null;
	isPublic: boolean;
}

export interface WebhooksWebMCPExtension {
	/** List configured webhook endpoints with their mapping rules */
	listWebhooks: () => WebhookEndpointInfo[];

	/** Recent webhook deliveries with payloads (sensitive data redacted) */
	getWebhookHistory: (
		webhookId?: string,
		limit?: number,
	) => WebhookDeliveryInfo[];

	/** Get the webhook receiver URL for this instance */
	getWebhookUrl: () => WebhookUrlInfo;
}

// ============================================================================
// Delivery history ring buffer
// ============================================================================

const DEFAULT_HISTORY_LIMIT = 50;
const MAX_HISTORY_SIZE = 200;

/** In-memory ring buffer for recent webhook deliveries */
const deliveryHistory: WebhookDeliveryInfo[] = [];
let deliveryCounter = 0;

/**
 * Record a webhook delivery for history tracking.
 *
 * Called by the plugin's request handler after processing each webhook.
 * Payloads are stored with sensitive fields redacted.
 */
export function recordDelivery(
	entry: Omit<WebhookDeliveryInfo, "id" | "payload"> & {
		payload: Record<string, unknown>;
	},
): void {
	deliveryCounter++;
	const delivery: WebhookDeliveryInfo = {
		...entry,
		id: `delivery-${deliveryCounter}`,
		payload: redactSensitiveFields(entry.payload),
	};
	deliveryHistory.push(delivery);
	if (deliveryHistory.length > MAX_HISTORY_SIZE) {
		deliveryHistory.splice(0, deliveryHistory.length - MAX_HISTORY_SIZE);
	}
}

/** Clear delivery history (for testing and shutdown) */
export function clearDeliveryHistory(): void {
	deliveryHistory.length = 0;
	deliveryCounter = 0;
}

// ============================================================================
// Sensitive data redaction
// ============================================================================

/** Fields that should be redacted from webhook payloads exposed via WebMCP */
const SENSITIVE_FIELDS = new Set([
	"token",
	"secret",
	"password",
	"api_key",
	"apikey",
	"api_secret",
	"apisecret",
	"access_token",
	"accesstoken",
	"refresh_token",
	"refreshtoken",
	"authorization",
	"auth",
	"credentials",
	"private_key",
	"privatekey",
	"secret_key",
	"secretkey",
	"webhook_secret",
	"webhooksecret",
	"signing_secret",
	"signingsecret",
	"client_secret",
	"clientsecret",
	"ssn",
	"credit_card",
	"creditcard",
	"card_number",
	"cardnumber",
	"cvv",
	"pin",
]);

function redactSensitiveFields(
	obj: Record<string, unknown>,
	depth = 0,
): Record<string, unknown> {
	if (depth > 5) return { "[depth limit]": true };

	const result: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(obj)) {
		const lowerKey = key.toLowerCase().replace(/[-_]/g, "");
		if (
			SENSITIVE_FIELDS.has(lowerKey) ||
			SENSITIVE_FIELDS.has(key.toLowerCase())
		) {
			result[key] = "[REDACTED]";
		} else if (
			value !== null &&
			typeof value === "object" &&
			!Array.isArray(value)
		) {
			result[key] = redactSensitiveFields(
				value as Record<string, unknown>,
				depth + 1,
			);
		} else if (Array.isArray(value)) {
			result[key] = value.map((item) =>
				item !== null && typeof item === "object" && !Array.isArray(item)
					? redactSensitiveFields(item as Record<string, unknown>, depth + 1)
					: item,
			);
		} else {
			result[key] = value;
		}
	}
	return result;
}

// ============================================================================
// Extension factory
// ============================================================================

function mappingToEndpointInfo(
	mapping: HookMappingResolved,
): WebhookEndpointInfo {
	return {
		id: mapping.id,
		action: mapping.action,
		matchPath: mapping.matchPath,
		matchSource: mapping.matchSource,
		name: mapping.name,
		wakeMode: mapping.wakeMode,
		hasTransform: !!mapping.transform,
	};
}

/**
 * Create the Webhooks WebMCP extension object.
 *
 * Uses getter functions so the extension always reflects the current
 * runtime state of the plugin.
 */
export function createWebhooksExtension(
	getConfig: () => WebhooksConfigResolved | null,
	getPort: () => number | null,
	getPublicUrl: () => string | null,
): WebhooksWebMCPExtension {
	return {
		listWebhooks: (): WebhookEndpointInfo[] => {
			const config = getConfig();
			if (!config) return [];
			return config.mappings.map(mappingToEndpointInfo);
		},

		getWebhookHistory: (
			webhookId?: string,
			limit?: number,
		): WebhookDeliveryInfo[] => {
			const cap = Math.min(
				Math.max(1, limit ?? DEFAULT_HISTORY_LIMIT),
				MAX_HISTORY_SIZE,
			);

			let entries = deliveryHistory;
			if (webhookId) {
				entries = entries.filter((d) => d.webhookId === webhookId);
			}

			// Return most recent first, up to `cap`
			return entries.slice(-cap).reverse();
		},

		getWebhookUrl: (): WebhookUrlInfo => {
			const config = getConfig();
			const pubUrl = getPublicUrl();
			const port = getPort();

			return {
				url:
					pubUrl ??
					(port
						? `http://localhost:${port}${config?.basePath ?? "/hooks"}`
						: null),
				basePath: config?.basePath ?? "/hooks",
				port,
				isPublic: pubUrl !== null,
			};
		},
	};
}
