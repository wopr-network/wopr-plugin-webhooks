/**
 * WOPR Webhooks Plugin - Type Definitions
 *
 * HTTP webhook ingress for triggering agent runs from external systems.
 */

// ============================================================================
// Configuration
// ============================================================================

export interface WebhooksConfig {
	/** Enable webhook endpoints */
	enabled: boolean;

	/** Shared secret token for authentication */
	token: string;

	/** HTTP server port (default: 7438) */
	port?: number;

	/** HTTP server host (default: 127.0.0.1) */
	host?: string;

	/** Base path for webhook endpoints (default: /hooks) */
	path?: string;

	/** Maximum request body size in bytes (default: 256KB) */
	maxBodyBytes?: number;

	/** Built-in presets to enable (e.g., ["gmail"]) */
	presets?: string[];

	/** Custom hook mappings */
	mappings?: HookMappingConfig[];

	/** Directory for transform modules (relative to WOPR_HOME) */
	transformsDir?: string;

	/** Per-preset configuration */
	gmail?: GmailHookConfig;
	github?: GitHubHookConfig;
}

export interface GitHubHookConfig {
	/** Webhook secret for signature verification (from wopr.config.json github.webhookSecret) */
	webhookSecret?: string;

	/** Session to route PR events to (from wopr.config.json github.prReviewSession) */
	prReviewSession?: string;

	/** Session to route release events to */
	releaseSession?: string;

	/** Organizations to accept webhooks from (empty = accept all) */
	allowedOrgs?: string[];
}

export interface GmailHookConfig {
	/** Gmail account to watch */
	account?: string;

	/** Label to watch */
	label?: string;

	/** Pub/Sub topic path */
	topic?: string;

	/** Pub/Sub subscription name */
	subscription?: string;

	/** OpenClaw-compatible hook URL */
	hookUrl?: string;

	/** Push token for gog watch serve */
	pushToken?: string;

	/** Allow unsafe external content (dangerous) */
	allowUnsafeExternalContent?: boolean;
}

// ============================================================================
// Hook Mappings
// ============================================================================

export interface HookMappingConfig {
	/** Unique identifier for this mapping */
	id?: string;

	/** Match criteria */
	match?: {
		/** Match by path suffix (e.g., "gmail" matches /hooks/gmail) */
		path?: string;

		/** Match by payload.source field */
		source?: string;
	};

	/** Action type: wake (inject to session) or agent (isolated run) */
	action?: "wake" | "agent";

	/** Target session for wake action (supports templates) */
	session?: string;

	/** Wake mode: now (immediate) or next-heartbeat */
	wakeMode?: "now" | "next-heartbeat";

	/** Human-readable name for the hook */
	name?: string;

	/** Session key for agent runs (supports templates) */
	sessionKey?: string;

	/** Message template for agent action (supports {{payload.field}}) */
	messageTemplate?: string;

	/** Text template for wake action */
	textTemplate?: string;

	/** Whether to deliver response to a channel */
	deliver?: boolean;

	/** Target channel for delivery */
	channel?: string;

	/** Recipient identifier */
	to?: string;

	/** Model override */
	model?: string;

	/** Thinking level override */
	thinking?: string;

	/** Timeout in seconds */
	timeoutSeconds?: number;

	/** Allow unsafe external content (dangerous) */
	allowUnsafeExternalContent?: boolean;

	/** Transform module for custom logic */
	transform?: {
		/** Module path (relative to transformsDir) */
		module: string;

		/** Export name (default: "default" or "transform") */
		export?: string;
	};
}

export interface HookMappingResolved {
	id: string;
	matchPath?: string;
	matchSource?: string;
	action: "wake" | "agent";
	session?: string;
	wakeMode: "now" | "next-heartbeat";
	name?: string;
	sessionKey?: string;
	messageTemplate?: string;
	textTemplate?: string;
	deliver?: boolean;
	channel?: string;
	to?: string;
	model?: string;
	thinking?: string;
	timeoutSeconds?: number;
	allowUnsafeExternalContent?: boolean;
	transform?: {
		modulePath: string;
		exportName?: string;
	};
}

// ============================================================================
// Hook Actions
// ============================================================================

export type HookAction = WakeAction | AgentAction;

export interface WakeAction {
	kind: "wake";
	text: string;
	session: string;
	mode: "now" | "next-heartbeat";
}

export interface AgentAction {
	kind: "agent";
	message: string;
	name?: string;
	wakeMode: "now" | "next-heartbeat";
	sessionKey?: string;
	deliver?: boolean;
	channel?: string;
	to?: string;
	model?: string;
	thinking?: string;
	timeoutSeconds?: number;
	allowUnsafeExternalContent?: boolean;
}

// ============================================================================
// Request/Response Types
// ============================================================================

export interface WakePayload {
	/** Event description text */
	text: string;

	/** Target session to inject into */
	session: string;

	/** Trigger mode */
	mode?: "now" | "next-heartbeat";
}

export interface AgentPayloadInput {
	/** Prompt message for the agent */
	message: string;

	/** Human-readable hook name */
	name?: string;

	/** Session key (default: hook:<uuid>) */
	sessionKey?: string;

	/** Trigger mode */
	wakeMode?: "now" | "next-heartbeat";

	/** Deliver response to channel */
	deliver?: boolean;

	/** Target channel */
	channel?: string;

	/** Recipient */
	to?: string;

	/** Model override */
	model?: string;

	/** Thinking level */
	thinking?: string;

	/** Timeout seconds */
	timeoutSeconds?: number;
}

/** Validated agent payload with required fields resolved */
export interface AgentPayload {
	/** Prompt message for the agent */
	message: string;

	/** Human-readable hook name */
	name: string;

	/** Session key (always set after validation) */
	sessionKey: string;

	/** Trigger mode */
	wakeMode: "now" | "next-heartbeat";

	/** Deliver response to channel */
	deliver: boolean;

	/** Target channel */
	channel?: string;

	/** Recipient */
	to?: string;

	/** Model override */
	model?: string;

	/** Thinking level */
	thinking?: string;

	/** Timeout seconds */
	timeoutSeconds?: number;
}

export interface HookMappingContext {
	payload: Record<string, unknown>;
	headers: Record<string, string>;
	url: URL;
	path: string;
}

export type HookTransformResult = Partial<{
	kind: "wake" | "agent";
	text: string;
	session: string;
	mode: "now" | "next-heartbeat";
	message: string;
	wakeMode: "now" | "next-heartbeat";
	name: string;
	sessionKey: string;
	deliver: boolean;
	channel: string;
	to: string;
	model: string;
	thinking: string;
	timeoutSeconds: number;
	allowUnsafeExternalContent: boolean;
}> | null;

export type HookTransformFn = (
	ctx: HookMappingContext,
) => HookTransformResult | Promise<HookTransformResult>;

// ============================================================================
// Result Types
// ============================================================================

export type HookMappingResult =
	| { ok: true; action: HookAction }
	| { ok: true; action: null; skipped: true }
	| { ok: false; error: string };

export interface WebhookResponse {
	ok: boolean;
	error?: string;
	sessionKey?: string;
	action?: string;
}

// ============================================================================
// Plugin Context Extensions
// ============================================================================

export interface WebhooksExtension {
	/** Get resolved config */
	getConfig(): WebhooksConfigResolved | null;

	/** Get the port the webhooks server is listening on */
	getPort(): number | null;

	/** Get the full public URL if exposed via funnel (e.g. https://host.tailnet.ts.net/hooks) */
	getPublicUrl(): string | null;

	/** Handle a webhook request programmatically */
	handleWebhook(
		path: string,
		payload: Record<string, unknown>,
		headers?: Record<string, string>,
	): Promise<WebhookResponse>;

	/** Test a webhook mapping */
	testMapping(
		mappingId: string,
		payload: Record<string, unknown>,
	): Promise<HookMappingResult | null>;
}

export interface WebhooksConfigResolved {
	basePath: string;
	token: string;
	maxBodyBytes: number;
	mappings: HookMappingResolved[];
}

// ============================================================================
// External Extension Interfaces
// ============================================================================

export interface FunnelExtension {
	isAvailable(): Promise<boolean>;
	expose(port: number): Promise<string | null>;
}
