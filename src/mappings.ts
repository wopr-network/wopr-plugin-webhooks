/**
 * WOPR Webhooks Plugin - Hook Mappings
 *
 * Resolves and applies hook mappings with template rendering and transforms.
 */

import { isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";
import type {
	HookAction,
	HookMappingConfig,
	HookMappingContext,
	HookMappingResolved,
	HookMappingResult,
	HookTransformFn,
	HookTransformResult,
	WebhooksConfig,
} from "./types.js";

// ============================================================================
// Built-in Presets
// ============================================================================

const PRESET_MAPPINGS: Record<string, HookMappingConfig[]> = {
	gmail: [
		{
			id: "gmail",
			match: { path: "gmail" },
			action: "agent",
			wakeMode: "now",
			name: "Gmail",
			sessionKey: "hook:gmail:{{messages[0].id}}",
			messageTemplate:
				"New email from {{messages[0].from}}\nSubject: {{messages[0].subject}}\n{{messages[0].snippet}}\n{{messages[0].body}}",
		},
	],
	github: [
		{
			id: "github-push",
			match: { path: "github", source: "push" },
			action: "agent",
			wakeMode: "now",
			name: "GitHub",
			sessionKey: "hook:github:{{repository.full_name}}:push",
			messageTemplate:
				"Push to {{repository.full_name}} by {{pusher.name}}\n{{commits.length}} commit(s)\n{{head_commit.message}}",
		},
		{
			id: "github-pr",
			match: { path: "github", source: "pull_request" },
			action: "agent",
			wakeMode: "now",
			name: "GitHub PR",
			sessionKey: "hook:github:pr:{{pull_request.number}}",
			messageTemplate:
				"PR #{{pull_request.number}} {{action}} in {{repository.full_name}}\nTitle: {{pull_request.title}}\nBy: {{pull_request.user.login}}",
		},
		{
			id: "github-issue",
			match: { path: "github", source: "issues" },
			action: "agent",
			wakeMode: "now",
			name: "GitHub Issue",
			sessionKey: "hook:github:issue:{{issue.number}}",
			messageTemplate:
				"Issue #{{issue.number}} {{action}} in {{repository.full_name}}\nTitle: {{issue.title}}\nBy: {{issue.user.login}}",
		},
	],
	slack: [
		{
			id: "slack-event",
			match: { path: "slack" },
			action: "agent",
			wakeMode: "now",
			name: "Slack",
			sessionKey: "hook:slack:{{event.channel}}:{{event.ts}}",
			messageTemplate: "Slack event from {{event.user}}: {{event.text}}",
		},
	],
};

// ============================================================================
// Transform Cache
// ============================================================================

const transformCache = new Map<string, HookTransformFn>();

// ============================================================================
// Mapping Resolution
// ============================================================================

export function resolveMappings(
	config: WebhooksConfig,
	woprHome: string,
): HookMappingResolved[] {
	const presets = config.presets ?? [];
	const mappings: HookMappingConfig[] = [];

	// Add user-defined mappings first (higher priority)
	if (config.mappings) {
		mappings.push(...config.mappings);
	}

	// Add preset mappings
	for (const preset of presets) {
		const presetMappings = PRESET_MAPPINGS[preset];
		if (!presetMappings) {
			continue;
		}

		// Apply preset-specific config
		if (
			preset === "gmail" &&
			config.gmail?.allowUnsafeExternalContent !== undefined
		) {
			mappings.push(
				...presetMappings.map((m) => ({
					...m,
					allowUnsafeExternalContent: config.gmail?.allowUnsafeExternalContent,
				})),
			);
		} else {
			mappings.push(...presetMappings);
		}
	}

	if (mappings.length === 0) {
		return [];
	}

	// Resolve transform paths
	const transformsDir = config.transformsDir
		? resolvePath(woprHome, config.transformsDir)
		: woprHome;

	return mappings.map((m, i) => normalizeMapping(m, i, transformsDir));
}

function normalizeMapping(
	mapping: HookMappingConfig,
	index: number,
	transformsDir: string,
): HookMappingResolved {
	const id = mapping.id?.trim() || `mapping-${index + 1}`;
	const matchPath = normalizeMatchPath(mapping.match?.path);
	const matchSource = mapping.match?.source?.trim();
	const action = mapping.action ?? "agent";
	const wakeMode = mapping.wakeMode ?? "now";

	const transform = mapping.transform
		? {
				modulePath: resolvePath(transformsDir, mapping.transform.module),
				exportName: mapping.transform.export?.trim() || undefined,
			}
		: undefined;

	return {
		id,
		matchPath,
		matchSource,
		action,
		session: mapping.session,
		wakeMode,
		name: mapping.name,
		sessionKey: mapping.sessionKey,
		messageTemplate: mapping.messageTemplate,
		textTemplate: mapping.textTemplate,
		deliver: mapping.deliver,
		channel: mapping.channel,
		to: mapping.to,
		model: mapping.model,
		thinking: mapping.thinking,
		timeoutSeconds: mapping.timeoutSeconds,
		allowUnsafeExternalContent: mapping.allowUnsafeExternalContent,
		transform,
	};
}

// ============================================================================
// Mapping Application
// ============================================================================

export async function applyMappings(
	mappings: HookMappingResolved[],
	ctx: HookMappingContext,
): Promise<HookMappingResult | null> {
	if (mappings.length === 0) {
		return null;
	}

	for (const mapping of mappings) {
		if (!mappingMatches(mapping, ctx)) {
			continue;
		}

		// Build base action from mapping
		const base = buildActionFromMapping(mapping, ctx);
		if (!base.ok) {
			return base;
		}

		// Apply transform if defined
		let override: HookTransformResult = null;
		if (mapping.transform) {
			try {
				const transform = await loadTransform(mapping.transform);
				override = await transform(ctx);
				if (override === null) {
					// Transform returned null = skip this hook
					return { ok: true, action: null, skipped: true };
				}
			} catch (err) {
				return { ok: false, error: `Transform error: ${err}` };
			}
		}

		if (!base.action) {
			return { ok: true, action: null, skipped: true };
		}

		// Merge base with transform overrides
		return mergeAction(base.action, override, mapping.action);
	}

	return null; // No mapping matched
}

function mappingMatches(
	mapping: HookMappingResolved,
	ctx: HookMappingContext,
): boolean {
	// Match by path
	if (mapping.matchPath) {
		if (mapping.matchPath !== normalizeMatchPath(ctx.path)) {
			return false;
		}
	}

	// Match by payload.source
	if (mapping.matchSource) {
		const source =
			typeof ctx.payload.source === "string" ? ctx.payload.source : undefined;
		if (!source || source !== mapping.matchSource) {
			return false;
		}
	}

	return true;
}

function buildActionFromMapping(
	mapping: HookMappingResolved,
	ctx: HookMappingContext,
): HookMappingResult {
	if (mapping.action === "wake") {
		const text = renderTemplate(mapping.textTemplate ?? "", ctx);
		const session = renderOptional(mapping.session, ctx);
		if (!session) {
			return { ok: false, error: "wake action requires session" };
		}
		return {
			ok: true,
			action: {
				kind: "wake",
				text,
				session,
				mode: mapping.wakeMode,
			},
		};
	}

	// Agent action
	const message = renderTemplate(mapping.messageTemplate ?? "", ctx);
	return {
		ok: true,
		action: {
			kind: "agent",
			message,
			name: renderOptional(mapping.name, ctx),
			wakeMode: mapping.wakeMode,
			sessionKey: renderOptional(mapping.sessionKey, ctx),
			deliver: mapping.deliver,
			channel: mapping.channel,
			to: renderOptional(mapping.to, ctx),
			model: renderOptional(mapping.model, ctx),
			thinking: renderOptional(mapping.thinking, ctx),
			timeoutSeconds: mapping.timeoutSeconds,
			allowUnsafeExternalContent: mapping.allowUnsafeExternalContent,
		},
	};
}

function mergeAction(
	base: HookAction,
	override: HookTransformResult,
	defaultAction: "wake" | "agent",
): HookMappingResult {
	if (!override) {
		return validateAction(base);
	}

	const kind = override.kind ?? base.kind ?? defaultAction;

	if (kind === "wake") {
		const baseWake = base.kind === "wake" ? base : undefined;
		const text =
			typeof override.text === "string"
				? override.text
				: (baseWake?.text ?? "");
		const session =
			typeof override.session === "string"
				? override.session
				: (baseWake?.session ?? "");
		const mode =
			override.mode === "next-heartbeat"
				? "next-heartbeat"
				: (baseWake?.mode ?? "now");
		return validateAction({ kind: "wake", text, session, mode });
	}

	// Agent action
	const baseAgent = base.kind === "agent" ? base : undefined;
	const message =
		typeof override.message === "string"
			? override.message
			: (baseAgent?.message ?? "");
	const wakeMode =
		override.wakeMode === "next-heartbeat"
			? "next-heartbeat"
			: (baseAgent?.wakeMode ?? "now");

	return validateAction({
		kind: "agent",
		message,
		wakeMode,
		name: override.name ?? baseAgent?.name,
		sessionKey: override.sessionKey ?? baseAgent?.sessionKey,
		deliver:
			typeof override.deliver === "boolean"
				? override.deliver
				: baseAgent?.deliver,
		channel: override.channel ?? baseAgent?.channel,
		to: override.to ?? baseAgent?.to,
		model: override.model ?? baseAgent?.model,
		thinking: override.thinking ?? baseAgent?.thinking,
		timeoutSeconds: override.timeoutSeconds ?? baseAgent?.timeoutSeconds,
		allowUnsafeExternalContent:
			typeof override.allowUnsafeExternalContent === "boolean"
				? override.allowUnsafeExternalContent
				: baseAgent?.allowUnsafeExternalContent,
	});
}

function validateAction(action: HookAction): HookMappingResult {
	if (action.kind === "wake") {
		if (!action.text?.trim()) {
			return { ok: false, error: "hook mapping requires text" };
		}
		if (!action.session?.trim()) {
			return { ok: false, error: "wake action requires session" };
		}
		return { ok: true, action };
	}

	if (!action.message?.trim()) {
		return { ok: false, error: "hook mapping requires message" };
	}
	return { ok: true, action };
}

// ============================================================================
// Transform Loading
// ============================================================================

async function loadTransform(transform: {
	modulePath: string;
	exportName?: string;
}): Promise<HookTransformFn> {
	const cached = transformCache.get(transform.modulePath);
	if (cached) {
		return cached;
	}

	const url = pathToFileURL(transform.modulePath).href;
	const mod = (await import(url)) as Record<string, unknown>;
	const fn = resolveTransformFn(mod, transform.exportName);

	transformCache.set(transform.modulePath, fn);
	return fn;
}

function resolveTransformFn(
	mod: Record<string, unknown>,
	exportName?: string,
): HookTransformFn {
	const candidate = exportName
		? mod[exportName]
		: (mod.default ?? mod.transform);

	if (typeof candidate !== "function") {
		throw new Error("hook transform module must export a function");
	}

	return candidate as HookTransformFn;
}

// ============================================================================
// Template Rendering
// ============================================================================

function renderTemplate(template: string, ctx: HookMappingContext): string {
	if (!template) {
		return "";
	}

	return template.replace(/\{\{\s*([^}]+)\s*\}\}/g, (_, expr: string) => {
		const value = resolveTemplateExpr(expr.trim(), ctx);
		if (value === undefined || value === null) {
			return "";
		}
		if (typeof value === "string") {
			return value;
		}
		if (typeof value === "number" || typeof value === "boolean") {
			return String(value);
		}
		return JSON.stringify(value);
	});
}

function renderOptional(
	value: string | undefined,
	ctx: HookMappingContext,
): string | undefined {
	if (!value) {
		return undefined;
	}
	const rendered = renderTemplate(value, ctx).trim();
	return rendered ? rendered : undefined;
}

function resolveTemplateExpr(expr: string, ctx: HookMappingContext): unknown {
	// Built-in variables
	if (expr === "path") {
		return ctx.path;
	}
	if (expr === "now") {
		return new Date().toISOString();
	}

	// Prefixed access
	if (expr.startsWith("headers.")) {
		return getByPath(ctx.headers, expr.slice("headers.".length));
	}
	if (expr.startsWith("query.")) {
		return getByPath(
			Object.fromEntries(ctx.url.searchParams.entries()),
			expr.slice("query.".length),
		);
	}
	if (expr.startsWith("payload.")) {
		return getByPath(ctx.payload, expr.slice("payload.".length));
	}

	// Default: look in payload
	return getByPath(ctx.payload, expr);
}

function getByPath(input: Record<string, unknown>, pathExpr: string): unknown {
	if (!pathExpr) {
		return undefined;
	}

	const parts: Array<string | number> = [];
	const re = /([^.[\]]+)|(\[(\d+)\])/g;
	let match = re.exec(pathExpr);
	while (match) {
		if (match[1]) {
			parts.push(match[1]);
		} else if (match[3]) {
			parts.push(Number(match[3]));
		}
		match = re.exec(pathExpr);
	}

	let current: unknown = input;
	for (const part of parts) {
		if (current === null || current === undefined) {
			return undefined;
		}
		if (typeof part === "number") {
			if (!Array.isArray(current)) {
				return undefined;
			}
			current = current[part] as unknown;
			continue;
		}
		if (typeof current !== "object") {
			return undefined;
		}
		current = (current as Record<string, unknown>)[part];
	}

	return current;
}

// ============================================================================
// Helpers
// ============================================================================

function normalizeMatchPath(raw?: string): string | undefined {
	if (!raw) {
		return undefined;
	}
	const trimmed = raw.trim();
	if (!trimmed) {
		return undefined;
	}
	// Strip leading/trailing slashes
	return trimmed.replace(/^\/+/, "").replace(/\/+$/, "");
}

function resolvePath(baseDir: string, target: string): string {
	if (!target) {
		return baseDir;
	}
	if (isAbsolute(target)) {
		return target;
	}
	return join(baseDir, target);
}

/** Clear transform cache (for hot reload) */
export function clearTransformCache(): void {
	transformCache.clear();
}
