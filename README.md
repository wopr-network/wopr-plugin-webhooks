# wopr-plugin-webhooks

HTTP webhook ingress for WOPR - trigger agent runs from external systems.

Inspired by [OpenClaw's webhooks system](https://docs.openclaw.ai/automation/webhook).

## Features

- **POST /hooks/wake** - Notify main session of external events
- **POST /hooks/agent** - Run isolated agent with optional channel delivery
- **POST /hooks/<name>** - Custom mappings with templates and transforms
- Token-based authentication
- Payload safety wrappers for untrusted content
- Built-in presets for Gmail, GitHub, Slack

## Installation

```bash
wopr plugin add github:wopr-network/wopr-plugin-webhooks
```

## Configuration

Add to your main WOPR config (`~/.wopr/config.json`) under the `webhooks` key:

```json
{
  "webhooks": {
    "enabled": true,
    "token": "your-secret-token",
    "port": 7438,
    "host": "0.0.0.0",
    "path": "/hooks",
    "presets": ["gmail", "github"],
    "mappings": [
      {
        "id": "custom-hook",
        "match": { "path": "myapp" },
        "action": "agent",
        "name": "MyApp",
        "messageTemplate": "Event: {{event}} from {{user}}"
      }
    ]
  }
}
```

> **Note:** Configuration goes in the main config's `webhooks` section, not in a plugin-specific config file.

## Endpoints

### POST /hooks/wake

Inject a message into a specific session (synchronous).

```bash
curl -X POST http://localhost:7438/hooks/wake \
  -H 'Authorization: Bearer your-secret-token' \
  -H 'Content-Type: application/json' \
  -d '{"text": "New email received", "session": "discord:misfits:#alerts"}'
```

**Payload:**
- `text` (required): Message to inject
- `session` (required): Target session name
- `mode` (optional): `"now"` or `"next-heartbeat"` (default: `"now"`)

**Response:** `200 OK` with response from the session

### POST /hooks/agent

Run an isolated agent with the given prompt.

```bash
curl -X POST http://localhost:7438/hooks/agent \
  -H 'Authorization: Bearer your-secret-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "Summarize the latest emails",
    "name": "Email",
    "sessionKey": "hook:email:summary",
    "deliver": true,
    "channel": "discord"
  }'
```

**Payload:**
- `message` (required): Prompt for the agent
- `name` (optional): Human-readable hook name (default: `"Hook"`)
- `sessionKey` (optional): Session key for multi-turn (default: `"hook:<uuid>"`)
- `wakeMode` (optional): `"now"` or `"next-heartbeat"` (default: `"now"`)
- `deliver` (optional): Deliver response to channel (default: `true`)
- `channel` (optional): Target channel (`"discord"`, `"telegram"`, etc.)
- `to` (optional): Recipient identifier
- `model` (optional): Model override
- `thinking` (optional): Thinking level override
- `timeoutSeconds` (optional): Max duration

**Response:** `202 Accepted` with `{ "ok": true, "sessionKey": "..." }`

### POST /hooks/<name>

Custom mappings transform arbitrary payloads into wake/agent actions.

```bash
curl -X POST http://localhost:7438/hooks/gmail \
  -H 'Authorization: Bearer your-secret-token' \
  -H 'Content-Type: application/json' \
  -d '{"messages": [{"from": "Ada", "subject": "Hello", "snippet": "Hi there"}]}'
```

## Built-in Presets

### Gmail

Enable with `"presets": ["gmail"]`. Handles Gmail Pub/Sub notifications.

### GitHub

Enable with `"presets": ["github"]`. Handles push, pull_request, and issues events.

### Slack

Enable with `"presets": ["slack"]`. Handles Slack event API webhooks.

## Custom Mappings

### Agent Action (async, isolated session)

```json
{
  "mappings": [
    {
      "id": "my-hook",
      "match": { "path": "myapp" },
      "action": "agent",
      "name": "MyApp",
      "sessionKey": "hook:myapp:{{payload.user_id}}",
      "messageTemplate": "User {{user}} did {{action}} on {{resource}}",
      "deliver": true,
      "channel": "discord"
    }
  ]
}
```

### Wake Action (sync, target session)

```json
{
  "mappings": [
    {
      "id": "alert-hook",
      "match": { "path": "alerts" },
      "action": "wake",
      "session": "discord:server:#alerts",
      "textTemplate": "Alert: {{message}}"
    }
  ]
}
```

> **Tip:** For external webhooks (GitHub, etc.) that expect fast responses, use `action: "agent"` with `wakeMode: "now"` instead of `action: "wake"`. The wake action is synchronous and waits for the full AI response, which can cause 504 timeouts from impatient webhook senders.

### Template Variables

- `{{field}}` - Access payload field
- `{{payload.field}}` - Explicit payload access
- `{{headers.name}}` - Access header
- `{{query.param}}` - Access query parameter
- `{{path}}` - The hook path
- `{{now}}` - Current ISO timestamp
- `{{field[0]}}` - Array indexing

### Transform Modules

Create custom transform logic:

```typescript
// transforms/myapp.ts
export function transform(ctx) {
  const { payload, headers, url, path } = ctx;

  // Return null to skip this hook
  if (payload.type === "ping") {
    return null;
  }

  // Return overrides
  return {
    message: `Custom message: ${payload.data}`,
    name: "MyApp",
    sessionKey: `myapp:${payload.id}`,
  };
}
```

## Security

- All payloads are wrapped with safety boundaries by default
- Use `"allowUnsafeExternalContent": true` on mappings to disable (dangerous)
- Tokens are compared in constant time to prevent timing attacks
- Keep webhook endpoints behind loopback, tailnet, or trusted reverse proxy

## CLI Commands

```bash
# Check status
wopr webhooks status

# List mappings
wopr webhooks mappings

# Test a hook
wopr webhooks test gmail '{"messages":[{"from":"test","subject":"hi"}]}'
```

## Events

The plugin emits events that other plugins can subscribe to:

- `webhook:wake` - Wake event triggered
- `webhook:agent:response` - Agent run completed (for channel delivery)

## License

MIT
