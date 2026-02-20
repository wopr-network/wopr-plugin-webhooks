# wopr-plugin-webhooks

HTTP webhook ingress for WOPR — trigger agent runs from external systems.

## Commands

```bash
npm run build     # tsc
npm run check     # biome check + tsc --noEmit (run before committing)
npm run format    # biome format --write src/
npm test          # vitest run
```

## Architecture

```
src/
  index.ts      # Plugin entry — registers HTTP server, webhook endpoint
  handlers.ts   # Webhook payload handlers (dispatch to WOPR sessions)
  mappings.ts   # Webhook → session/channel mapping rules
  security.ts   # Signature verification (HMAC, bearer tokens)
  types.ts      # Plugin-local types
```

## Key Details

- Listens on a configurable port for incoming HTTP POST webhooks
- `security.ts` handles request verification — always validate signatures before processing
- `mappings.ts` routes webhook payloads to the correct WOPR session/channel
- Supports custom payload shapes via configurable field mappings
- **Gotcha**: Needs a public URL to receive webhooks. Use `wopr-plugin-tailscale-funnel` or similar for local dev.
- **Security**: Never process a webhook without signature verification — `security.ts` handles this, don't bypass it.

## Plugin Contract

Imports only from `@wopr-network/plugin-types`. Never import from `@wopr-network/wopr` core.

## Issue Tracking

All issues in **Linear** (team: WOPR). Issue descriptions start with `**Repo:** wopr-network/wopr-plugin-webhooks`.

## Session Memory

At the start of every WOPR session, **read `~/.wopr-memory.md` if it exists.** It contains recent session context: which repos were active, what branches are in flight, and how many uncommitted changes exist. Use it to orient quickly without re-investigating.

The `Stop` hook writes to this file automatically at session end. Only non-main branches are recorded — if everything is on `main`, nothing is written for that repo.