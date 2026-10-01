# Config UI for fusion-siem-bridge

Date: 2026-10-01  
Status: approved for planning

## Goal

Give `fusion-siem serve` a minimal localhost UI so an operator can see whether ingest is alive and edit the `.env` settings without a React app or a second process.

## Architecture

One FastAPI process, same bind as today (`0.0.0.0:8080` by default).

- Fusion keeps posting to `POST /v1/ingest` (query token or Bearer). That path stays public.
- `GET /health` stays public.
- `GET /` is a single HTML page (no React, no Vite). CSS and a small JS module ship from the same app.
- JSON for that page: `GET /ui/status`, `GET /ui/settings`, `PUT /ui/settings`.
- UI HTML and `/ui/*` return **403** unless the peer is `127.0.0.1` or `::1`. Ingest is not gated this way.

Saving writes `.env`. The running process does **not** hot-reload. The Settings tab shows that `fusion-siem serve` must be restarted to apply.

## UI

Two tabs, no sidebar.

**Status**

- Ingest live (process is serving)
- Outbox line count (`data/outbox.jsonl`)
- Last ingest time (from the last outbox line’s `ingested_at`, or “never”)
- Generic Webhook URL with copy. Host is `FUSION_SIEM_PUBLIC_HOST` if set,
  otherwise `127.0.0.1` (never `0.0.0.0`). Path is `/v1/ingest?token=…`.
  Note on the page: Fusion needs a host it can reach; set public host on Settings
  when the collector is behind a DNS name or reverse proxy.
- Short note: UI is localhost-only; Fusion posts to `/v1/ingest`

**Settings**

- Ingest token (masked on load, e.g. last four characters; blank replace field writes only if the operator types a new value)
- Data directory
- Forward URL (optional)
- Forward token (optional, masked the same way)
- Bind host / port
- Public host (optional; used only to build the copyable webhook URL)
- Save writes `.env` and shows “restart `fusion-siem serve` to apply”

**Theme**

Client-side only (`localStorage`). Toggle between:

- Light (the light admin look)
- High contrast (black, green live indicator)

Default: light. No server round-trip for the theme.

## Data flow

```
Browser (localhost) --GET /--> HTML
                   --GET /ui/status--> counts from outbox + settings
                   --GET /ui/settings--> masked settings from env/.env
                   --PUT /ui/settings--> rewrite .env (restart still required)

Fusion             --POST /v1/ingest?token=--> unchanged pipeline
```

`.env` keys stay the existing `FUSION_SIEM_*` names. PUT must preserve comments and unrelated keys when possible; if a naive rewrite is simpler, replace the known keys and keep `CLIENT_ID` / `CLIENT_SECRET` lines untouched.

## Errors

| Case | Behavior |
| --- | --- |
| UI request not from loopback | 403 |
| PUT missing required ingest token | 422, `.env` unchanged |
| PUT cannot write `.env` | 500, `.env` unchanged |
| Outbox missing | Status shows 0 lines and last ingest “never” |
| Bad ingest body | still 422 on `/v1/ingest` (unchanged) |

## Tests

- Loopback `GET /` returns 200 HTML; a request with a non-loopback client host is 403 (Starlette `TestClient` + forced client, or a small ASGI trick).
- `GET /ui/status` and `PUT /ui/settings` are 403 off-loopback.
- `PUT /ui/settings` updates `.env` on disk; running Settings object used by `/v1/ingest` does **not** change until a new app is created (models restart-required).
- Ingest still accepts query token and still writes JSONL.
- Masked GET never returns the full ingest token.

## Out of scope

- Hot-reload of settings
- Login / admin password
- Second bind port
- Splunk HEC (or other SIEM) adapter UI
- Live tail of every outbox line
- Changing playbook YAML from the UI
