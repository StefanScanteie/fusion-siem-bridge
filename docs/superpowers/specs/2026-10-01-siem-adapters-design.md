# SIEM adapters: Splunk, QRadar, Rapid7, Any

Date: 2026-10-01  
Status: approved for planning

## Goal

After ingest, send each `fusion-siem.v1` envelope to **one** chosen destination: Splunk HTTP Event Collector, QRadar syslog (LEEF), Rapid7 InsightIDR custom-log webhook, or the existing generic HTTPS collector (**Any**). Fusion playbooks stay webhook-only.

## Architecture

Same FastAPI process. Envelope, idempotency key, and `data/outbox.jsonl` do not change.

`FUSION_SIEM_DESTINATION` is one of `none`, `splunk`, `qradar`, `rapid7`, `any`.

```
Fusion POST /v1/ingest
  -> parse envelope
  -> if seen: 202 duplicate (no write, no forward)
  -> append outbox.jsonl
  -> if destination != none: adapter.send(envelope)
  -> mark seen
  -> 202
```

If the adapter raises, ingest returns **502**, the event is **not** marked seen, and Fusion may retry. JSONL already has a line; a retry appends another line with a new `ingested_at`. That duplicate JSONL is accepted for this slice (no outbox replay worker).

**Backward compatible default**

| `.env` | Effective destination |
| --- | --- |
| `DESTINATION` unset, `FORWARD_URL` set | `any` |
| `DESTINATION` unset, no `FORWARD_URL` | `none` |
| `DESTINATION` set | that value |

`none` writes JSONL only (today with no forward URL).

One adapter module per destination. Pipeline calls exactly one. Unused `FUSION_SIEM_*` keys stay in `.env` and are ignored.

## Settings UI

On Settings, a **Destination** control: None, Splunk, QRadar, Rapid7, Any. Only that destination’s fields are visible. Save still upserts `.env` and still requires restart. Tokens stay masked. Ingest token, data dir, bind, public host, disclaimer stay as they are.

| Destination | Operator fields | Env keys |
| --- | --- | --- |
| None | — | `FUSION_SIEM_DESTINATION=none` |
| Splunk | HEC URL, HEC token, index (optional), sourcetype (default `fusion_siem:v1`) | `FUSION_SIEM_SPLUNK_HEC_URL`, `FUSION_SIEM_SPLUNK_HEC_TOKEN`, `FUSION_SIEM_SPLUNK_INDEX`, `FUSION_SIEM_SPLUNK_SOURCETYPE` |
| QRadar | Host, port (default `514`) | `FUSION_SIEM_QRADAR_HOST`, `FUSION_SIEM_QRADAR_PORT` |
| Rapid7 | Custom-log URL, API key | `FUSION_SIEM_RAPID7_URL`, `FUSION_SIEM_RAPID7_TOKEN` |
| Any | Forward URL, forward token | existing `FUSION_SIEM_FORWARD_URL`, `FUSION_SIEM_FORWARD_TOKEN` |

QRadar is **TCP syslog** (so connect/send failure can 502). No TLS in this slice.

## Payloads

Envelope JSON stays the canonical event. Adapters wrap it; they do not invent a second schema.

**Splunk HEC** — `POST` HEC URL, `Authorization: Splunk <token>`, `Content-Type: application/json`:

```json
{
  "event": { "...envelope..." },
  "sourcetype": "fusion_siem:v1",
  "source": "fusion-siem-bridge",
  "index": "<optional>"
}
```

Omit `index` when unset. Non-2xx from HEC is a failed send.

**QRadar** — one TCP line, LEEF 2.0, tab-separated attributes. Header vendor/product are **FusionSIEM** / **Bridge** (not Sophos). Event ID is `detection` or `case`. Include `devTime` from `ingested_at`, `ident` = envelope id, `msg` = title, `sev` 1–10 (`detection.severity * 10` clamped; case `Low=3` `Medium=5` `High=8` `Critical=10`, else `5`), plus `tenant_id` and `datastream` as custom keys. Compact envelope JSON always goes in `rawEvent` (one line).

**Rapid7** — `POST` the envelope JSON to the operator URL, `Content-Type: application/json`, `X-Api-Key: <token>`. Non-2xx is a failed send.

**Any** — today’s `HttpsAdapter`: envelope JSON, optional `Authorization: Bearer`.

## Errors

| Case | Behavior |
| --- | --- |
| Destination `none` | JSONL + seen, 202 |
| Destination set, required URL/host/token missing | **503** on ingest, `.env` unchanged, not seen |
| SIEM unreachable / non-2xx / TCP error | **502**, JSONL written, not seen |
| Duplicate idempotency key | **202** `duplicate: true`, no JSONL, no forward |
| Adapter timeout | 30s, then 502 |

No internal retry. Fusion retries. Ingest path and loopback UI gate stay unchanged.

## Tests

- `none`: ingest writes JSONL, no HTTP/TCP, 202, seen.
- `splunk`: request is HEC wrapper + `Authorization: Splunk`; 200 → seen; HEC 503 → ingest 502, not seen, JSONL has a line.
- `qradar`: captured TCP payload starts with `LEEF:2.0|FusionSIEM|Bridge|`; connect fail → 502, not seen.
- `rapid7`: `X-Api-Key` set, body is envelope JSON; 200 → seen.
- `any`: existing Bearer HTTPS envelope POST still works.
- Unset `DESTINATION` + `FORWARD_URL` behaves as `any`.
- Settings GET/PUT round-trip destination fields; blank tokens keep existing; unused vendor keys preserved in `.env`.
- UI still 403 off-loopback; `/v1/ingest` still public.

## Out of scope

- Microsoft Sentinel
- Fan-out to more than one SIEM at once
- QRadar TLS / UDP
- Hot-reload
- Outbox replay / JSONL-dedup on Fusion retry
- Changing playbook YAML
