# Fusion (XDR) SIEM Bridge

Middleware plus Fusion Automations playbooks that export **detections**, **related events**, and **cases** from Sophos Fusion (Sophos XDR powered by Secureworks) to a SIEM.

The repo is `fusion-siem-bridge`; the CLI is `fusion-siem`. Fusion playbooks can only POST HTTPS. They cannot talk Splunk HEC, Sentinel, or syslog directly. This middleware is the “any SIEM” side: it accepts the Fusion webhook JSON those playbooks POST, normalizes it to a stable `fusion-siem.v1` envelope, writes that envelope locally, and optionally forwards it to another HTTP collector.

```
Fusion Automations
  Custom_Webhook / send-to-webhook / cases-to-webhook
        |
        |  HTTPS POST  /v1/ingest?token=...
        v
fusion-siem-bridge
        |- data/outbox.jsonl     (always)
        |- data/seen.txt         (idempotency)
        `- FUSION_SIEM_FORWARD_URL  (optional HTTPS fan-out)

SDK backfill (taegis-sdk-python) ---- same /v1/ingest ----^
```

This is **not** a Data Lake firehose. The slice is detections (Alert2), events linked to those detections or cases, and cases. Downstream SIEM mapping belongs in this middleware, not in a one-off Fusion playbook per SIEM.

See [playbooks/INSTALL.md](playbooks/INSTALL.md) for the operator walkthrough and [playbooks/CONTRACT.md](playbooks/CONTRACT.md) for the JSON envelope.

## Which playbook to import

Use one Generic Webhook connection. Pick playbooks by whether you need resolved related events:

| Goal | Import | POST body |
| --- | --- | --- |
| Detections **and** related events | [playbooks/Custom_Webhook_v1.0.1.yaml](playbooks/Custom_Webhook_v1.0.1.yaml) | `{ "alert": <Alert2>, "events": <Event.resolve> }` |
| Detections **and** cases, no event resolve | [playbooks/send-to-webhook.yaml](playbooks/send-to-webhook.yaml) | Raw trigger `inputs` |
| Cases **and** related events | [playbooks/cases-to-webhook.yaml](playbooks/cases-to-webhook.yaml) | `{ "alert": { "type": "case", ... }, "events": <Event.resolve> }` |

Typical pairing: `Custom_Webhook_v1.0.1.yaml` for detections, plus `cases-to-webhook.yaml` if the SIEM should see case event evidence. Use `send-to-webhook.yaml` alone if one playbook for both sources is enough and related events can wait for backfill or a later adapter.

[playbooks/detections-to-webhook.yaml](playbooks/detections-to-webhook.yaml) is the same detections workflow as `Custom_Webhook_v1.0.1.yaml`, without the template icon. Walkthrough: [playbooks/Custom Webhook Playbook Template_v1.0.1.pdf](playbooks/Custom%20Webhook%20Playbook%20Template_v1.0.1.pdf).

### Recommended platform triggers

**Detections** (`Custom_Webhook_v1.0.1.yaml` / `detections-to-webhook.yaml`)

| Field | Value |
| --- | --- |
| Trigger type | Platform |
| Source | Alert2 |
| Events | Create |
| Filter | `alertSeverity(inputs) >= .6` |

**Detections** (`send-to-webhook.yaml`) — same High/Critical cut, newer CEL names:

`detectionSeverityNice(inputs) in ['High','Critical']`

**Cases** (`cases-to-webhook.yaml` / `send-to-webhook.yaml`)

| Field | Value |
| --- | --- |
| Trigger type | Platform |
| Source | case |
| Events | Create, Update, Delete, Events Added |
| Filter | `caseSeverity(inputs) in ['High', 'Critical']` |

`send-to-webhook.yaml` can also run on detection/asset/comment/file/link case mutations. Add those events if the SIEM should see every case change.

## Quick start

Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
# set FUSION_SIEM_INGEST_TOKEN in .env

fusion-siem serve
```

Default bind is `0.0.0.0:8080`. Health check: `GET /health`. On the same
machine, open [http://127.0.0.1:8080/](http://127.0.0.1:8080/) for the
Status / Settings UI (see [Local UI](#local-ui)). Fusion still posts to
`/v1/ingest`.

In another shell, POST a sample envelope:

```bash
export FUSION_SIEM_INGEST_TOKEN='the-same-token'
fusion-siem post-file examples/detection.json
```

`data/outbox.jsonl` should gain one canonical line. The same tenant + datastream + id posted again returns HTTP `202` with `"duplicate": true` and is not written again.

Native Taegis webhook shapes (query token, matching Generic Webhook):

```bash
fusion-siem post-file examples/taegis-webhook-alert.json \
  --url 'http://127.0.0.1:8080/v1/ingest?token=the-same-token'
fusion-siem post-file examples/taegis-webhook-case.json \
  --url 'http://127.0.0.1:8080/v1/ingest?token=the-same-token'
fusion-siem post-file examples/taegis-send-to-webhook-case.json \
  --url 'http://127.0.0.1:8080/v1/ingest?token=the-same-token'
```

`fusion-siem post-file` still sends `Authorization: Bearer`. The middleware accepts **either** the query token **or** Bearer. Generic Webhook from Fusion only sends the query token.

## Local UI

On the same machine as `fusion-siem serve`, open
[http://127.0.0.1:8080/](http://127.0.0.1:8080/). The page is loopback-only
(`127.0.0.1` / `::1`); any other client gets `403`. There is no login.
`GET /health` and `POST /v1/ingest` stay reachable on the bind address.

The header is **Fusion (XDR) SIEM Bridge** / **Middleware**.

| Tab | Shows |
| --- | --- |
| Status | Ingest live/down, outbox line count, last ingest time, copyable Generic Webhook URL |
| Settings | Destination (None / Splunk / QRadar / Rapid7 / Any) and that destination’s fields; ingest token; data directory; bind host/port; public host |

The copied webhook URL uses `FUSION_SIEM_PUBLIC_HOST` when set, otherwise
`127.0.0.1` (never `0.0.0.0`). If Fusion cannot reach loopback, set public host
to a DNS name Fusion can call.

**Save .env** upserts `FUSION_SIEM_*` keys and leaves other lines (including
`CLIENT_ID`) alone. Blank token fields keep the current secrets. The process
does not hot-reload: restart `fusion-siem serve` before a new ingest token is
honored. Light / Dark is stored in the browser, not in `.env`.

Pick **one** destination. After JSONL write, ingest forwards that envelope:

| Destination | Protocol |
| --- | --- |
| None | JSONL only |
| Splunk | HTTP Event Collector (`Authorization: Splunk`) |
| QRadar | TCP syslog LEEF 2.0. TLS is currently not supported. |
| Rapid7 | InsightIDR custom-log webhook (`X-Api-Key`) |
| Any | Generic HTTPS JSON (Bearer), same as today’s forward URL |

If the SIEM is down, ingest returns **502** and does not mark the event seen (Fusion may retry). If the destination is selected but missing URL/host/token, ingest returns **503** and does not write JSONL. Unset `FUSION_SIEM_DESTINATION` with `FORWARD_URL` set still behaves as Any.

## Fusion connection

In Fusion: **Automations → Connections → Generic Webhook**.

```
https://<public-host>/v1/ingest?token=<FUSION_SIEM_INGEST_TOKEN>
```

`Taegis.Webhook.post` does **not** send an `Authorization` header. The connection Test button is inactive (note in the webhook PDF). Do not create a `FusionSIEM.Webhook` connector.

The middleware host must be reachable from Fusion (public HTTPS or a reverse proxy Fusion can call). Copy the URL from Status after setting public host if Fusion cannot use `127.0.0.1`.

## What the middleware accepts

`POST /v1/ingest` is untyped JSON. The parser then maps every supported inbound shape to the same envelope.

| Inbound | How it arrives | How it is recognized |
| --- | --- | --- |
| `Custom_Webhook_v1.0.1.yaml` | `{ "alert": <Alert2>, "events": ... }` | `alert` / `alert2` present, `type` is `alert2` or absent |
| `cases-to-webhook.yaml` | `{ "alert": { "type": "case", ... }, "events": ... }` | `alert.type == "case"` |
| `send-to-webhook.yaml` detection | Raw Alert2 trigger `inputs` | nested `alert2`, or top-level `type: alert2` |
| `send-to-webhook.yaml` case | Raw case trigger `inputs` | `type: SECURITY_CASE`, `keyFindings` / `primaryStatus`, nested `case`, or PascalCase case `event` |
| Backfill / `post-file` | Canonical `fusion-siem.v1` | `datastream` is `detection` or `case` |

Auth:

| Client | Token |
| --- | --- |
| Fusion Generic Webhook | `?token=` on the URL |
| `fusion-siem post-file` / `backfill` | `Authorization: Bearer` (query token also works) |

Missing/wrong token → `401`. Unrecognized body → `422`. Success and duplicates → `202`. Destination misconfigured → `503`. SIEM send failed → `502`.

```json
{ "idempotency_key": "48454:detection:alert://...", "duplicate": false }
```

Idempotency key is `{tenant_id}:{datastream}:{id}`. Case updates from Fusion reuse the case id, so a later Update is treated as a duplicate unless the key is changed. The current store is create-once, which matches detections; case Update/Delete fan-out is still a later adapter concern.

## Canonical envelope (`fusion-siem.v1`)

Written to `data/outbox.jsonl` and, if configured, POSTed to `FUSION_SIEM_FORWARD_URL`.

Detection severity stays on the Fusion GraphQL `0.0`–`1.0` scale. Case severity and priority stay Fusion case strings (`High`, `Critical`). Do not convert either to a SIEM integer in this middleware until a named adapter does it.

**Detection**

```json
{
  "schema_version": "fusion-siem.v1",
  "datastream": "detection",
  "tenant_id": "48454",
  "source": "playbook",
  "detection": {
    "id": "alert://...",
    "title": "Suspicious PowerShell activity",
    "severity": 0.8,
    "status": "OPEN",
    "sensor_types": ["ENDPOINT_TAEGIS"],
    "attack_technique_ids": ["T1059.001"]
  },
  "case": null,
  "events": []
}
```

**Case**

```json
{
  "schema_version": "fusion-siem.v1",
  "datastream": "case",
  "tenant_id": "48454",
  "source": "playbook",
  "detection": null,
  "case": {
    "id": "case://48454/abc-123",
    "title": "Suspected intrusion",
    "severity": "High",
    "priority": "Critical",
    "status": "OPEN",
    "case_type": "SECURITY_CASE",
    "url": "https://console.example/cases/abc-123",
    "key_findings": "Key findings from the case",
    "event": "Create"
  },
  "events": []
}
```

Full field notes: [playbooks/CONTRACT.md](playbooks/CONTRACT.md).

## Sample payloads

| File | Shape |
| --- | --- |
| [examples/detection.json](examples/detection.json) | Canonical detection |
| [examples/case.json](examples/case.json) | Canonical case |
| [examples/taegis-webhook-alert.json](examples/taegis-webhook-alert.json) | `Custom_Webhook_v1.0.1.yaml` `{alert, events}` |
| [examples/taegis-webhook-case.json](examples/taegis-webhook-case.json) | `cases-to-webhook.yaml` `{alert: {type: case}, events}` |
| [examples/taegis-send-to-webhook-case.json](examples/taegis-send-to-webhook-case.json) | `send-to-webhook.yaml` raw case `inputs` |

## CLI

```bash
fusion-siem serve
fusion-siem post-file <file.json> [--url URL] [--token TOKEN]
fusion-siem backfill --tenant-id <uuid> [--earliest -1d] [--url URL] [--console-url URL]
```

`--url` defaults to `http://127.0.0.1:8080/v1/ingest` or `FUSION_SIEM_INGEST_URL`. `--token` defaults to `FUSION_SIEM_INGEST_TOKEN`.

## Backfill

Pulls recent detections from Fusion GraphQL via [taegis-sdk-python](https://github.com/secureworks/taegis-sdk-python) and POSTs the same canonical documents the playbooks produce after mapping. Default window is `EARLIEST=-1d`. This is catch-up, not a Data Lake dump.

```bash
pip install -e '.[backfill]'
export CLIENT_ID=...
export CLIENT_SECRET=...
export FUSION_SIEM_INGEST_TOKEN='the-same-token'
fusion-siem backfill --tenant-id <tenant-uuid>
```

`CLIENT_ID` / `CLIENT_SECRET` are Taegis SDK credentials, not the ingest token.

## Configuration

Copy [.env.example](.env.example). Variables use the `FUSION_SIEM_` prefix.

| Variable | Purpose |
| --- | --- |
| `FUSION_SIEM_INGEST_TOKEN` | Shared secret for `/v1/ingest` (query and/or Bearer) |
| `FUSION_SIEM_DATA_DIR` | Outbox and idempotency store (default `data`) |
| `FUSION_SIEM_DESTINATION` | `none`, `splunk`, `qradar`, `rapid7`, or `any` |
| `FUSION_SIEM_SPLUNK_HEC_URL` / `_TOKEN` / `_INDEX` / `_SOURCETYPE` | Splunk HEC (sourcetype default `fusion_siem:v1`) |
| `FUSION_SIEM_QRADAR_HOST` / `_PORT` | QRadar TCP syslog LEEF (port default `514`). TLS is currently not supported. |
| `FUSION_SIEM_RAPID7_URL` / `_TOKEN` | Rapid7 InsightIDR custom-log webhook |
| `FUSION_SIEM_FORWARD_URL` | Any: HTTPS collector for the canonical envelope |
| `FUSION_SIEM_FORWARD_TOKEN` | Bearer token for Any |
| `FUSION_SIEM_HOST` / `FUSION_SIEM_PORT` | Bind address (default `0.0.0.0:8080`) |
| `FUSION_SIEM_PUBLIC_HOST` | Hostname in the Status page webhook URL (optional; never `0.0.0.0`) |
| `FUSION_SIEM_INGEST_URL` | CLI default for `post-file` / `backfill` |
| `FUSION_SIEM_CONSOLE_URL` | Console base used when backfill builds alert/case URLs |
| `CLIENT_ID` / `CLIENT_SECRET` | Taegis SDK auth for backfill only |

The Settings form writes the `FUSION_SIEM_*` rows above. Events always land in `data/outbox.jsonl`. Named adapters then wrap that envelope for Splunk HEC, QRadar LEEF, Rapid7, or Any. Microsoft Sentinel is not in this slice.

## Tests

```bash
pytest
```

## Layout

```
playbooks/     Fusion YAML, install notes, payload contract
examples/      Canonical and native webhook JSON
src/fusion_siem/
  app.py       FastAPI /v1/ingest, /health, localhost UI
  ui.py        loopback gate, /ui/status, /ui/settings
  envfile.py   Settings form upserts `.env`
  web/         Status / Settings page (Light / Dark)
  envelope.py  Fusion webhook JSON → fusion-siem.v1
  pipeline.py  idempotency, JSONL, one SIEM adapter
  adapters/    jsonl, Splunk HEC, QRadar LEEF, Rapid7, HTTPS Any
  backfill.py  SDK detection/case mapping
tests/
```

## Disclaimer

Disclaimer: This software is provided free of charge, "as is," and without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement. This software is not officially supported by Sophos, and Sophos has no obligation to provide maintenance, updates, or support for it. You are responsible for reviewing and testing the software before using it in any environment. Use of this software is at your own risk. In no event will Sophos be liable for any damages, including but not limited to data loss, system downtime, security incidents, or business interruption, arising from the use of or inability to use this software.
