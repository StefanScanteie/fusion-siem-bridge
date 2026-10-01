# fusion-siem-bridge

Middleware plus Fusion Automations playbooks that export **detections**, **related events**, and **cases** to a SIEM.

Fusion playbooks can only POST HTTPS. This collector is the “any SIEM” side: it accepts a stable JSON contract, writes it locally, and can forward it to Splunk HEC, Sentinel, syslog, or another HTTP endpoint.

```
Fusion playbook  --HTTPS POST fusion-siem.v1-->  middleware /v1/ingest
                                                  |- data/outbox.jsonl (always)
                                                  `- FUSION_SIEM_FORWARD_URL (optional)
SDK backfill     --same contract--------------^
```

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

In another shell:

```bash
export FUSION_SIEM_INGEST_TOKEN='the-same-token'
fusion-siem post-file examples/detection.json
```

`data/outbox.jsonl` should gain a canonical envelope. Duplicates of the same tenant + datastream + id return `202` with `"duplicate": true` and are not written again.

## Fusion playbooks

See [playbooks/INSTALL.md](playbooks/INSTALL.md) and [playbooks/CONTRACT.md](playbooks/CONTRACT.md).

| File | Trigger | What it sends |
| --- | --- | --- |
| [playbooks/detections-to-webhook.yaml](playbooks/detections-to-webhook.yaml) | `alert2` create | Detection + resolved related events |
| [playbooks/cases-to-webhook.yaml](playbooks/cases-to-webhook.yaml) | investigation/case create | Case + related events when IDs are present |

Create a Custom Connector `FusionSIEM.Webhook` with function `post` (HTTP POST, `Authorization: Bearer <token>`, JSON body). Point the playbook webhook URL at `https://<your-collector>/v1/ingest`.

## Backfill

```bash
pip install -e '.[backfill]'
export CLIENT_ID=...
export CLIENT_SECRET=...
fusion-siem backfill --tenant-id <uuid>
```

Uses [taegis-sdk-python](https://github.com/secureworks/taegis-sdk-python) against Fusion/Taegis GraphQL and posts the same `fusion-siem.v1` documents.

## Configuration

| Variable | Purpose |
| --- | --- |
| `FUSION_SIEM_INGEST_TOKEN` | Bearer token playbooks must send |
| `FUSION_SIEM_DATA_DIR` | Outbox and idempotency store (default `data`) |
| `FUSION_SIEM_FORWARD_URL` | Optional HTTP collector for the canonical envelope |
| `FUSION_SIEM_FORWARD_TOKEN` | Bearer token for `FORWARD_URL` |
| `FUSION_SIEM_HOST` / `FUSION_SIEM_PORT` | Bind address |

## Tests

```bash
pytest
```
