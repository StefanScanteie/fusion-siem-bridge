# Install the Fusion playbooks

These templates export detections (with related events) and cases to the
fusion-siem-bridge middleware. Fusion Automations only speaks HTTPS; the
middleware is what fans out to Splunk, Sentinel, syslog, or another SIEM.

## 1. Run the middleware

The playbook URL must be reachable from Fusion (public HTTPS or an allow-listed
collector). Set a long random ingest token.

```bash
export FUSION_SIEM_INGEST_TOKEN='replace-me'
fusion-siem serve
```

Optional: forward the canonical envelope to another HTTP collector (your SIEM
webhook, Cribl, a function app, Splunk HEC proxy):

```bash
export FUSION_SIEM_FORWARD_URL='https://siem.example/collector'
export FUSION_SIEM_FORWARD_TOKEN='siem-token'
```

Until `FORWARD_URL` is set, events are appended to `data/outbox.jsonl` only
(dry-run).

## 2. Create a Custom Connector

In Fusion: **Automations → Connections → Connector Library → Create**.

| Field | Value |
| --- | --- |
| Connector name | `FusionSIEM.Webhook` |
| Function name | `post` |
| Method | `POST` |
| URL | playbook input `webhook_url` |
| Header `Content-Type` | `application/json` |
| Header `Authorization` | `Bearer ${webhook_token}` |
| Body | raw JSON from playbook input `body` |

Publish the connector so playbook templates can call `FusionSIEM.Webhook.post`.

If your tenant already has **Generic Webhook**, you can point that at
`https://<collector>/v1/ingest` and put the token in a header, but you still
need the playbook to send the `fusion-siem.v1` body from CONTRACT.md — not
the raw `alert2` trigger blob.

## 3. Import the playbook templates

Import:

- [`detections-to-webhook.yaml`](detections-to-webhook.yaml)
- [`cases-to-webhook.yaml`](cases-to-webhook.yaml)

Create a playbook instance per tenant. Inputs:

| Input | Example |
| --- | --- |
| Webhook URL | `https://collector.example/v1/ingest` |
| Webhook token | same value as `FUSION_SIEM_INGEST_TOKEN` |
| Minimum severity | `0.6` (detections only; Fusion scale 0–1) |

Enable the **platform** trigger (`alert2` create, or investigation/case create).

## 4. Verify

Trigger a test detection or POST [`examples/detection.json`](../examples/detection.json):

```bash
fusion-siem post-file examples/detection.json
```

Confirm a 202 and a new line in `data/outbox.jsonl`.

## 5. Backfill

```bash
pip install -e '.[backfill]'
fusion-siem backfill --tenant-id <tenant-uuid>
```

Uses `taegis-sdk-python` (`CLIENT_ID` / `CLIENT_SECRET`) and posts the same
contract the playbooks use.
