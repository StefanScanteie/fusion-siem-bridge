# Install the Fusion playbooks

Fusion Automations only POSTs HTTPS; this collector accepts that POST and
fans out to a SIEM. Import the YAML in this directory.

## 1. Run the middleware

The webhook URL must be reachable from Fusion.

```bash
export FUSION_SIEM_INGEST_TOKEN='replace-me'
fusion-siem serve
```

`Taegis.Webhook.post` does **not** send `Authorization`. Put the token in the
connection URL:

```
https://<collector-host>/v1/ingest?token=<FUSION_SIEM_INGEST_TOKEN>
```

Bearer tokens still work for `fusion-siem post-file` and SDK backfill.

Until `FUSION_SIEM_FORWARD_URL` is set, events are appended to
`data/outbox.jsonl` only.

## 2. Generic Webhook connection

In Fusion: **Automations → Connections**. Create **Generic Webhook** and set
the URL above. The connection Test button is inactive (Secureworks note in
the PDF).

Do not create `FusionSIEM.Webhook`. The template calls `Taegis.Webhook.post`.

## 3. Import detections

Import [`Custom_Webhook_v1.0.1.yaml`](Custom_Webhook_v1.0.1.yaml) when you need
Alert2 **plus related events**. Walkthrough:
[`Custom Webhook Playbook Template_v1.0.1.pdf`](Custom%20Webhook%20Playbook%20Template_v1.0.1.pdf).

Platform trigger:

| Field | Value |
| --- | --- |
| Trigger type | Platform |
| Source | Alert2 |
| Events | Create |
| Filter | `alertSeverity(inputs) >= .6` |

That POSTs `{ "alert": <Alert2>, "events": <Event.resolve outputs> }`. The
collector maps it to the canonical envelope.

[`detections-to-webhook.yaml`](detections-to-webhook.yaml) is the same workflow
without the template icon.

[`send-to-webhook.yaml`](send-to-webhook.yaml) posts detections and cases in one
playbook and does **not** call `Taegis.Event.resolve`. Its Alert2 filter is
`detectionSeverityNice(inputs) in ['High','Critical']` (same High/Critical cut).

## 4. Cases

Import [`send-to-webhook.yaml`](send-to-webhook.yaml) for detections and cases
with no event resolve (`Taegis.Webhook.post` with `inputs: inputs`).

Import [`cases-to-webhook.yaml`](cases-to-webhook.yaml) when the SIEM should
receive resolved event evidence. Trigger is `source: case`. CEL helpers include
`caseId`, `caseTitle`, `caseSeverity`, `casePriority`, `caseTenantId`,
`caseKeyFindings`, `caseEventEvidence`, and `createShareLink`. The POST body is
`{ "alert": { "type": "case", ... }, "events": ... }` so Event.resolve output
fits the `{alert, events}` slots.

Reuse the detections Generic Webhook connection. Case trigger:

| Field | Value |
| --- | --- |
| Trigger type | Platform |
| Source | case |
| Events | Create, Update, Delete, Events Added |
| Filter | `caseSeverity(inputs) in ['High', 'Critical']` |

## 5. Verify

Generate a High/Critical detection or case, or POST the native shapes:

```bash
fusion-siem post-file examples/taegis-webhook-alert.json --url 'http://127.0.0.1:8080/v1/ingest?token=replace-me'
fusion-siem post-file examples/taegis-webhook-case.json --url 'http://127.0.0.1:8080/v1/ingest?token=replace-me'
fusion-siem post-file examples/taegis-send-to-webhook-case.json --url 'http://127.0.0.1:8080/v1/ingest?token=replace-me'
```

Expect HTTP 202 and a new line in `data/outbox.jsonl`.

## 6. Backfill

```bash
pip install -e '.[backfill]'
fusion-siem backfill --tenant-id <tenant-uuid>
```
