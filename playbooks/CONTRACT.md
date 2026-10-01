# Playbook payload contract (`fusion-siem.v1`)

Fusion playbooks POST JSON to `POST /v1/ingest`. Put the ingest token in the
Generic Webhook URL (`?token=`). Bearer still works for backfill and
`fusion-siem post-file`.

`Taegis.Webhook.post` is used two ways:

- `Custom_Webhook_v1.0.1.yaml` and `cases-to-webhook.yaml` map
  `{ "alert": <object>, "events": <resolved events> }`. Detections put Alert2
  in `alert`. Cases put a synthetic object with `"type": "case"` in that slot.
- `send-to-webhook.yaml` posts the raw trigger `inputs` (`inputs: inputs`).
  Alert2 triggers arrive as `alert2` or a top-level Alert2 object. Case
  triggers arrive as the case record (`type: SECURITY_CASE`, `keyFindings`,
  `primaryStatus`, `tenantId`, `event: Create`, …).

Backfill posts the canonical `fusion-siem.v1` document. All of these become
the same envelope.

```json
{
  "schema": "fusion-siem.v1",
  "datastream": "detection",
  "tenant_id": "48454",
  "source": "playbook",
  "detection": {
    "id": "alert://...",
    "title": "Suspicious PowerShell activity",
    "description": "Encoded PowerShell command",
    "severity": 0.8,
    "status": "OPEN",
    "sensor_types": ["ENDPOINT_TAEGIS"],
    "attack_technique_ids": ["T1059.001"],
    "url": "https://console.example/alerts/..."
  },
  "case": null,
  "events": [
    {
      "id": "event://...",
      "event_type": "PROCESS",
      "summary": "powershell.exe -enc ...",
      "event_time": "2026-09-04T22:10:44.929917Z",
      "values": {
        "hostname": "FINANCE-LAPTOP-07",
        "image_path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
        "commandline": "powershell.exe -enc ..."
      }
    }
  ]
}
```

For cases, set `datastream` to `"case"`, omit or null `detection`, and fill `case`.
Severity and priority are Fusion case strings (`High`, `Critical`), not the
Alert2 0.0–1.0 scale.

```json
{
  "id": "case://48454/abc-123",
  "title": "Suspected intrusion",
  "severity": "High",
  "priority": "Critical",
  "status": "OPEN",
  "case_type": "SECURITY_CASE",
  "url": "https://console.example/cases/abc-123",
  "key_findings": "Key findings from the case",
  "event": "Create"
}
```

Severity on detections is Fusion GraphQL `0.0`–`1.0`. Do not convert it to Central SIEM integer severity.
