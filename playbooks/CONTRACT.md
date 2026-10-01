# Playbook payload contract (`fusion-siem.v1`)

Fusion playbooks POST this JSON to `POST /v1/ingest` with
`Authorization: Bearer <FUSION_SIEM_INGEST_TOKEN>`.

The SDK backfill CLI emits the same document (`source: "backfill"`).

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

For cases, set `datastream` to `"case"`, omit or null `detection`, and fill `case`:

```json
{
  "id": "investigation://...",
  "title": "Suspected intrusion",
  "severity": "HIGH",
  "status": "OPEN",
  "url": "https://console.example/investigations/..."
}
```

Severity on detections is Fusion GraphQL `0.0`–`1.0`. Do not convert it to Central SIEM integer severity.
