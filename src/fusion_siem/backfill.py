from __future__ import annotations

from typing import Any

from fusion_siem.envelope import envelope_from_playbook


def detection_to_payload(
    tenant_id: str,
    detection: dict[str, Any],
    events: list[dict[str, Any]],
    console_url: str | None = None,
) -> dict[str, Any]:
    metadata = detection.get("metadata") or {}
    detection_id = str(detection["id"])
    url = None
    if console_url:
        url = f"{console_url.rstrip('/')}/alerts/{detection_id}"

    mapped_events = []
    for item in events:
        mapped_events.append(
            {
                "id": item.get("id") or item.get("rn"),
                "event_type": item.get("event_type") or item.get("eventType"),
                "summary": item.get("summary"),
                "event_time": item.get("event_time") or item.get("eventTime"),
                "values": item.get("values") or {},
            }
        )

    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "detection",
        "tenant_id": tenant_id,
        "source": "backfill",
        "detection": {
            "id": detection_id,
            "title": metadata.get("title"),
            "description": metadata.get("description"),
            "severity": metadata.get("severity"),
            "status": detection.get("status"),
            "sensor_types": detection.get("sensor_types") or [],
            "attack_technique_ids": detection.get("attack_technique_ids") or [],
            "url": url,
        },
        "events": mapped_events,
    }
    envelope_from_playbook(payload)
    return payload


def case_to_payload(
    tenant_id: str,
    case: dict[str, Any],
    events: list[dict[str, Any]] | None = None,
    console_url: str | None = None,
) -> dict[str, Any]:
    case_id = str(case["id"])
    url = None
    if console_url:
        url = f"{console_url.rstrip('/')}/investigations/{case_id}"
    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "case",
        "tenant_id": tenant_id,
        "source": "backfill",
        "case": {
            "id": case_id,
            "title": case.get("title"),
            "severity": case.get("severity") or case.get("primaryStatus"),
            "status": case.get("status") or case.get("primaryStatus"),
            "url": url,
        },
        "events": events or [],
    }
    envelope_from_playbook(payload)
    return payload
