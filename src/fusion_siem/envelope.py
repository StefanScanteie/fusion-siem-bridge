from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, assert_never

from pydantic import BaseModel, Field


class EventRecord(BaseModel):
    id: str
    event_type: str | None = None
    summary: str | None = None
    event_time: str | None = None
    values: dict[str, Any] = Field(default_factory=dict)


class DetectionRecord(BaseModel):
    id: str
    title: str | None = None
    description: str | None = None
    severity: float | None = None
    status: str | None = None
    sensor_types: list[str] = Field(default_factory=list)
    attack_technique_ids: list[str] = Field(default_factory=list)
    url: str | None = None


class CaseRecord(BaseModel):
    id: str
    title: str | None = None
    severity: str | None = None
    priority: str | None = None
    status: str | None = None
    case_type: str | None = None
    url: str | None = None
    key_findings: str | None = None
    event: str | None = None


class Envelope(BaseModel):
    schema_version: str = "fusion-siem.v1"
    datastream: Literal["detection", "case"]
    tenant_id: str
    source: str = "playbook"
    ingested_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    detection: DetectionRecord | None = None
    case: CaseRecord | None = None
    events: list[EventRecord] = Field(default_factory=list)

    @property
    def idempotency_key(self) -> str:
        if self.datastream == "detection":
            if self.detection is None:
                raise ValueError("detection datastream requires detection")
            object_id = self.detection.id
        elif self.datastream == "case":
            if self.case is None:
                raise ValueError("case datastream requires case")
            object_id = self.case.id
        else:
            assert_never(self.datastream)
        return f"{self.tenant_id}:{self.datastream}:{object_id}"


_CASE_TRIGGER_EVENTS = {
    "Create",
    "Update",
    "Delete",
    "Detections Added",
    "Detections Removed",
    "Events Added",
    "Events Removed",
    "Assets Added",
    "Assets Removed",
    "Comment Added",
    "Comment Updated",
    "Comment Deleted",
    "File Added",
    "File Deleted",
    "Searches Added",
    "Searches Removed",
    "Link Added",
    "Link Updated",
    "Link Deleted",
}


def envelope_from_playbook(payload: dict[str, Any]) -> Envelope:
    if payload.get("alert") or payload.get("alert2"):
        return _from_taegis_webhook(payload)
    kind = str(payload.get("type") or "").lower()
    if kind in {"alert2", "alert"}:
        return _from_taegis_webhook({"alert": payload, "events": payload.get("events")})
    if payload.get("datastream") in {"detection", "case"}:
        return _from_canonical(payload)
    if _looks_like_case_trigger(payload):
        return _from_send_to_webhook_case(payload)
    return _from_canonical(payload)


def _from_canonical(payload: dict[str, Any]) -> Envelope:
    datastream = payload.get("datastream")
    if datastream not in {"detection", "case"}:
        raise ValueError("datastream must be 'detection' or 'case'")

    events = [_event_record(item) for item in _coerce_events(payload.get("events"))]

    detection = None
    if payload.get("detection"):
        detection = DetectionRecord.model_validate(payload["detection"])

    case = None
    if payload.get("case"):
        case = CaseRecord.model_validate(payload["case"])

    envelope = Envelope(
        schema_version=str(payload.get("schema") or "fusion-siem.v1"),
        datastream=datastream,
        tenant_id=str(payload["tenant_id"]),
        source=str(payload.get("source") or "playbook"),
        detection=detection,
        case=case,
        events=events,
    )
    _ = envelope.idempotency_key
    return envelope


def _from_taegis_webhook(payload: dict[str, Any]) -> Envelope:
    alert = payload.get("alert") or payload.get("alert2") or {}
    if not isinstance(alert, dict):
        raise ValueError("alert must be an object")
    if str(alert.get("type") or "").lower() == "case":
        return _from_taegis_case_webhook(alert, payload.get("events"))
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    detection_id = alert.get("resource_id") or alert.get("id")
    if not detection_id:
        raise ValueError("alert is missing resource_id/id")
    tenant_id = str(alert.get("tenant_id") or payload.get("tenant_id") or "")
    if not tenant_id:
        raise ValueError("alert is missing tenant_id")

    detection = DetectionRecord(
        id=str(detection_id),
        title=metadata.get("title") or alert.get("title"),
        description=metadata.get("description") or alert.get("description"),
        severity=_as_float(metadata.get("severity", alert.get("severity"))),
        status=alert.get("status"),
        sensor_types=list(alert.get("sensor_types") or []),
        attack_technique_ids=list(alert.get("attack_technique_ids") or []),
    )
    envelope = Envelope(
        datastream="detection",
        tenant_id=tenant_id,
        source="playbook",
        detection=detection,
        events=[_event_record(item) for item in _coerce_events(payload.get("events"))],
    )
    _ = envelope.idempotency_key
    return envelope


def _looks_like_case_trigger(payload: dict[str, Any]) -> bool:
    nested = payload.get("case")
    if isinstance(nested, dict) and (nested.get("id") or nested.get("resource_id")):
        return True
    kind = str(payload.get("type") or "").upper()
    if kind in {"CASE", "SECURITY_CASE"}:
        return True
    if payload.get("keyFindings") is not None or payload.get("key_findings") is not None:
        return True
    if payload.get("primaryStatus") is not None:
        return True
    event = payload.get("event")
    has_id = bool(payload.get("id") or payload.get("resource_id"))
    return isinstance(event, str) and event in _CASE_TRIGGER_EVENTS and has_id


def _status_value(raw: dict[str, Any]) -> Any:
    status = raw.get("status") or raw.get("primaryStatus")
    if isinstance(status, dict):
        return status.get("id") or status.get("name")
    return status


def _from_send_to_webhook_case(payload: dict[str, Any]) -> Envelope:
    nested = payload.get("case")
    raw = nested if isinstance(nested, dict) else payload
    description = (
        raw.get("keyFindings")
        or raw.get("key_findings")
        or raw.get("description")
        or payload.get("keyFindings")
        or payload.get("key_findings")
    )
    alert = {
        "type": "case",
        "resource_id": raw.get("resource_id") or raw.get("id") or payload.get("id"),
        "tenant_id": (
            raw.get("tenant_id")
            or raw.get("tenantId")
            or payload.get("tenant_id")
            or payload.get("tenantId")
        ),
        "status": _status_value(raw) or _status_value(payload),
        "metadata": {
            "title": raw.get("title") or payload.get("title"),
            "description": description,
        },
        "case_severity": raw.get("severity") or raw.get("case_severity") or payload.get("severity"),
        "case_priority": raw.get("priority") or raw.get("case_priority") or payload.get("priority"),
        "case_type": raw.get("type") or raw.get("case_type") or payload.get("type"),
        "url": raw.get("url") or payload.get("url"),
        "playbook_event": payload.get("event") or raw.get("event"),
    }
    events = (
        payload.get("events")
        or payload.get("eventEvidence")
        or raw.get("events")
        or raw.get("eventEvidence")
        or []
    )
    return _from_taegis_case_webhook(alert, events)


def _from_taegis_case_webhook(alert: dict[str, Any], events_raw: Any) -> Envelope:
    metadata = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}
    case_id = alert.get("resource_id") or alert.get("id")
    if not case_id:
        raise ValueError("case is missing resource_id/id")
    tenant_id = str(alert.get("tenant_id") or "")
    if not tenant_id:
        raise ValueError("case is missing tenant_id")
    description = metadata.get("description") or alert.get("description")
    envelope = Envelope(
        datastream="case",
        tenant_id=tenant_id,
        source="playbook",
        case=CaseRecord(
            id=str(case_id),
            title=metadata.get("title") or alert.get("title"),
            severity=alert.get("case_severity") or alert.get("severity"),
            priority=alert.get("case_priority") or alert.get("priority"),
            status=alert.get("status"),
            case_type=alert.get("case_type"),
            url=alert.get("url"),
            key_findings=description if isinstance(description, str) else None,
            event=alert.get("playbook_event") or alert.get("event"),
        ),
        events=[_event_record(item) for item in _coerce_events(events_raw)],
    )
    _ = envelope.idempotency_key
    return envelope


def _coerce_events(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        events: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, dict):
                events.append(item)
            elif isinstance(item, str) and item:
                events.append({"id": item})
        return events
    if isinstance(raw, dict):
        nested = raw.get("outputs") or raw.get("results") or raw.get("list")
        if nested and not any(
            key in raw for key in ("resource_id", "id", "rn", "commandline")
        ):
            return _coerce_events(nested)
        return [raw]
    return []


def _event_record(item: dict[str, Any]) -> EventRecord:
    event_id = item.get("id") or item.get("resource_id") or item.get("rn") or "unknown"
    nested = item.get("values")
    if isinstance(nested, dict) and nested:
        values = nested
    else:
        values = dict(item)
    return EventRecord(
        id=str(event_id),
        event_type=item.get("event_type") or item.get("eventType") or item.get("sensor_type"),
        summary=(
            item.get("summary")
            or item.get("enrichSummary")
            or item.get("commandline")
        ),
        event_time=item.get("event_time") or item.get("eventTime"),
        values=values,
    )


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    return float(value)
