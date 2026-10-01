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
    status: str | None = None
    url: str | None = None


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


def envelope_from_playbook(payload: dict[str, Any]) -> Envelope:
    datastream = payload.get("datastream")
    if datastream not in {"detection", "case"}:
        raise ValueError("datastream must be 'detection' or 'case'")

    events = [
        EventRecord(
            id=str(item["id"]),
            event_type=item.get("event_type") or item.get("eventType"),
            summary=item.get("summary"),
            event_time=item.get("event_time") or item.get("eventTime"),
            values=item.get("values") or {},
        )
        for item in payload.get("events") or []
    ]

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
