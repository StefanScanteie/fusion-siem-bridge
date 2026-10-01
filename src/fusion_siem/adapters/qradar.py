from __future__ import annotations

import json
import socket

from fusion_siem.envelope import Envelope

PRODUCT_VERSION = "0.1.0"

_CASE_SEV = {
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10,
}


def _escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("|", "\\|")
    )


def _severity(envelope: Envelope) -> int:
    if envelope.datastream == "detection" and envelope.detection is not None:
        raw = envelope.detection.severity
        if raw is None:
            return 5
        return max(1, min(10, round(raw * 10)))
    if envelope.datastream == "case" and envelope.case is not None:
        label = (envelope.case.severity or "").strip().lower()
        return _CASE_SEV.get(label, 5)
    return 5


def _ident_title(envelope: Envelope) -> tuple[str, str]:
    if envelope.datastream == "detection" and envelope.detection is not None:
        return envelope.detection.id, envelope.detection.title or ""
    if envelope.datastream == "case" and envelope.case is not None:
        return envelope.case.id, envelope.case.title or ""
    return "", ""


def leef_line(envelope: Envelope) -> str:
    ident, title = _ident_title(envelope)
    attrs = {
        "devTime": envelope.ingested_at,
        "ident": ident,
        "msg": title,
        "sev": str(_severity(envelope)),
        "tenant_id": envelope.tenant_id,
        "datastream": envelope.datastream,
        "rawEvent": json.dumps(envelope.model_dump(mode="json"), separators=(",", ":")),
    }
    extension = "\t".join(f"{key}={_escape(value)}" for key, value in attrs.items())
    return (
        f"LEEF:2.0|FusionSIEM|Bridge|{PRODUCT_VERSION}|{envelope.datastream}|{extension}"
    )


class QRadarAdapter:
    def __init__(self, host: str, port: int = 514, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def send(self, envelope: Envelope) -> None:
        payload = (leef_line(envelope) + "\n").encode("utf-8")
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(payload)
