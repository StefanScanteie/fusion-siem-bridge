import json
import socket
import threading

import httpx
import pytest

from fusion_siem.adapters.destination import build_destination, effective_destination
from fusion_siem.adapters.qradar import leef_line
from fusion_siem.config import Settings
from fusion_siem.envelope import CaseRecord, DetectionRecord, Envelope


def _envelope(**overrides) -> Envelope:
    values = {
        "datastream": "detection",
        "tenant_id": "t1",
        "source": "playbook",
        "ingested_at": "2026-10-01T12:00:00+00:00",
        "detection": DetectionRecord(id="det-1", title="Malware", severity=0.8),
        "events": [],
    }
    values.update(overrides)
    return Envelope(**values)


def test_effective_destination_none_when_unset():
    settings = Settings(ingest_token="x")
    assert effective_destination(settings) == "none"


def test_effective_destination_any_when_forward_url_and_unset():
    settings = Settings(ingest_token="x", forward_url="https://siem.example/collector")
    assert effective_destination(settings) == "any"


def test_effective_destination_explicit_wins():
    settings = Settings(
        ingest_token="x",
        destination="splunk",
        forward_url="https://siem.example/collector",
    )
    assert effective_destination(settings) == "splunk"


def test_build_destination_none_returns_none():
    assert build_destination(Settings(ingest_token="x")) is None


def test_splunk_hec_wraps_envelope_and_uses_splunk_auth():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = build_destination(
        Settings(
            ingest_token="x",
            destination="splunk",
            splunk_hec_url="https://hec.example/services/collector/event",
            splunk_hec_token="hec-token",
            splunk_index="fusion",
        ),
        client=client,
    )
    assert adapter is not None
    adapter.send(_envelope())

    assert captured["url"] == "https://hec.example/services/collector/event"
    assert captured["auth"] == "Splunk hec-token"
    assert captured["body"]["sourcetype"] == "fusion_siem:v1"
    assert captured["body"]["source"] == "fusion-siem-bridge"
    assert captured["body"]["index"] == "fusion"
    assert captured["body"]["event"]["detection"]["id"] == "det-1"
    assert "index" in captured["body"]


def test_splunk_omits_index_when_unset():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = build_destination(
        Settings(
            ingest_token="x",
            destination="splunk",
            splunk_hec_url="https://hec.example/event",
            splunk_hec_token="hec-token",
        ),
        client=client,
    )
    assert adapter is not None
    adapter.send(_envelope())
    assert "index" not in captured["body"]


def test_rapid7_posts_envelope_with_api_key():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["key"] = request.headers.get("x-api-key")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = build_destination(
        Settings(
            ingest_token="x",
            destination="rapid7",
            rapid7_url="https://data.logs.insight.rapid7.com/log/custom/abc",
            rapid7_token="r7-key",
        ),
        client=client,
    )
    assert adapter is not None
    adapter.send(_envelope())
    assert captured["url"].startswith("https://data.logs.insight.rapid7.com/")
    assert captured["key"] == "r7-key"
    assert captured["body"]["detection"]["id"] == "det-1"


def test_leef_line_uses_fusionsiem_header_and_raw_event():
    line = leef_line(_envelope())
    assert line.startswith("LEEF:2.0|FusionSIEM|Bridge|0.1.0|detection|")
    assert "\t" in line
    assert "ident=det-1" in line
    assert "msg=Malware" in line
    assert "sev=8" in line
    assert "tenant_id=t1" in line
    assert "datastream=detection" in line
    assert "rawEvent=" in line
    assert "Sophos" not in line


def test_leef_case_severity_high_is_8():
    envelope = _envelope(
        datastream="case",
        detection=None,
        case=CaseRecord(id="case-1", title="Intrusion", severity="High"),
    )
    line = leef_line(envelope)
    assert line.startswith("LEEF:2.0|FusionSIEM|Bridge|0.1.0|case|")
    assert "ident=case-1" in line
    assert "sev=8" in line


def test_qradar_sends_leef_over_tcp():
    received: list[bytes] = []
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept() -> None:
        conn, _addr = server.accept()
        received.append(conn.recv(65536))
        conn.close()

    thread = threading.Thread(target=accept)
    thread.start()
    adapter = build_destination(
        Settings(ingest_token="x", destination="qradar", qradar_host="127.0.0.1", qradar_port=port)
    )
    assert adapter is not None
    adapter.send(_envelope())
    thread.join(timeout=2)
    server.close()
    assert received
    assert received[0].startswith(b"LEEF:2.0|FusionSIEM|Bridge|")
    assert received[0].endswith(b"\n")


def test_qradar_connect_fail_raises():
    adapter = build_destination(
        Settings(ingest_token="x", destination="qradar", qradar_host="127.0.0.1", qradar_port=1)
    )
    assert adapter is not None
    with pytest.raises(OSError):
        adapter.send(_envelope())
