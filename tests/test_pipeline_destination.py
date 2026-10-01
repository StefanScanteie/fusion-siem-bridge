import json

import httpx
from fastapi.testclient import TestClient

from fusion_siem.app import create_app
from fusion_siem.config import Settings


DETECTION = {
    "schema": "fusion-siem.v1",
    "datastream": "detection",
    "tenant_id": "t1",
    "detection": {"id": "det-fwd", "title": "Malware", "severity": 0.9},
    "events": [],
}


def _client(tmp_path, http_client=None, **overrides):
    settings = Settings(ingest_token="test-token", data_dir=tmp_path, **overrides)
    return TestClient(create_app(settings, http_client=http_client))


def test_ingest_none_writes_jsonl_and_does_not_need_http(tmp_path):
    client = _client(tmp_path, destination="none")
    response = client.post("/v1/ingest?token=test-token", json=DETECTION)
    assert response.status_code == 202
    assert response.json()["duplicate"] is False
    assert (tmp_path / "outbox.jsonl").exists()
    seen = (tmp_path / "seen.txt").read_text(encoding="utf-8")
    assert "det-fwd" in seen


def test_unset_destination_with_forward_url_uses_any(tmp_path):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = request.content
        return httpx.Response(200)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = _client(
        tmp_path,
        http_client=http_client,
        forward_url="https://siem.example/collector",
        forward_token="fwd",
    )
    response = client.post("/v1/ingest?token=test-token", json=DETECTION)
    assert response.status_code == 202
    assert captured["auth"] == "Bearer fwd"
    assert b"det-fwd" in captured["body"]


def test_splunk_reject_returns_502_writes_jsonl_not_seen(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = _client(
        tmp_path,
        http_client=http_client,
        destination="splunk",
        splunk_hec_url="https://hec.example/event",
        splunk_hec_token="hec-token",
    )
    response = client.post("/v1/ingest?token=test-token", json=DETECTION)
    assert response.status_code == 502
    assert (tmp_path / "outbox.jsonl").exists()
    seen_path = tmp_path / "seen.txt"
    if seen_path.exists():
        assert "det-fwd" not in seen_path.read_text(encoding="utf-8")


def test_splunk_missing_url_returns_503_without_jsonl(tmp_path):
    client = _client(tmp_path, destination="splunk", splunk_hec_token="hec-token")
    response = client.post("/v1/ingest?token=test-token", json=DETECTION)
    assert response.status_code == 503
    assert not (tmp_path / "outbox.jsonl").exists()


def test_duplicate_skips_forward(tmp_path):
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = _client(
        tmp_path,
        http_client=http_client,
        destination="rapid7",
        rapid7_url="https://data.logs.insight.rapid7.com/log/custom/abc",
        rapid7_token="r7",
    )
    first = client.post("/v1/ingest?token=test-token", json=DETECTION)
    second = client.post("/v1/ingest?token=test-token", json=DETECTION)
    assert first.status_code == 202
    assert second.status_code == 202
    assert second.json()["duplicate"] is True
    assert calls["n"] == 1
    lines = (tmp_path / "outbox.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["detection"]["id"] == "det-fwd"
