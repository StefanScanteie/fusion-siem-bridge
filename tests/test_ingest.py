from fastapi.testclient import TestClient

from fusion_siem.app import create_app
from fusion_siem.config import Settings


def _client(tmp_path, **overrides):
    settings = Settings(
        ingest_token="test-token",
        data_dir=tmp_path,
        **overrides,
    )
    return TestClient(create_app(settings))


def test_ingest_rejects_missing_token(tmp_path):
    client = _client(tmp_path)
    response = client.post("/v1/ingest", json={"schema": "fusion-siem.v1"})
    assert response.status_code == 401


def test_ingest_accepts_token_query_param_for_generic_webhook(tmp_path):
    client = _client(tmp_path)
    payload = {
        "alert": {
            "resource_id": "alert://t1/det-2",
            "tenant_id": "t1",
            "metadata": {"title": "Malware", "severity": 0.9},
        },
        "events": [],
    }
    response = client.post("/v1/ingest?token=test-token", json=payload)
    assert response.status_code == 202
    assert response.json()["idempotency_key"] == "t1:detection:alert://t1/det-2"


def test_ingest_accepts_detection_and_writes_jsonl(tmp_path):
    client = _client(tmp_path)
    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "detection",
        "tenant_id": "t1",
        "source": "playbook",
        "detection": {
            "id": "det-1",
            "title": "Malware",
            "severity": 0.9,
            "status": "OPEN",
        },
        "events": [],
    }

    response = client.post(
        "/v1/ingest",
        headers={"Authorization": "Bearer test-token"},
        json=payload,
    )

    assert response.status_code == 202
    assert response.json()["idempotency_key"] == "t1:detection:det-1"
    outbox = tmp_path / "outbox.jsonl"
    assert outbox.exists()
    line = outbox.read_text(encoding="utf-8").strip()
    assert '"det-1"' in line
    assert '"schema_version"' in line


def test_duplicate_detection_is_idempotent(tmp_path):
    client = _client(tmp_path)
    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "detection",
        "tenant_id": "t1",
        "source": "playbook",
        "detection": {"id": "det-1", "title": "Malware"},
        "events": [],
    }
    headers = {"Authorization": "Bearer test-token"}

    first = client.post("/v1/ingest", headers=headers, json=payload)
    second = client.post("/v1/ingest", headers=headers, json=payload)

    assert first.status_code == 202
    assert second.status_code == 202
    assert second.json()["duplicate"] is True
    lines = (tmp_path / "outbox.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
