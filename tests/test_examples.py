import json
from pathlib import Path

from fastapi.testclient import TestClient

from fusion_siem.app import create_app
from fusion_siem.config import Settings

ROOT = Path(__file__).resolve().parents[1]


def test_example_detection_and_case_ingest(tmp_path):
    client = TestClient(
        create_app(Settings(ingest_token="test-token", data_dir=tmp_path))
    )
    headers = {"Authorization": "Bearer test-token"}

    detection = json.loads((ROOT / "examples/detection.json").read_text(encoding="utf-8"))
    case = json.loads((ROOT / "examples/case.json").read_text(encoding="utf-8"))
    native = json.loads(
        (ROOT / "examples/taegis-webhook-alert.json").read_text(encoding="utf-8")
    )
    native_case = json.loads(
        (ROOT / "examples/taegis-webhook-case.json").read_text(encoding="utf-8")
    )
    send_case = json.loads(
        (ROOT / "examples/taegis-send-to-webhook-case.json").read_text(encoding="utf-8")
    )

    det = client.post("/v1/ingest", headers=headers, json=detection)
    cse = client.post("/v1/ingest", headers=headers, json=case)
    taegis = client.post("/v1/ingest?token=test-token", json=native)
    taegis_case = client.post("/v1/ingest?token=test-token", json=native_case)
    send_to_webhook_case = client.post("/v1/ingest?token=test-token", json=send_case)

    assert det.status_code == 202
    assert cse.status_code == 202
    assert taegis.status_code == 202
    assert taegis_case.status_code == 202
    assert send_to_webhook_case.status_code == 202
    lines = (tmp_path / "outbox.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 5
