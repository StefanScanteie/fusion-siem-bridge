from fastapi.testclient import TestClient

from fusion_siem.app import create_app
from fusion_siem.config import Settings


def _app(tmp_path, env_file=None, **overrides):
    settings = Settings(
        ingest_token="test-token",
        data_dir=tmp_path,
        host="0.0.0.0",
        port=8080,
        **overrides,
    )
    return create_app(settings, env_file=env_file or (tmp_path / ".env"))


def _loopback(tmp_path, **overrides):
    return TestClient(_app(tmp_path, **overrides), client=("127.0.0.1", 50000))


def _remote(tmp_path, **overrides):
    return TestClient(_app(tmp_path, **overrides), client=("203.0.113.10", 50000))


def test_ui_home_ok_from_loopback(tmp_path):
    response = _loopback(tmp_path).get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Fusion (XDR) SIEM Bridge" in response.text
    assert "Middleware" in response.text
    assert "Collector" not in response.text
    assert "<img" not in response.text.lower()
    assert ">Dark</button>" in response.text
    assert "High contrast" not in response.text
    assert "not officially supported by Sophos" in response.text


def test_ui_css_uses_brand_palette(tmp_path):
    css = _loopback(tmp_path).get("/ui/static/app.css").text
    assert "#2006f7" in css
    assert "#001a47" in css
    assert "#00f2b3" in css
    assert "#edf2f9" in css
    assert "Zalando Sans" in css


def test_ui_home_forbidden_from_remote(tmp_path):
    assert _remote(tmp_path).get("/").status_code == 403


def test_health_and_ingest_remain_public(tmp_path):
    client = _remote(tmp_path)
    assert client.get("/health").status_code == 200
    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "detection",
        "tenant_id": "t1",
        "detection": {"id": "det-public"},
        "events": [],
    }
    response = client.post("/v1/ingest?token=test-token", json=payload)
    assert response.status_code == 202


def test_ui_status_forbidden_from_remote(tmp_path):
    assert _remote(tmp_path).get("/ui/status").status_code == 403


def test_ui_status_empty_outbox(tmp_path):
    body = _loopback(tmp_path).get("/ui/status").json()
    assert body["ingest_live"] is True
    assert body["outbox_lines"] == 0
    assert body["last_ingest_at"] is None
    assert body["webhook_url"] == "http://127.0.0.1:8080/v1/ingest?token=test-token"


def test_ui_status_uses_public_host(tmp_path):
    client = _loopback(tmp_path, public_host="collector.example")
    body = client.get("/ui/status").json()
    assert body["webhook_url"].startswith("http://collector.example:8080/v1/ingest?token=")


def test_ui_status_counts_outbox_after_ingest(tmp_path):
    client = _loopback(tmp_path)
    client.post(
        "/v1/ingest?token=test-token",
        json={
            "schema": "fusion-siem.v1",
            "datastream": "detection",
            "tenant_id": "t1",
            "detection": {"id": "det-1"},
            "events": [],
        },
    )
    body = client.get("/ui/status").json()
    assert body["outbox_lines"] == 1
    assert body["last_ingest_at"]


def test_ui_settings_masks_token(tmp_path):
    body = _loopback(tmp_path).get("/ui/settings").json()
    assert "test-token" not in str(body)
    assert body["ingest_token"].endswith("oken")
    assert "•" in body["ingest_token"] or "*" in body["ingest_token"]
    assert body["destination"] == "none"


def test_ui_settings_destination_defaults_to_any_when_forward_url(tmp_path):
    body = _loopback(tmp_path, forward_url="https://siem.example/collector").get("/ui/settings").json()
    assert body["destination"] == "any"


def test_ui_home_has_destination_select(tmp_path):
    html = _loopback(tmp_path).get("/").text
    assert 'id="destination"' in html
    assert ">Splunk</option>" in html
    assert ">QRadar</option>" in html
    assert ">Rapid7</option>" in html
    assert ">Any</option>" in html


def test_ui_settings_put_writes_splunk_destination(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "FUSION_SIEM_INGEST_TOKEN=test-token\n"
        "FUSION_SIEM_QRADAR_HOST=qradar.example\n",
        encoding="utf-8",
    )
    client = TestClient(
        _app(tmp_path, env_file=env_file, destination="qradar", qradar_host="qradar.example"),
        client=("127.0.0.1", 50000),
    )
    put = client.put(
        "/ui/settings",
        json={
            "ingest_token": "",
            "data_dir": str(tmp_path),
            "host": "0.0.0.0",
            "port": 8080,
            "destination": "splunk",
            "splunk_hec_url": "https://hec.example/event",
            "splunk_hec_token": "hec-secret",
            "splunk_index": "fusion",
            "splunk_sourcetype": "fusion_siem:v1",
            "qradar_host": "qradar.example",
            "qradar_port": 514,
        },
    )
    assert put.status_code == 200
    text = env_file.read_text(encoding="utf-8")
    assert "FUSION_SIEM_DESTINATION=splunk" in text
    assert "FUSION_SIEM_SPLUNK_HEC_URL=https://hec.example/event" in text
    assert "FUSION_SIEM_SPLUNK_HEC_TOKEN=hec-secret" in text
    assert "FUSION_SIEM_QRADAR_HOST=qradar.example" in text


def test_ui_settings_put_writes_env_without_hot_reload(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "FUSION_SIEM_INGEST_TOKEN=test-token\nCLIENT_ID=keep-me\n",
        encoding="utf-8",
    )
    client = TestClient(
        _app(tmp_path, env_file=env_file),
        client=("127.0.0.1", 50000),
    )
    put = client.put(
        "/ui/settings",
        json={
            "ingest_token": "brand-new-token",
            "data_dir": str(tmp_path),
            "forward_url": "https://siem.example/collector",
            "forward_token": "fwd",
            "host": "0.0.0.0",
            "port": 8080,
            "public_host": "bridge.example",
        },
    )
    assert put.status_code == 200
    text = env_file.read_text(encoding="utf-8")
    assert "brand-new-token" in text
    assert "CLIENT_ID=keep-me" in text
    assert "FUSION_SIEM_PUBLIC_HOST=bridge.example" in text

    old_token = client.post(
        "/v1/ingest?token=test-token",
        json={
            "schema": "fusion-siem.v1",
            "datastream": "detection",
            "tenant_id": "t1",
            "detection": {"id": "still-old"},
            "events": [],
        },
    )
    new_token = client.post(
        "/v1/ingest?token=brand-new-token",
        json={
            "schema": "fusion-siem.v1",
            "datastream": "detection",
            "tenant_id": "t1",
            "detection": {"id": "should-fail"},
            "events": [],
        },
    )
    assert old_token.status_code == 202
    assert new_token.status_code == 401


def test_ui_settings_put_blank_token_keeps_existing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("FUSION_SIEM_INGEST_TOKEN=test-token\n", encoding="utf-8")
    client = TestClient(
        _app(tmp_path, env_file=env_file),
        client=("127.0.0.1", 50000),
    )
    response = client.put(
        "/ui/settings",
        json={
            "ingest_token": "",
            "data_dir": str(tmp_path / "out"),
            "host": "127.0.0.1",
            "port": 9090,
        },
    )
    assert response.status_code == 200
    text = env_file.read_text(encoding="utf-8")
    assert "FUSION_SIEM_INGEST_TOKEN=test-token" in text
    assert "FUSION_SIEM_PORT=9090" in text
