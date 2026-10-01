from fusion_siem.backfill import detection_to_payload


def test_sdk_detection_maps_to_playbook_contract():
    detection = {
        "id": "alert://abc",
        "status": "OPEN",
        "metadata": {
            "title": "Suspicious PowerShell activity",
            "description": "Encoded command",
            "severity": 0.8,
        },
        "sensor_types": ["ENDPOINT_TAEGIS"],
        "attack_technique_ids": ["T1059.001"],
        "event_ids": [{"id": "event://1"}, {"id": "event://2"}],
    }
    events = [
        {
            "rn": "event://1",
            "eventType": "PROCESS",
            "summary": "powershell.exe",
            "eventTime": "2026-09-04T22:10:44Z",
            "values": {"hostname": "host-1"},
        }
    ]

    payload = detection_to_payload(
        tenant_id="48454",
        detection=detection,
        events=events,
        console_url="https://ctpx.secureworks.com",
    )

    assert payload["schema"] == "fusion-siem.v1"
    assert payload["datastream"] == "detection"
    assert payload["source"] == "backfill"
    assert payload["detection"]["id"] == "alert://abc"
    assert payload["detection"]["title"] == "Suspicious PowerShell activity"
    assert payload["events"][0]["id"] == "event://1"
    assert payload["events"][0]["values"]["hostname"] == "host-1"
