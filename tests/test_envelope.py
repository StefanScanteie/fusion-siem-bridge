from fusion_siem.envelope import envelope_from_playbook


def test_detection_playbook_payload_becomes_envelope():
    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "detection",
        "tenant_id": "48454",
        "source": "playbook",
        "detection": {
            "id": "alert://priv:org:tenant:detector:1",
            "title": "Suspicious PowerShell activity",
            "description": "Encoded PowerShell command",
            "severity": 0.8,
            "status": "OPEN",
            "sensor_types": ["ENDPOINT_TAEGIS"],
            "attack_technique_ids": ["T1059.001"],
            "url": "https://ctpx.secureworks.com/alerts/alert://priv:org:tenant:detector:1",
        },
        "events": [
            {
                "id": "event://tenant/process/abc",
                "event_type": "PROCESS",
                "summary": "powershell.exe -enc ...",
                "event_time": "2026-09-04T22:10:44.929917Z",
                "values": {
                    "hostname": "FINANCE-LAPTOP-07",
                    "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandline": "powershell.exe -enc ...",
                },
            }
        ],
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.schema_version == "fusion-siem.v1"
    assert envelope.datastream == "detection"
    assert envelope.tenant_id == "48454"
    assert envelope.detection.id == "alert://priv:org:tenant:detector:1"
    assert envelope.detection.severity == 0.8
    assert envelope.case is None
    assert envelope.events[0].values["hostname"] == "FINANCE-LAPTOP-07"
    assert envelope.idempotency_key == (
        "48454:detection:alert://priv:org:tenant:detector:1"
    )


def test_case_playbook_payload_becomes_envelope():
    payload = {
        "schema": "fusion-siem.v1",
        "datastream": "case",
        "tenant_id": "48454",
        "source": "playbook",
        "case": {
            "id": "investigation://tenant/cases/99",
            "title": "Suspected intrusion",
            "severity": "HIGH",
            "status": "OPEN",
            "url": "https://ctpx.secureworks.com/investigations/99",
        },
        "events": [],
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "case"
    assert envelope.case.id == "investigation://tenant/cases/99"
    assert envelope.detection is None
    assert envelope.idempotency_key == "48454:case:investigation://tenant/cases/99"
