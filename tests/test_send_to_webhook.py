from fusion_siem.envelope import envelope_from_playbook


def test_send_to_webhook_posts_raw_alert2_inputs():
    payload = {
        "event": "create",
        "alert2": {
            "resource_id": "alert://priv:event-filter:48454:1:send-wh",
            "tenant_id": "48454",
            "type": "alert2",
            "status": "OPEN",
            "sensor_types": ["ENDPOINT_TAEGIS"],
            "attack_technique_ids": ["T1059.001"],
            "metadata": {
                "title": "PowerSploit Recon Script",
                "description": "PowerSploit recon",
                "severity": 0.99,
            },
        },
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "detection"
    assert envelope.detection.id.endswith("send-wh")
    assert envelope.detection.title == "PowerSploit Recon Script"
    assert envelope.events == []


def test_send_to_webhook_posts_top_level_alert2_object():
    payload = {
        "event": "create",
        "resource_id": "alert://48454/top-level-alert2",
        "tenant_id": "48454",
        "type": "alert2",
        "status": "OPEN",
        "metadata": {"title": "Top-level Alert2", "severity": 0.8},
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "detection"
    assert envelope.detection.id == "alert://48454/top-level-alert2"
    assert envelope.detection.title == "Top-level Alert2"


def test_send_to_webhook_posts_raw_case_inputs():
    payload = {
        "event": "Create",
        "id": "abc-123",
        "tenantId": "48454",
        "title": "Suspected intrusion",
        "severity": "High",
        "priority": "Critical",
        "type": "SECURITY_CASE",
        "primaryStatus": {"id": "OPEN"},
        "keyFindings": "Key findings from the case",
        "url": "https://ctpx.secureworks.com/cases/abc-123",
        "eventEvidence": [
            {"id": "event://1", "commandline": "powershell.exe"},
        ],
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "case"
    assert envelope.detection is None
    assert envelope.case.id == "abc-123"
    assert envelope.case.title == "Suspected intrusion"
    assert envelope.case.severity == "High"
    assert envelope.case.priority == "Critical"
    assert envelope.case.status == "OPEN"
    assert envelope.case.case_type == "SECURITY_CASE"
    assert envelope.case.key_findings == "Key findings from the case"
    assert envelope.case.event == "Create"
    assert envelope.events[0].values["commandline"] == "powershell.exe"
    assert envelope.idempotency_key == "48454:case:abc-123"


def test_send_to_webhook_nested_case_object():
    payload = {
        "event": "Update",
        "case": {
            "id": "case://48454/nested",
            "tenant_id": "48454",
            "title": "Nested case",
            "severity": "High",
            "priority": "High",
            "status": "OPEN",
            "type": "SECURITY_CASE",
            "keyFindings": "Updated findings",
        },
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "case"
    assert envelope.case.id == "case://48454/nested"
    assert envelope.case.event == "Update"
    assert envelope.case.key_findings == "Updated findings"
