from fusion_siem.envelope import envelope_from_playbook


def test_case_sync_helpers_payload_via_webhook_alert_slot():
    payload = {
        "alert": {
            "type": "case",
            "resource_id": "case://48454/abc-123",
            "tenant_id": "48454",
            "status": "OPEN",
            "metadata": {
                "title": "Suspected intrusion",
                "description": "Key findings from the case",
            },
            "case_severity": "High",
            "case_priority": "Critical",
            "case_type": "SECURITY_CASE",
            "url": "https://ctpx.secureworks.com/cases/abc-123",
            "playbook_event": "Create",
        },
        "events": [
            {"id": "event://1", "commandline": "powershell.exe"},
        ],
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "case"
    assert envelope.detection is None
    assert envelope.case.id == "case://48454/abc-123"
    assert envelope.case.title == "Suspected intrusion"
    assert envelope.case.severity == "High"
    assert envelope.case.priority == "Critical"
    assert envelope.case.case_type == "SECURITY_CASE"
    assert envelope.case.key_findings == "Key findings from the case"
    assert envelope.case.event == "Create"
    assert envelope.events[0].values["commandline"] == "powershell.exe"
    assert envelope.idempotency_key == "48454:case:case://48454/abc-123"
