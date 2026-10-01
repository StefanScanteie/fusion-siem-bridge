from fusion_siem.envelope import envelope_from_playbook


def test_official_custom_webhook_alert_and_event_payload():
    payload = {
        "alert": {
            "resource_id": "alert://priv:event-filter:48454:1675951037688:6b389753",
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
        "events": {
            "resource_id": "event://priv:scwx.process:48454:1675951030000:2c0735a1",
            "commandline": "powershell.exe get-httpstatus",
            "hostname": "WSAMZN-VU5R5RS6",
            "image_path": "\\Device\\HarddiskVolume1\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "sensor_type": "ENDPOINT_TAEGIS",
        },
    }

    envelope = envelope_from_playbook(payload)

    assert envelope.datastream == "detection"
    assert envelope.tenant_id == "48454"
    assert envelope.detection.id.endswith("6b389753")
    assert envelope.detection.title == "PowerSploit Recon Script"
    assert envelope.detection.severity == 0.99
    assert envelope.events[0].values["hostname"] == "WSAMZN-VU5R5RS6"
    assert envelope.events[0].values["commandline"] == "powershell.exe get-httpstatus"
    assert envelope.idempotency_key.startswith("48454:detection:alert://")


def test_official_webhook_events_list_from_playbook_loop():
    payload = {
        "alert": {
            "id": "alert://abc",
            "tenant_id": "48454",
            "metadata": {"title": "Test", "severity": 0.7},
        },
        "events": [
            {"id": "event://1", "commandline": "cmd.exe"},
            {"rn": "event://2", "summary": "second"},
        ],
    }

    envelope = envelope_from_playbook(payload)
    assert [event.id for event in envelope.events] == ["event://1", "event://2"]
