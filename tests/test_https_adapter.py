import httpx

from fusion_siem.adapters.https import HttpsAdapter
from fusion_siem.envelope import Envelope, DetectionRecord


def test_https_adapter_posts_canonical_envelope():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = request.content
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    adapter = HttpsAdapter(
        url="https://siem.example/collector",
        token="siem-token",
        client=client,
    )
    envelope = Envelope(
        datastream="detection",
        tenant_id="t1",
        source="playbook",
        detection=DetectionRecord(id="det-1", title="Malware"),
        events=[],
    )

    adapter.send(envelope)

    assert captured["url"] == "https://siem.example/collector"
    assert captured["auth"] == "Bearer siem-token"
    assert b'"det-1"' in captured["body"]
    assert b"fusion-siem.v1" in captured["body"]
