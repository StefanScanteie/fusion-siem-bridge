from __future__ import annotations

import json

import httpx

from fusion_siem.envelope import Envelope


class SplunkAdapter:
    def __init__(
        self,
        url: str,
        token: str,
        index: str | None = None,
        sourcetype: str = "fusion_siem:v1",
        client: httpx.Client | None = None,
    ) -> None:
        self.url = url
        self.token = token
        self.index = index
        self.sourcetype = sourcetype
        self._client = client or httpx.Client(timeout=30.0)

    def send(self, envelope: Envelope) -> None:
        body: dict[str, object] = {
            "event": json.loads(envelope.model_dump_json()),
            "sourcetype": self.sourcetype,
            "source": "fusion-siem-bridge",
        }
        if self.index:
            body["index"] = self.index
        response = self._client.post(
            self.url,
            json=body,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
