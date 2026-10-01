from __future__ import annotations

import httpx

from fusion_siem.envelope import Envelope


class Rapid7Adapter:
    def __init__(
        self,
        url: str,
        token: str,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = url
        self.token = token
        self._client = client or httpx.Client(timeout=30.0)

    def send(self, envelope: Envelope) -> None:
        response = self._client.post(
            self.url,
            content=envelope.model_dump_json(),
            headers={
                "Content-Type": "application/json",
                "X-Api-Key": self.token,
            },
        )
        response.raise_for_status()
