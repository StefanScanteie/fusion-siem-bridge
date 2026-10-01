from __future__ import annotations

import httpx

from fusion_siem.envelope import Envelope


class HttpsAdapter:
    def __init__(
        self,
        url: str,
        token: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = url
        self.token = token
        self._client = client or httpx.Client(timeout=30.0)
        self._owns_client = client is None

    def send(self, envelope: Envelope) -> None:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = self._client.post(
            self.url,
            content=envelope.model_dump_json(),
            headers=headers,
        )
        response.raise_for_status()
