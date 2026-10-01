from __future__ import annotations

from typing import Any

import httpx

from fusion_siem.adapters.destination import build_destination, effective_destination
from fusion_siem.adapters.errors import DestinationNotConfigured, DestinationSendError
from fusion_siem.adapters.jsonl import JsonlAdapter
from fusion_siem.config import Settings
from fusion_siem.envelope import envelope_from_playbook
from fusion_siem.idempotency import SeenStore


class IngestPipeline:
    def __init__(
        self,
        settings: Settings,
        http_client: httpx.Client | None = None,
    ) -> None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = JsonlAdapter(settings.data_dir / "outbox.jsonl")
        self.seen = SeenStore(settings.data_dir / "seen.txt")
        self.config_error: DestinationNotConfigured | None = None
        self.adapter = None
        dest = effective_destination(settings)
        if dest == "none":
            return
        try:
            self.adapter = build_destination(settings, client=http_client)
        except DestinationNotConfigured as exc:
            self.config_error = exc

    def ingest(self, payload: dict[str, Any]) -> dict[str, Any]:
        envelope = envelope_from_playbook(payload)
        key = envelope.idempotency_key
        if self.seen.seen(key):
            return {"idempotency_key": key, "duplicate": True}
        if self.config_error is not None:
            raise self.config_error
        self.jsonl.send(envelope)
        if self.adapter is not None:
            try:
                self.adapter.send(envelope)
            except (httpx.HTTPError, OSError) as exc:
                raise DestinationSendError("destination send failed") from exc
        self.seen.add(key)
        return {"idempotency_key": key, "duplicate": False}
