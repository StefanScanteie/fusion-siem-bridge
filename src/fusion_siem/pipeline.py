from __future__ import annotations

from typing import Any

from fusion_siem.adapters.https import HttpsAdapter
from fusion_siem.adapters.jsonl import JsonlAdapter
from fusion_siem.config import Settings
from fusion_siem.envelope import envelope_from_playbook
from fusion_siem.idempotency import SeenStore


class IngestPipeline:
    def __init__(self, settings: Settings) -> None:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = JsonlAdapter(settings.data_dir / "outbox.jsonl")
        self.seen = SeenStore(settings.data_dir / "seen.txt")
        self.https: HttpsAdapter | None = None
        if settings.forward_url:
            self.https = HttpsAdapter(settings.forward_url, settings.forward_token)

    def ingest(self, payload: dict[str, Any]) -> dict[str, Any]:
        envelope = envelope_from_playbook(payload)
        key = envelope.idempotency_key
        if self.seen.seen(key):
            return {"idempotency_key": key, "duplicate": True}
        self.jsonl.send(envelope)
        if self.https is not None:
            self.https.send(envelope)
        self.seen.add(key)
        return {"idempotency_key": key, "duplicate": False}
