from __future__ import annotations

from pathlib import Path

from fusion_siem.envelope import Envelope


class JsonlAdapter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, envelope: Envelope) -> None:
        line = envelope.model_dump_json()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
