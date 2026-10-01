from __future__ import annotations

from pathlib import Path


class SeenStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._keys = self._load()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()
        return {
            line.strip()
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    def seen(self, key: str) -> bool:
        return key in self._keys

    def add(self, key: str) -> None:
        if key in self._keys:
            return
        self._keys.add(key)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(key + "\n")
