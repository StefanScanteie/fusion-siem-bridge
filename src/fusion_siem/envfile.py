from __future__ import annotations

from pathlib import Path

MANAGED_KEYS = (
    "FUSION_SIEM_INGEST_TOKEN",
    "FUSION_SIEM_DATA_DIR",
    "FUSION_SIEM_HOST",
    "FUSION_SIEM_PORT",
    "FUSION_SIEM_FORWARD_URL",
    "FUSION_SIEM_FORWARD_TOKEN",
    "FUSION_SIEM_PUBLIC_HOST",
)


def upsert_env(path: Path, values: dict[str, str]) -> None:
    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()

    seen: set[str] = set()
    updated: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            updated.append(line)
            continue
        key = stripped.split("=", 1)[0]
        if key in values:
            updated.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            updated.append(line)

    for key in MANAGED_KEYS:
        if key in values and key not in seen:
            updated.append(f"{key}={values[key]}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(updated) + "\n", encoding="utf-8")
