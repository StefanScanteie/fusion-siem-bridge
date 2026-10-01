from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from fusion_siem.config import Settings
from fusion_siem.envfile import upsert_env

WEB_DIR = Path(__file__).resolve().parent / "web"


def is_loopback(request: Request) -> bool:
    client = request.client
    if client is None:
        return False
    host = client.host
    return host in {"127.0.0.1", "::1"}


def require_loopback(request: Request) -> None:
    if not is_loopback(request):
        raise HTTPException(status_code=403, detail="UI is localhost-only")


def mask_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "••••"
    return "••••" + value[-4:]


def webhook_host(settings: Settings) -> str:
    public = (settings.public_host or "").strip()
    if public:
        return public
    if settings.host in {"0.0.0.0", "::", ""}:
        return "127.0.0.1"
    return settings.host


def webhook_url(settings: Settings) -> str:
    return (
        f"http://{webhook_host(settings)}:{settings.port}"
        f"/v1/ingest?token={settings.ingest_token}"
    )


def outbox_stats(data_dir: Path) -> tuple[int, str | None]:
    path = data_dir / "outbox.jsonl"
    if not path.exists():
        return 0, None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    last_at = None
    if lines:
        try:
            payload = json.loads(lines[-1])
            last_at = payload.get("ingested_at")
        except json.JSONDecodeError:
            last_at = None
    return len(lines), last_at if isinstance(last_at, str) else None


class SettingsUpdate(BaseModel):
    ingest_token: str = ""
    data_dir: str
    forward_url: str = ""
    forward_token: str = ""
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)
    public_host: str = ""


def build_ui_router(settings: Settings, env_file: Path) -> APIRouter:
    router = APIRouter()

    @router.get("/")
    def home(request: Request) -> FileResponse:
        require_loopback(request)
        return FileResponse(WEB_DIR / "index.html")

    @router.get("/ui/static/{name}")
    def static_file(name: str, request: Request) -> FileResponse:
        require_loopback(request)
        allowed = {"app.css": "text/css", "app.js": "text/javascript"}
        if name not in allowed:
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(WEB_DIR / name, media_type=allowed[name])

    @router.get("/ui/status")
    def status(request: Request) -> dict[str, Any]:
        require_loopback(request)
        lines, last_at = outbox_stats(settings.data_dir)
        return {
            "ingest_live": True,
            "outbox_lines": lines,
            "last_ingest_at": last_at,
            "webhook_url": webhook_url(settings),
        }

    @router.get("/ui/settings")
    def get_settings(request: Request) -> dict[str, Any]:
        require_loopback(request)
        return {
            "ingest_token": mask_secret(settings.ingest_token),
            "data_dir": str(settings.data_dir),
            "forward_url": settings.forward_url or "",
            "forward_token": mask_secret(settings.forward_token),
            "host": settings.host,
            "port": settings.port,
            "public_host": settings.public_host or "",
        }

    @router.put("/ui/settings")
    def put_settings(request: Request, body: SettingsUpdate) -> JSONResponse:
        require_loopback(request)
        token = body.ingest_token.strip() or settings.ingest_token
        if not token:
            raise HTTPException(status_code=422, detail="ingest token is required")
        values = {
            "FUSION_SIEM_INGEST_TOKEN": token,
            "FUSION_SIEM_DATA_DIR": body.data_dir,
            "FUSION_SIEM_HOST": body.host,
            "FUSION_SIEM_PORT": str(body.port),
            "FUSION_SIEM_FORWARD_URL": body.forward_url.strip(),
            "FUSION_SIEM_FORWARD_TOKEN": (
                body.forward_token.strip() or (settings.forward_token or "")
            ),
            "FUSION_SIEM_PUBLIC_HOST": body.public_host.strip(),
        }
        try:
            upsert_env(env_file, values)
        except OSError as exc:
            raise HTTPException(status_code=500, detail="could not write .env") from exc
        return JSONResponse(
            {"ok": True, "restart_required": True},
        )

    return router
