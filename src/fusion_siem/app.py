from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from fusion_siem.adapters.errors import DestinationNotConfigured, DestinationSendError
from fusion_siem.auth import verify_ingest_token
from fusion_siem.config import Settings
from fusion_siem.pipeline import IngestPipeline
from fusion_siem.ui import build_ui_router


def create_app(
    settings: Settings | None = None,
    env_file: Path | None = None,
    http_client: httpx.Client | None = None,
) -> FastAPI:
    settings = settings or Settings()
    pipeline = IngestPipeline(settings, http_client=http_client)
    app = FastAPI(title="Fusion (XDR) SIEM Bridge", version="0.1.0")
    app.include_router(build_ui_router(settings, env_file or Path(".env")))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/ingest")
    async def ingest(
        request: Request,
        authorization: str | None = Header(default=None),
        token: str | None = Query(default=None),
    ) -> JSONResponse:
        try:
            verify_ingest_token(
                authorization,
                settings.ingest_token,
                query_token=token,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        payload: dict[str, Any] = await request.json()
        try:
            result = pipeline.ingest(payload)
        except DestinationNotConfigured as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except DestinationSendError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return JSONResponse(status_code=202, content=result)

    return app
