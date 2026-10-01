from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from fusion_siem.auth import verify_bearer_token
from fusion_siem.config import Settings
from fusion_siem.pipeline import IngestPipeline


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    pipeline = IngestPipeline(settings)
    app = FastAPI(title="fusion-siem-bridge", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/ingest")
    async def ingest(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        try:
            verify_bearer_token(authorization, settings.ingest_token)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        payload: dict[str, Any] = await request.json()
        try:
            result = pipeline.ingest(payload)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return JSONResponse(status_code=202, content=result)

    return app
