from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx
import uvicorn

from fusion_siem.app import create_app
from fusion_siem.config import Settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fusion-siem",
        description="Fusion SIEM webhook middleware",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the ingest webhook")
    serve.set_defaults(func=_serve)

    replay = sub.add_parser(
        "post-file",
        help="POST a JSON payload file to a running ingest endpoint",
    )
    replay.add_argument("path")
    replay.add_argument(
        "--url",
        default=os.environ.get("FUSION_SIEM_INGEST_URL", "http://127.0.0.1:8080/v1/ingest"),
    )
    replay.add_argument(
        "--token",
        default=os.environ.get("FUSION_SIEM_INGEST_TOKEN"),
    )
    replay.set_defaults(func=_post_file)

    backfill = sub.add_parser(
        "backfill",
        help="Pull last-day detections from Fusion and POST them to ingest",
    )
    backfill.add_argument("--tenant-id", required=True)
    backfill.add_argument("--earliest", default="-1d")
    backfill.add_argument(
        "--url",
        default=os.environ.get("FUSION_SIEM_INGEST_URL", "http://127.0.0.1:8080/v1/ingest"),
    )
    backfill.add_argument(
        "--token",
        default=os.environ.get("FUSION_SIEM_INGEST_TOKEN"),
    )
    backfill.add_argument(
        "--console-url",
        default=os.environ.get("FUSION_SIEM_CONSOLE_URL", "https://ctpx.secureworks.com"),
    )
    backfill.set_defaults(func=_backfill)

    args = parser.parse_args(argv)
    return args.func(args)


def _serve(_args: argparse.Namespace) -> int:
    settings = Settings()
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
    )
    return 0


def _post_file(args: argparse.Namespace) -> int:
    if not args.token:
        print("FUSION_SIEM_INGEST_TOKEN is required", file=sys.stderr)
        return 2
    with open(args.path, encoding="utf-8") as handle:
        payload: dict[str, Any] = json.load(handle)
    response = httpx.post(
        args.url,
        json=payload,
        headers={"Authorization": f"Bearer {args.token}"},
        timeout=30.0,
    )
    print(response.status_code, response.text)
    response.raise_for_status()
    return 0


def _backfill(args: argparse.Namespace) -> int:
    if not args.token:
        print("FUSION_SIEM_INGEST_TOKEN is required", file=sys.stderr)
        return 2
    try:
        from taegis_sdk_python import GraphQLService
        from taegis_sdk_python.services.alerts.types import SearchRequestInput
    except ImportError:
        print(
            "Install backfill extras: pip install -e '.[backfill]'",
            file=sys.stderr,
        )
        return 2

    from fusion_siem.backfill import detection_to_payload

    service = GraphQLService(tenant_id=args.tenant_id)
    results = service.alerts.query.alerts_service_search(
        SearchRequestInput(
            cql_query=f"FROM detection EARLIEST={args.earliest}",
            limit=1000,
            offset=0,
        )
    )
    alerts = []
    if results.alerts is not None and results.alerts.list is not None:
        alerts = results.alerts.list

    posted = 0
    for alert in alerts:
        detection = alert.to_dict() if hasattr(alert, "to_dict") else _obj_to_dict(alert)
        event_ids = [
            item.get("id") if isinstance(item, dict) else getattr(item, "id", None)
            for item in (detection.get("event_ids") or [])
        ]
        events = _resolve_events(service, [eid for eid in event_ids if eid])
        payload = detection_to_payload(
            tenant_id=args.tenant_id,
            detection=detection,
            events=events,
            console_url=args.console_url,
        )
        response = httpx.post(
            args.url,
            json=payload,
            headers={"Authorization": f"Bearer {args.token}"},
            timeout=60.0,
        )
        response.raise_for_status()
        posted += 1
    print(f"posted {posted} detections")
    return 0


def _resolve_events(service: Any, event_ids: list[str]) -> list[dict[str, Any]]:
    if not event_ids:
        return []
    query = """
    query EventDetails($input: EventsInput!) {
      events(input: $input) {
        rn
        eventType
        summary
        eventTime
        values
      }
    }
    """
    result = service.core.execute(
        query_string=query,
        variables={"input": {"rns": event_ids}},
    )
    return result.get("events") or []


def _obj_to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return {
            key: _maybe_dict(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    return dict(value)


def _maybe_dict(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return value


if __name__ == "__main__":
    raise SystemExit(main())
