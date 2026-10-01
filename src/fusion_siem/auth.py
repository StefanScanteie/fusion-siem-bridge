from __future__ import annotations

import hmac


def verify_ingest_token(
    authorization: str | None,
    expected: str,
    query_token: str | None = None,
) -> None:
    provided: str | None = None
    if authorization and authorization.startswith("Bearer "):
        provided = authorization.removeprefix("Bearer ")
    elif query_token:
        provided = query_token
    if provided is None:
        raise PermissionError("missing token")
    if not hmac.compare_digest(provided, expected):
        raise PermissionError("invalid token")
