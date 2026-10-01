from __future__ import annotations

import hmac


def verify_bearer_token(authorization: str | None, expected: str) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise PermissionError("missing bearer token")
    provided = authorization.removeprefix("Bearer ")
    if not hmac.compare_digest(provided, expected):
        raise PermissionError("invalid bearer token")
