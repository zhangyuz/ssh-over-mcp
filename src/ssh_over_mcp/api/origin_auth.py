from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path
from typing import Self

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .errors import RuntimeConfigurationError

_MAX_ORIGIN_BEARER_BYTES = 4096


def _invalid_runtime_configuration() -> RuntimeConfigurationError:
    return RuntimeConfigurationError("runtime configuration is invalid")


def load_origin_bearer_token(path: Path) -> bytes:
    token_path = Path(path)
    try:
        before = token_path.lstat()
    except OSError:
        raise _invalid_runtime_configuration() from None

    if not stat.S_ISREG(before.st_mode):
        raise _invalid_runtime_configuration() from None

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(token_path, flags)
    except OSError:
        raise _invalid_runtime_configuration() from None

    try:
        after = os.fstat(fd)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
        ):
            raise _invalid_runtime_configuration() from None
        token = os.read(fd, _MAX_ORIGIN_BEARER_BYTES + 1)
    except OSError:
        raise _invalid_runtime_configuration() from None
    finally:
        os.close(fd)

    if not 1 <= len(token) <= _MAX_ORIGIN_BEARER_BYTES:
        raise _invalid_runtime_configuration() from None
    if any(byte < 0x21 or byte > 0x7E for byte in token):
        raise _invalid_runtime_configuration() from None
    return token


class _RedactedBearerToken(bytes):
    def __new__(cls, value: bytes) -> Self:
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return "<origin bearer redacted>"

    def __str__(self) -> str:
        return "<origin bearer redacted>"


def redact_origin_bearer_token(token: bytes) -> bytes:
    return _RedactedBearerToken(token)


class OriginBearerAuthMiddleware:
    def __init__(self, app: ASGIApp, token: bytes) -> None:
        self._app = app
        self._token = token

    @staticmethod
    def _protects_path(path: str) -> bool:
        return path == "/mcp" or path.startswith("/mcp/")

    def _authorized(self, headers: list[tuple[bytes, bytes]]) -> bool:
        values = [
            value
            for name, value in headers
            if name.lower() == b"authorization"
        ]
        if len(values) != 1:
            return False
        value = values[0]
        scheme, separator, supplied = value.partition(b" ")
        if separator != b" " or scheme.lower() != b"bearer" or not supplied:
            return False
        return hmac.compare_digest(supplied, self._token)

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http" or not self._protects_path(scope.get("path", "")):
            await self._app(scope, receive, send)
            return

        headers = list(scope.get("headers", []))
        if not self._authorized(headers):
            response = JSONResponse(
                {"error": "origin authentication failed"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self._app(scope, receive, send)
