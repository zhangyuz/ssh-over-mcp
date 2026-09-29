from __future__ import annotations

import base64
import re
import secrets
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

from .containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
    ContainmentUnavailableError,
)

MANAGER_PROTOCOL_MAGIC = b"SCMG\x00\x01"
MAX_MANAGER_MESSAGE_BYTES = 16 * 1024

_SAFE_ID = r"^[A-Za-z0-9._:-]{8,160}$"
_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class ContainmentManagerProtocolError(ValueError):
    """Invalid local containment-manager framing or message schema."""


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1] = 1
    message_id: str = Field(pattern=_SAFE_ID)


class ManagerLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    memory_max_bytes: int
    pids_max: int
    cpu_quota_us: int
    cpu_period_us: int

    @classmethod
    def from_limits(cls, limits: ContainmentLimits) -> ManagerLimits:
        return cls(
            memory_max_bytes=limits.memory_max_bytes,
            pids_max=limits.pids_max,
            cpu_quota_us=limits.cpu_quota_us,
            cpu_period_us=limits.cpu_period_us,
        )

    def to_limits(self) -> ContainmentLimits:
        return ContainmentLimits(
            memory_max_bytes=self.memory_max_bytes,
            pids_max=self.pids_max,
            cpu_quota_us=self.cpu_quota_us,
            cpu_period_us=self.cpu_period_us,
        )


class ManagerStats(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    memory_current_bytes: int | None = Field(default=None, ge=0)
    pids_current: int | None = Field(default=None, ge=0)
    cpu_usage_usec: int | None = Field(default=None, ge=0)
    populated: bool | None = None

    @classmethod
    def from_stats(cls, stats: ContainmentStats) -> ManagerStats:
        return cls(
            memory_current_bytes=stats.memory_current_bytes,
            pids_current=stats.pids_current,
            cpu_usage_usec=stats.cpu_usage_usec,
            populated=stats.populated,
        )

    def to_stats(self) -> ContainmentStats:
        return ContainmentStats(
            memory_current_bytes=self.memory_current_bytes,
            pids_current=self.pids_current,
            cpu_usage_usec=self.cpu_usage_usec,
            populated=self.populated,
        )


class CreateRequest(_Message):
    op: Literal["create"] = "create"
    request_id: str = Field(pattern=_SAFE_ID)
    limits: ManagerLimits


class _ScopeRequest(_Message):
    scope_id: str = Field(pattern=_SAFE_ID)
    capability: str

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        _decode_capability(value)
        return value


class AttachRequest(_ScopeRequest):
    op: Literal["attach"] = "attach"
    pid: int = Field(gt=0, strict=True)


class KillRequest(_ScopeRequest):
    op: Literal["kill"] = "kill"


class StatsRequest(_ScopeRequest):
    op: Literal["stats"] = "stats"


class CloseRequest(_ScopeRequest):
    op: Literal["close"] = "close"


ManagerRequest = Annotated[
    CreateRequest | AttachRequest | KillRequest | StatsRequest | CloseRequest,
    Field(discriminator="op"),
]


class CreateResponse(_Message):
    type: Literal["create_ok"] = "create_ok"
    scope_id: str = Field(pattern=_SAFE_ID)
    capability: str

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        _decode_capability(value)
        return value


class AckResponse(_Message):
    type: Literal["ack"] = "ack"


class StatsResponse(_Message):
    type: Literal["stats_ok"] = "stats_ok"
    stats: ManagerStats


class ErrorResponse(_Message):
    type: Literal["error"] = "error"
    code: Literal[
        "invalid_request",
        "not_authorized",
        "unavailable",
        "operation_failed",
        "internal",
    ]


ManagerResponse = Annotated[
    CreateResponse | AckResponse | StatsResponse | ErrorResponse,
    Field(discriminator="type"),
]

_REQUEST_ADAPTER = TypeAdapter(ManagerRequest)
_RESPONSE_ADAPTER = TypeAdapter(ManagerResponse)


def _decode_capability(value: str) -> bytes:
    if not isinstance(value, str) or not _CAPABILITY_RE.fullmatch(value):
        raise ValueError("invalid containment-manager capability")

    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise ValueError("invalid containment-manager capability") from exc

    if len(raw) != 32:
        raise ValueError("invalid containment-manager capability")
    return raw


def _new_capability() -> str:
    return secrets.token_urlsafe(32)


def _new_message_id() -> str:
    return f"msg_{secrets.token_hex(16)}"


def encode_manager_message(message: BaseModel) -> bytes:
    payload = message.model_dump_json(
        exclude_none=True,
        by_alias=True,
    ).encode("utf-8")
    if len(payload) > MAX_MANAGER_MESSAGE_BYTES:
        raise ContainmentManagerProtocolError(
            "containment-manager message exceeds maximum"
        )
    return (
        MANAGER_PROTOCOL_MAGIC
        + struct.pack(">I", len(payload))
        + payload
    )


def _decode_payload(frame: bytes) -> bytes:
    header_size = len(MANAGER_PROTOCOL_MAGIC) + 4
    if len(frame) < header_size:
        raise ContainmentManagerProtocolError(
            "truncated containment-manager frame"
        )
    if frame[: len(MANAGER_PROTOCOL_MAGIC)] != MANAGER_PROTOCOL_MAGIC:
        raise ContainmentManagerProtocolError(
            "invalid containment-manager magic"
        )

    (length,) = struct.unpack(
        ">I",
        frame[len(MANAGER_PROTOCOL_MAGIC) : header_size],
    )
    if length > MAX_MANAGER_MESSAGE_BYTES:
        raise ContainmentManagerProtocolError(
            "containment-manager message exceeds maximum"
        )
    if len(frame) != header_size + length:
        raise ContainmentManagerProtocolError(
            "invalid containment-manager frame length"
        )
    return frame[header_size:]


def decode_manager_request(frame: bytes) -> ManagerRequest:
    try:
        return _REQUEST_ADAPTER.validate_json(_decode_payload(frame))
    except ContainmentManagerProtocolError:
        raise
    except Exception as exc:
        raise ContainmentManagerProtocolError(
            "invalid containment-manager request"
        ) from exc


def decode_manager_response(frame: bytes) -> ManagerResponse:
    try:
        return _RESPONSE_ADAPTER.validate_json(_decode_payload(frame))
    except ContainmentManagerProtocolError:
        raise
    except Exception as exc:
        raise ContainmentManagerProtocolError(
            "invalid containment-manager response"
        ) from exc


class ContainmentManagerTransport(ABC):
    """One synchronous request/response channel to a local manager."""

    @abstractmethod
    def round_trip(self, frame: bytes) -> bytes:
        """Send one complete frame and return exactly one complete response."""

    @abstractmethod
    def close(self) -> None:
        """Release the manager transport."""


@dataclass(slots=True)
class _ManagedScope:
    capability: str
    handle: ContainmentHandle


class ContainmentManagerDispatcher:
    """Manager-side protocol dispatcher around a real containment backend."""

    def __init__(
        self,
        backend: ContainmentBackend,
        *,
        capability_factory=_new_capability,
    ) -> None:
        self._backend = backend
        self._capability_factory = capability_factory
        self._scopes: dict[str, _ManagedScope] = {}

    def _error(
        self,
        message_id: str,
        code: Literal[
            "invalid_request",
            "not_authorized",
            "unavailable",
            "operation_failed",
            "internal",
        ],
    ) -> bytes:
        return encode_manager_message(
            ErrorResponse(message_id=message_id, code=code)
        )

    def _lookup(
        self,
        scope_id: str,
        capability: str,
    ) -> ContainmentHandle:
        managed = self._scopes.get(scope_id)
        if managed is None:
            raise KeyError(scope_id)
        if not secrets.compare_digest(
            managed.capability,
            capability,
        ):
            raise PermissionError(scope_id)
        return managed.handle

    def handle_frame(self, frame: bytes) -> bytes:
        # Malformed frames do not contain a trustworthy message ID, so protocol
        # errors propagate before entering request-specific error normalization.
        request = decode_manager_request(frame)

        try:
            if isinstance(request, CreateRequest):
                containment_request = ContainmentRequest(
                    request_id=request.request_id,
                    limits=request.limits.to_limits(),
                )
                handle = self._backend.create(containment_request)
                registered = False
                try:
                    scope_id = handle.scope_id
                    if scope_id in self._scopes:
                        raise ContainmentError(
                            "duplicate manager scope identifier"
                        )

                    capability = self._capability_factory()
                    _decode_capability(capability)
                    if any(
                        secrets.compare_digest(
                            managed.capability,
                            capability,
                        )
                        for managed in self._scopes.values()
                    ):
                        raise ContainmentError(
                            "duplicate manager capability"
                        )

                    response = CreateResponse(
                        message_id=request.message_id,
                        scope_id=scope_id,
                        capability=capability,
                    )
                    encoded = encode_manager_message(response)
                    self._scopes[scope_id] = _ManagedScope(
                        capability=capability,
                        handle=handle,
                    )
                    registered = True
                    return encoded
                finally:
                    if not registered:
                        try:
                            handle.close()
                        except ContainmentError:
                            pass

            handle = self._lookup(
                request.scope_id,
                request.capability,
            )

            if isinstance(request, AttachRequest):
                handle.attach(request.pid)
                return encode_manager_message(
                    AckResponse(message_id=request.message_id)
                )

            if isinstance(request, KillRequest):
                handle.kill_all()
                return encode_manager_message(
                    AckResponse(message_id=request.message_id)
                )

            if isinstance(request, StatsRequest):
                return encode_manager_message(
                    StatsResponse(
                        message_id=request.message_id,
                        stats=ManagerStats.from_stats(handle.stats()),
                    )
                )

            if isinstance(request, CloseRequest):
                handle.close()
                del self._scopes[request.scope_id]
                return encode_manager_message(
                    AckResponse(message_id=request.message_id)
                )

            return self._error(request.message_id, "invalid_request")
        except KeyError:
            return self._error(request.message_id, "not_authorized")
        except PermissionError:
            return self._error(request.message_id, "not_authorized")
        except ContainmentUnavailableError:
            return self._error(request.message_id, "unavailable")
        except (ContainmentError, ValueError):
            return self._error(request.message_id, "operation_failed")
        except Exception:  # noqa: BLE001
            # Trust boundary: never expose unexpected backend implementation details.
            return self._error(request.message_id, "internal")


class InMemoryContainmentManagerTransport(ContainmentManagerTransport):
    """Test transport which crosses the same framing boundary in-process."""

    def __init__(self, dispatcher: ContainmentManagerDispatcher) -> None:
        self._dispatcher = dispatcher

    def round_trip(self, frame: bytes) -> bytes:
        return self._dispatcher.handle_frame(frame)

    def close(self) -> None:
        return


class ContainmentManagerClient(ContainmentBackend):
    """Host-agent ContainmentBackend adapter for the manager protocol."""

    def __init__(self, transport: ContainmentManagerTransport) -> None:
        self._transport = transport
        self._closed = False

    @property
    def name(self) -> str:
        return "containment-manager"

    def _call(
        self,
        request: ManagerRequest,
    ) -> ManagerResponse:
        if self._closed:
            raise ContainmentUnavailableError(
                "containment manager client is closed"
            )

        try:
            response = decode_manager_response(
                self._transport.round_trip(
                    encode_manager_message(request)
                )
            )
        except ContainmentUnavailableError:
            raise
        except ContainmentManagerProtocolError as exc:
            raise ContainmentUnavailableError(
                "containment manager returned an invalid response"
            ) from exc
        if response.message_id != request.message_id:
            raise ContainmentError(
                "containment-manager response correlation failed"
            )
        if isinstance(response, ErrorResponse):
            if response.code == "unavailable":
                raise ContainmentUnavailableError(
                    "containment manager unavailable"
                )
            if response.code == "not_authorized":
                raise ContainmentError(
                    "containment manager capability rejected"
                )
            raise ContainmentError(
                "containment manager operation failed"
            )
        return response

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        message = CreateRequest(
            message_id=_new_message_id(),
            request_id=request.request_id,
            limits=ManagerLimits.from_limits(request.limits),
        )
        response = self._call(message)
        if not isinstance(response, CreateResponse):
            raise ContainmentError(
                "unexpected containment-manager create response"
            )
        return ManagedContainmentHandle(
            client=self,
            scope_id=response.scope_id,
            capability=response.capability,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._transport.close()


class ManagedContainmentHandle(ContainmentHandle):
    def __init__(
        self,
        *,
        client: ContainmentManagerClient,
        scope_id: str,
        capability: str,
    ) -> None:
        self._client = client
        self._scope_id = scope_id
        self._capability = capability
        self._closed = False

    @property
    def scope_id(self) -> str:
        return self._scope_id

    def _require_open(self) -> None:
        if self._closed:
            raise ContainmentError(
                "containment-manager scope is closed"
            )

    def _base(self) -> dict[str, str]:
        self._require_open()
        return {
            "message_id": _new_message_id(),
            "scope_id": self._scope_id,
            "capability": self._capability,
        }

    def attach(self, pid: int) -> None:
        response = self._client._call(
            AttachRequest(
                **self._base(),
                pid=pid,
            )
        )
        if not isinstance(response, AckResponse):
            raise ContainmentError(
                "unexpected containment-manager attach response"
            )

    def kill_all(self) -> None:
        response = self._client._call(
            KillRequest(**self._base())
        )
        if not isinstance(response, AckResponse):
            raise ContainmentError(
                "unexpected containment-manager kill response"
            )

    def stats(self) -> ContainmentStats:
        response = self._client._call(
            StatsRequest(**self._base())
        )
        if not isinstance(response, StatsResponse):
            raise ContainmentError(
                "unexpected containment-manager stats response"
            )
        return response.stats.to_stats()

    def close(self) -> None:
        if self._closed:
            return
        response = self._client._call(
            CloseRequest(**self._base())
        )
        if not isinstance(response, AckResponse):
            raise ContainmentError(
                "unexpected containment-manager close response"
            )
        self._closed = True
        # Drop the capability as soon as the scope has been destroyed.
        self._capability = ""
