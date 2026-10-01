from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from ssh_over_mcp.api.context import OperationContext, new_request_id
from ssh_over_mcp.api.models import PrincipalContext


def _principal() -> PrincipalContext:
    return PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )


def test_new_request_id_is_server_generated_and_unique() -> None:
    values = {new_request_id() for _ in range(32)}

    assert len(values) == 32
    assert all(re.fullmatch(r"req_[0-9a-f]{32}", value) for value in values)


def test_operation_context_accepts_strict_utc_and_optional_approval_id() -> None:
    context = OperationContext(
        request_id="req_" + ("a" * 32),
        principal=_principal(),
        received_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        approval_id="apr_" + ("b" * 32),
    )

    assert context.request_id == "req_" + ("a" * 32)
    assert context.principal == _principal()
    assert context.received_at.tzinfo is UTC
    assert context.approval_id == "apr_" + ("b" * 32)


@pytest.mark.parametrize(
    "received_at",
    [
        datetime.fromisoformat("2026-10-01T12:00:00"),
        datetime(
            2026,
            10,
            1,
            12,
            0,
            tzinfo=timezone(timedelta(hours=1)),
        ),
    ],
)
def test_operation_context_rejects_non_utc_timestamp(
    received_at: datetime,
) -> None:
    with pytest.raises(ValidationError):
        OperationContext(
            request_id="req_" + ("a" * 32),
            principal=_principal(),
            received_at=received_at,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_id", "req_short"),
        ("request_id", "req_" + ("A" * 32)),
        ("approval_id", "apr_short"),
        ("approval_id", "apr_" + ("B" * 32)),
    ],
)
def test_operation_context_rejects_malformed_ids(
    field: str,
    value: str,
) -> None:
    kwargs = {
        "request_id": "req_" + ("a" * 32),
        "principal": _principal(),
        "received_at": datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        "approval_id": None,
    }
    kwargs[field] = value

    with pytest.raises(ValidationError):
        OperationContext.model_validate(kwargs)


def test_operation_context_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        OperationContext(
            request_id="req_" + ("a" * 32),
            principal=_principal(),
            received_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
            unexpected="value",
        )
