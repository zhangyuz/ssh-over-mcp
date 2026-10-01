from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import PrincipalContext


def new_request_id() -> str:
    return f"req_{uuid.uuid4().hex}"


class OperationContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=r"^req_[0-9a-f]{32}$")
    principal: PrincipalContext
    received_at: datetime
    approval_id: str | None = Field(
        default=None,
        pattern=r"^apr_[0-9a-f]{32}$",
    )

    @field_validator("received_at")
    @classmethod
    def validate_received_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("received_at must be timezone-aware UTC")
        return value
