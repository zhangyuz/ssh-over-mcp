from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    address: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = Field(min_length=1)
    credential_ref: str = Field(min_length=1)
    host_key: str = Field(min_length=1)
    labels: frozenset[str] = Field(default_factory=frozenset)
    allowed_roles: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("address", "ssh_user", "credential_ref", "host_key")
    @classmethod
    def no_surrounding_whitespace(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("value may not have surrounding whitespace")
        return value


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hosts: dict[str, Host]

    @field_validator("hosts")
    @classmethod
    def validate_aliases(cls, hosts: dict[str, Host]) -> dict[str, Host]:
        if not hosts:
            raise ValueError("inventory must contain at least one host")

        for alias in hosts:
            if not _ALIAS_RE.fullmatch(alias):
                raise ValueError(
                    "host aliases may contain only letters, digits, '.', "
                    "'_', and '-'"
                )

        return hosts
