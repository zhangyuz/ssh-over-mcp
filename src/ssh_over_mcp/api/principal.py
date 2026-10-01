from __future__ import annotations

from typing import Protocol

from ssh_over_mcp.policy.models import PolicyDocument

from .errors import PrincipalConfigurationError
from .models import PrincipalContext


class PrincipalProvider(Protocol):
    def get_principal(self) -> PrincipalContext: ...


class StaticPrincipalProvider:
    def __init__(self, *, profile: str, policy: PolicyDocument) -> None:
        if profile not in policy.roles:
            raise PrincipalConfigurationError(
                "configured principal profile is invalid"
            )
        self._principal = PrincipalContext(profile=profile)

    def get_principal(self) -> PrincipalContext:
        return self._principal
