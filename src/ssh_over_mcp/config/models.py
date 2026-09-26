from pydantic import BaseModel, ConfigDict

from ssh_over_mcp.inventory.models import Inventory
from ssh_over_mcp.policy.models import PolicyDocument


class ConfigBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    inventory: Inventory
    policy: PolicyDocument
