from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TenantContext:
    tenant_id: uuid.UUID
    user_id: uuid.UUID | None = None
    is_platform_admin: bool = False
    bypass_rls: bool = False
    trace_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        if self.tenant_id == uuid.UUID(int=0):
            raise ValueError("TenantContext: tenant_id cannot be a zero UUID")

    @property
    def tenant_id_str(self) -> str:
        return str(self.tenant_id)

    @property
    def trace_id_str(self) -> str:
        return str(self.trace_id)