from __future__ import annotations

import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TenantContext:
    """
    Immutable value object representing the resolved tenant identity
    for a single request.

    Created once by TenantRLSMiddleware after JWT verification.
    Attached to request.state.tenant_context so route handlers can read it.
    frozen=True enforces immutability at runtime — no accidental mutation
    mid-request.

    Fields
    ------
    tenant_id : UUID
        The tenant this request is scoped to. Always set. Never zero UUID.

    user_id : UUID | None
        The Keycloak `sub` claim — the human user. None if JWT had no sub.

    is_platform_admin : bool
        True if the JWT contained the platform_admin realm role AND the
        tenant:investigate permission. Application-layer flag only.

    bypass_rls : bool
        True for platform admin sessions. APPLICATION-LAYER FLAG ONLY.
        Used by route handlers to decide PII masking / elevated access.
        Never propagated to the database session.
        The DB enforces the same RLS policies for all sessions including admins —
        admins are scoped to the targeted tenant UUID, not to a global bypass.

    trace_id : UUID
        Per-request correlation ID. Ties this context to denial log entries,
        audit events, and application logs.
    """

    tenant_id: uuid.UUID
    user_id: uuid.UUID | None = None
    is_platform_admin: bool = False
    bypass_rls: bool = False
    trace_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        # Zero UUID is never a valid tenant — reject immediately
        if self.tenant_id == uuid.UUID(int=0):
            raise ValueError("TenantContext: tenant_id cannot be a zero UUID")

    @property
    def tenant_id_str(self) -> str:
        return str(self.tenant_id)

    @property
    def trace_id_str(self) -> str:
        return str(self.trace_id)
