"""
zerotheft-rls
=============
Tenant RLS context propagation and enforcement for zerotheft platform services.

Public API — import only from here, never from internal modules directly.
This lets internals be refactored without breaking consuming services.

Typical usage in a consuming service
-------------------------------------
    from app import (
        TenantRLSMiddleware,
        KeycloakTokenVerifier,
        DenialLogger,
        AuditLogger,
        register_rls_listener,
        TenantContext,
    )

    # At startup:
    register_rls_listener(engine)
    app.add_middleware(
        TenantRLSMiddleware,
        token_verifier=KeycloakTokenVerifier(),
        denial_logger=DenialLogger(session_factory=SessionLocal),
        audit_logger=AuditLogger(session_factory=SessionLocal),
    )

    # In a route handler (if you need the context):
    ctx: TenantContext = request.state.tenant_context
    if ctx.bypass_rls:
        # admin session — unmask PII if needed
        ...
"""

from .interfaces.middleware import TenantRLSMiddleware
from .interfaces.exceptions import (
    TenantContextError,
    MissingToken,
    InvalidToken,
    ExpiredToken,
)
from .infrastructure.keycloak_verifier import KeycloakTokenVerifier
from .infrastructure.denial_logger import DenialLogger
from .infrastructure.audit_logger import AuditLogger
from .infrastructure.rls_listener import register_rls_listener
from .domain.tenant_context import TenantContext
from .application.context import (
    set_tenant_context,
    clear_tenant_context,
    get_tenant_id,
    get_bypass_rls,
    get_trace_id,
)

__all__ = [
    "TenantRLSMiddleware",
    "TenantContextError",
    "MissingToken",
    "InvalidToken",
    "ExpiredToken",
    "KeycloakTokenVerifier",
    "DenialLogger",
    "AuditLogger",
    "register_rls_listener",
    "TenantContext",
    "set_tenant_context",
    "clear_tenant_context",
    "get_tenant_id",
    "get_bypass_rls",
    "get_trace_id",
]
