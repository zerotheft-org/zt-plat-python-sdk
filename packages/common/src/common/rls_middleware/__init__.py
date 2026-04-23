"""
Shared tenant RLS middleware package for zerotheft services.
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