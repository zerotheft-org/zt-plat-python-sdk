from __future__ import annotations

import logging
from contextvars import ContextVar

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Three separate ContextVars — one per value.
#
# Why not one ContextVar holding a TenantContext object?
# Replacing a single object in a ContextVar does not propagate to coroutines
# that already hold a reference to the old object. Separate vars are safer.
#
# ContextVar (PEP 567) is async-safe: each concurrent request (coroutine)
# gets its own isolated copy of these values. No cross-request leakage.
# ---------------------------------------------------------------------------

_tenant_id_var: ContextVar[str | None] = ContextVar("rls_tenant_id", default=None)
_trace_id_var: ContextVar[str | None] = ContextVar("rls_trace_id", default=None)

# bypass_rls is stored here for application-layer consumers (route handlers
# that need to decide PII masking). The SQLAlchemy listener does NOT read
# this — it is never propagated to the DB session.
_bypass_rls_var: ContextVar[bool] = ContextVar("rls_bypass_rls", default=False)


def set_tenant_context(
    tenant_id: str,
    bypass_rls: bool = False,
    trace_id: str | None = None,
) -> None:
    """
    Store tenant context for the current async task (request).

    Called by TenantRLSMiddleware immediately after JWT verification.
    Values are then available to:
      - The SQLAlchemy listener  (reads tenant_id only)
      - Route handlers           (read via request.state.tenant_context)
      - DenialLogger             (reads trace_id)

    Parameters
    ----------
    tenant_id : str
        UUID string of the resolved tenant.
    bypass_rls : bool
        Application-layer flag for admin sessions. Never sent to DB.
    trace_id : str | None
        Per-request correlation ID.
    """
    _tenant_id_var.set(tenant_id)
    _bypass_rls_var.set(bypass_rls)
    _trace_id_var.set(trace_id)
    logger.debug(
        "Tenant context set | tenant=%s bypass=%s trace=%s",
        tenant_id,
        bypass_rls,
        trace_id,
    )


def clear_tenant_context() -> None:
    """
    Reset all context vars to their defaults.

    Called in TenantRLSMiddleware.dispatch finally block.
    Always executes — even if the route handler raised an exception.
    Prevents context leaking to the next request when connections or
    coroutines are reused from the pool.
    """
    _tenant_id_var.set(None)
    _bypass_rls_var.set(False)
    _trace_id_var.set(None)


def get_tenant_id() -> str | None:
    """
    Read by the SQLAlchemy listener before every query.
    Returns None when no tenant context is set (unauthenticated or cleared).
    """
    return _tenant_id_var.get()


def get_bypass_rls() -> bool:
    """
    Read by route handlers for application-layer decisions (PII masking etc).
    NOT read by the SQLAlchemy listener — never propagated to the DB.
    """
    return _bypass_rls_var.get()


def get_trace_id() -> str | None:
    """Read by DenialLogger for correlating denial records with request logs."""
    return _trace_id_var.get()
