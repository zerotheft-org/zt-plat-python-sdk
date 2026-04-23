from __future__ import annotations

import logging
from contextvars import ContextVar

logger = logging.getLogger(__name__)

_tenant_id_var: ContextVar[str | None] = ContextVar("rls_tenant_id", default=None)
_trace_id_var: ContextVar[str | None] = ContextVar("rls_trace_id", default=None)
_bypass_rls_var: ContextVar[bool] = ContextVar("rls_bypass_rls", default=False)


def set_tenant_context(
    tenant_id: str,
    bypass_rls: bool = False,
    trace_id: str | None = None,
) -> None:
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
    _tenant_id_var.set(None)
    _bypass_rls_var.set(False)
    _trace_id_var.set(None)


def get_tenant_id() -> str | None:
    return _tenant_id_var.get()


def get_bypass_rls() -> bool:
    return _bypass_rls_var.get()


def get_trace_id() -> str | None:
    return _trace_id_var.get()