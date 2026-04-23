from __future__ import annotations

import logging
from sqlalchemy import event

from ..application.context import get_tenant_id

logger = logging.getLogger(__name__)


def register_rls_listener(engine):
    """
    Register the tenant isolation hook on a SQLAlchemy Engine.

    Call ONCE during service bootstrap — not per-request.
    After registration, every SQL executed through this engine will have
    ``SET LOCAL app.current_tenant = '<uuid>'`` issued before it runs.

    Returns the listener function so callers can remove it later with
    ``sqlalchemy.event.remove(engine, "before_cursor_execute", fn)``
    if needed (e.g. in tests).

    How it works
    ------------
    The `before_cursor_execute` event fires before every SQL statement.
    We read the tenant UUID from the ContextVar (set by middleware per-request)
    and inject it into the CRDB session via SET LOCAL.

    CRDB RLS policies then call `internal.current_tenant_id()` which reads
    `current_setting('app.current_tenant', true)` — the value we just set.

    SET LOCAL scope
    ---------------
    SET LOCAL resets when the current transaction ends. This makes connection
    pool reuse safe — each new transaction starts with a clean session state
    regardless of which request previously used that connection.

    Requires: engine must use autocommit=False (default for SQLAlchemy).

    What is NOT set here
    --------------------
    Only app.current_tenant is set. No other session variables are propagated
    to the database. Admin access is enforced by the middleware setting
    app.current_tenant to the targeted tenant UUID. The DB sees admin
    sessions as normal tenant sessions — same RLS policies apply.

    Parameters
    ----------
    engine : sqlalchemy.Engine
        The SQLAlchemy engine created by the consuming service.
    """

    @event.listens_for(engine, "before_cursor_execute")
    def _set_rls_context(
        conn, cursor, statement, parameters, context, executemany
    ):
        tenant_id = get_tenant_id()

        if tenant_id:
            # Stamp the session with the current tenant UUID.
            # Uses set_config() with parameterized value to avoid SQL injection.
            # Third arg = true → LOCAL (transaction-scoped), same as SET LOCAL.
            cursor.execute(
                "SELECT set_config('app.current_tenant', %s, true)",
                (tenant_id,),
            )
        else:
            # Fail-closed: explicitly set empty string.
            # internal.current_tenant_id() in CRDB returns NULL for empty string
            # via NULLIF(..., ''). UUID equality against NULL is always false.
            # Result: all tenant-scoped RLS policies return 0 rows, no error,
            # no data leak.
            cursor.execute(
                "SELECT set_config('app.current_tenant', '', true)"
            )

    logger.info(
        "RLS before_cursor_execute listener registered | engine=%s",
        engine.url.database,
    )
    return _set_rls_context
