from __future__ import annotations

import logging

from sqlalchemy import event

from ..application.context import get_tenant_id

logger = logging.getLogger(__name__)


def register_rls_listener(engine):
    @event.listens_for(engine, "before_cursor_execute")
    def _set_rls_context(
        conn, cursor, statement, parameters, context, executemany
    ):
        tenant_id = get_tenant_id()

        if tenant_id:
            cursor.execute(
                "SELECT set_config('app.current_tenant', %s, true)",
                (tenant_id,),
            )
        else:
            cursor.execute(
                "SELECT set_config('app.current_tenant', '', true)"
            )

    logger.info(
        "RLS before_cursor_execute listener registered | engine=%s",
        engine.url.database,
    )
    return _set_rls_context