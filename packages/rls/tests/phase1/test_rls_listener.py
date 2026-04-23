"""
RLS Listener — SET LOCAL Propagation

Verifies that:
  - register_rls_listener() stamps SET LOCAL app.current_tenant before queries
  - bypass_rls is never sent to the DB (app.bypass_rls absent from listener)
  - Missing tenant context sets empty string (fail-closed)

These are unit tests using a mock cursor — no real DB connection needed.
Phase 2 integration tests verify against a real CRDB instance.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call

from app.infrastructure.rls_listener import register_rls_listener


def _make_mock_engine():
    """Return a mock SQLAlchemy engine that captures event.listens_for calls."""
    engine = MagicMock()
    engine.url.database = "test_db"
    return engine


class TestSetLocalPropagation:

    def test_set_local_called_with_tenant_id_when_context_set(self):
        """
        When tenant context is set, the listener must call
        SET LOCAL app.current_tenant = '<uuid>'.
        """
        import uuid
        from app.application import context

        tenant = str(uuid.uuid4())
        context.set_tenant_context(tenant_id=tenant)

        cursor = MagicMock()
        executed_calls = []
        cursor.execute.side_effect = lambda sql, params=None: executed_calls.append((sql, params))

        # Manually invoke the listener function
        from sqlalchemy import event
        engine = MagicMock()
        engine.url.database = "test_db"

        registered_fn = None

        def capture_listener(engine_arg, event_name):
            def decorator(fn):
                nonlocal registered_fn
                registered_fn = fn
                return fn
            return decorator

        with patch.object(event, "listens_for", capture_listener):
            register_rls_listener(engine)

        registered_fn(None, cursor, "", {}, None, False)

        assert any(
            "set_config('app.current_tenant'" in sql and params == (tenant,)
            for sql, params in executed_calls
        )

        context.clear_tenant_context()

    def test_set_local_empty_string_when_no_context(self):
        """
        When no tenant context is set (missing/cleared), the listener must
        explicitly set empty string — not skip the SET LOCAL call.
        Empty string causes internal.current_tenant_id() to return NULL,
        which makes all tenant-scoped policies return 0 rows.
        """
        from app.application import context
        context.clear_tenant_context()  # ensure no context

        cursor = MagicMock()
        executed_calls = []
        cursor.execute.side_effect = lambda sql, params=None: executed_calls.append((sql, params))

        from sqlalchemy import event
        registered_fn = None

        def capture_listener(engine_arg, event_name):
            def decorator(fn):
                nonlocal registered_fn
                registered_fn = fn
                return fn
            return decorator

        with patch.object(event, "listens_for", capture_listener):
            register_rls_listener(MagicMock())

        registered_fn(None, cursor, "", {}, None, False)

        assert any(
            "set_config('app.current_tenant'" in sql and "''" in sql
            for sql, params in executed_calls
        )

    def test_bypass_rls_never_sent_to_db(self):
        """
        app.bypass_rls must never appear in any SET LOCAL call.
        The listener is intentionally only allowed to set app.current_tenant.
        """
        import inspect
        source = inspect.getsource(register_rls_listener)

        assert "app.bypass_rls" not in source, (
            "rls_listener must not set app.bypass_rls — "
            "that variable was removed from all CRDB RLS policies"
        )

    def test_only_current_tenant_is_set_in_db_session(self):
        """
        Only one SET LOCAL statement should be issued per query: app.current_tenant.
        No other session variables.
        """
        import uuid
        from app.application import context

        tenant = str(uuid.uuid4())
        context.set_tenant_context(tenant_id=tenant, bypass_rls=True)  # even with bypass_rls=True

        cursor = MagicMock()
        executed_calls = []
        cursor.execute.side_effect = lambda sql, params=None: executed_calls.append((sql, params))

        from sqlalchemy import event
        registered_fn = None

        def capture_listener(engine_arg, event_name):
            def decorator(fn):
                nonlocal registered_fn
                registered_fn = fn
                return fn
            return decorator

        with patch.object(event, "listens_for", capture_listener):
            register_rls_listener(MagicMock())

        registered_fn(None, cursor, "", {}, None, False)

        # Must be exactly one call
        assert len(executed_calls) == 1
        sql, params = executed_calls[0]
        assert "app.current_tenant" in sql
        assert "bypass_rls" not in sql

        context.clear_tenant_context()
