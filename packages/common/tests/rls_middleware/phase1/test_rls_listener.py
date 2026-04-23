from __future__ import annotations

from unittest.mock import MagicMock, patch

from common.rls_middleware.infrastructure.rls_listener import register_rls_listener


class TestSetLocalPropagation:
    def test_set_local_called_with_tenant_id_when_context_set(self):
        import uuid

        from common.rls_middleware.application import context

        tenant = str(uuid.uuid4())
        context.set_tenant_context(tenant_id=tenant)

        cursor = MagicMock()
        executed_calls = []
        cursor.execute.side_effect = (
            lambda sql, params=None: executed_calls.append((sql, params))
        )

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
        from common.rls_middleware.application import context

        context.clear_tenant_context()

        cursor = MagicMock()
        executed_calls = []
        cursor.execute.side_effect = (
            lambda sql, params=None: executed_calls.append((sql, params))
        )

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
        import inspect

        source = inspect.getsource(register_rls_listener)
        assert "app.bypass_rls" not in source

    def test_only_current_tenant_is_set_in_db_session(self):
        import uuid

        from common.rls_middleware.application import context

        tenant = str(uuid.uuid4())
        context.set_tenant_context(tenant_id=tenant, bypass_rls=True)

        cursor = MagicMock()
        executed_calls = []
        cursor.execute.side_effect = (
            lambda sql, params=None: executed_calls.append((sql, params))
        )

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

        assert len(executed_calls) == 1
        sql, params = executed_calls[0]
        assert "app.current_tenant" in sql
        assert "bypass_rls" not in sql

        context.clear_tenant_context()
