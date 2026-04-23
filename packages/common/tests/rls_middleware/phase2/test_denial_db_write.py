"""
C4 — Denial DB Write (Integration)

Verifies that DenialLogger writes a real row to security.rls_denials
with the correct trace_id, using a separate session as app_user.

The app_user role can INSERT but NOT SELECT security.rls_denials
(denial_write_only policy). Verification reads use raw_session (admin).
"""
from __future__ import annotations

import uuid

from sqlalchemy import text

from common.rls_middleware.infrastructure.denial_logger import DenialLogger
from tests.rls_middleware.phase2.conftest import TENANT_A, USER_A


class TestDenialDbWrite:

    def test_denial_written_to_rls_denials(
        self, app_user_session_factory, raw_session,
    ):
        """
        C4: Any denial → row in security.rls_denials with matching trace_id.
        DenialLogger writes as app_user (RLS INSERT policy: WITH CHECK true).
        Verification read uses admin session (app_user has no SELECT policy).
        """
        trace = str(uuid.uuid4())

        logger = DenialLogger(session_factory=app_user_session_factory)
        logger.log_denial(
            trace_id=trace,
            tenant_id=TENANT_A,
            user_id=USER_A,
            action="MIDDLEWARE_REJECT",
            resource="/api/projects",
        )

        row = raw_session.execute(
            text("""
                SELECT trace_id::TEXT, action, resource
                FROM security.rls_denials
                WHERE trace_id = :tid
            """),
            {"tid": trace},
        ).fetchone()

        assert row is not None
        assert row[0] == trace
        assert row[1] == "MIDDLEWARE_REJECT"
        assert row[2] == "/api/projects"

    def test_denial_has_all_required_fields(
        self, app_user_session_factory, raw_session,
    ):
        """All columns in rls_denials must be populated correctly."""
        trace = str(uuid.uuid4())

        logger = DenialLogger(session_factory=app_user_session_factory)
        logger.log_denial(
            trace_id=trace,
            tenant_id=TENANT_A,
            user_id=USER_A,
            action="MIDDLEWARE_ERROR",
            resource="/api/billing",
        )

        row = raw_session.execute(
            text("""
                SELECT denial_id, tenant_id::TEXT, user_id::TEXT,
                       action, resource, trace_id::TEXT, created_at
                FROM security.rls_denials
                WHERE trace_id = :tid
            """),
            {"tid": trace},
        ).fetchone()

        assert row is not None
        assert row[0] is not None         # denial_id (auto-generated)
        assert row[1] == TENANT_A         # tenant_id
        assert row[2] == USER_A           # user_id
        assert row[3] == "MIDDLEWARE_ERROR"
        assert row[4] == "/api/billing"
        assert row[5] == trace            # trace_id
        assert row[6] is not None         # created_at

    def test_app_user_cannot_select_denials(self, tenant_a_session):
        """
        The denial_write_only RLS policy allows INSERT only — no SELECT.
        app_user querying rls_denials must see 0 rows (no error).
        """
        rows = tenant_a_session.execute(
            text("SELECT * FROM security.rls_denials")
        ).fetchall()
        assert len(rows) == 0

    def test_denial_write_failure_does_not_raise(self):
        """
        Fire-and-forget contract: if the session_factory fails,
        log_denial must not raise — it only logs.
        """
        def bad_factory():
            raise RuntimeError("DB is down")

        logger = DenialLogger(session_factory=bad_factory)
        # Must not raise
        logger.log_denial(
            trace_id=str(uuid.uuid4()),
            action="MIDDLEWARE_REJECT",
            resource="/boom",
        )
