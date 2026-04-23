"""
Tenant-Scoped User Isolation (Integration)

Verifies that iam.users is tenant-scoped and filtered directly by tenant_id.

The RLS policy on iam.users is expected to be:
    USING (tenant_id = internal.current_tenant_id())
    WITH CHECK (tenant_id = internal.current_tenant_id())

Test data:
    - USER_A:    tenant A only
    - USER_B:    tenant B only
    - USER_AB_A: tenant A row for shared human
    - USER_AB_B: tenant B row for shared human
"""
from __future__ import annotations

from sqlalchemy import text

from tests.phase2.conftest import (
    EXTERNAL_SUB_AB,
    TENANT_A,
    TENANT_B,
    USER_A,
    USER_AB_A,
    USER_AB_B,
    USER_B,
)


class TestUserTenantIsolation:

    def test_tenant_a_sees_tenant_a_users(self, tenant_a_session):
        """
        Tenant A should only see tenant A rows in iam.users.
        """
        rows = tenant_a_session.execute(
            text("SELECT user_id::TEXT FROM iam.users ORDER BY email")
        ).fetchall()
        user_ids = [r[0] for r in rows]
        assert USER_A in user_ids
        assert USER_AB_A in user_ids
        assert USER_B not in user_ids
        assert USER_AB_B not in user_ids

    def test_tenant_a_cannot_see_tenant_b_users(self, tenant_a_session):
        """Tenant A cannot query tenant B rows by user_id."""
        rows = tenant_a_session.execute(
            text("SELECT * FROM iam.users WHERE user_id = :uid"),
            {"uid": USER_B},
        ).fetchall()
        assert len(rows) == 0
        rows = tenant_a_session.execute(
            text("SELECT * FROM iam.users WHERE user_id = :uid"),
            {"uid": USER_AB_B},
        ).fetchall()
        assert len(rows) == 0

    def test_tenant_b_sees_tenant_b_users(self, tenant_b_session):
        """
        Tenant B should only see tenant B rows in iam.users.
        """
        rows = tenant_b_session.execute(
            text("SELECT user_id::TEXT FROM iam.users ORDER BY email")
        ).fetchall()
        user_ids = [r[0] for r in rows]
        assert USER_B in user_ids
        assert USER_AB_B in user_ids
        assert USER_A not in user_ids
        assert USER_AB_A not in user_ids

    def test_tenant_b_cannot_see_tenant_a_users(self, tenant_b_session):
        """Tenant B cannot query tenant A rows by user_id."""
        rows = tenant_b_session.execute(
            text("SELECT * FROM iam.users WHERE user_id = :uid"),
            {"uid": USER_A},
        ).fetchall()
        assert len(rows) == 0
        rows = tenant_b_session.execute(
            text("SELECT * FROM iam.users WHERE user_id = :uid"),
            {"uid": USER_AB_A},
        ).fetchall()
        assert len(rows) == 0

    def test_no_context_sees_no_users(self, no_tenant_session):
        """Fail-closed: no context → 0 users visible."""
        rows = no_tenant_session.execute(
            text("SELECT * FROM iam.users")
        ).fetchall()
        assert len(rows) == 0


class TestExternalAuthIdLookup:

    def test_external_auth_id_not_unique_globally(self, raw_session):
        """The same external_auth_id can appear once per tenant."""
        rows = raw_session.execute(
            text("""
                SELECT tenant_id::TEXT, user_id::TEXT
                FROM iam.users
                WHERE external_auth_id = :sub
                ORDER BY tenant_id
            """),
            {"sub": EXTERNAL_SUB_AB},
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][0] == TENANT_A
        assert rows[1][0] == TENANT_B

    def test_external_auth_id_with_tenant_filter_resolves_single_user(self, raw_session):
        """Lookup must include tenant_id to get one deterministic user row."""
        row = raw_session.execute(
            text("""
                SELECT user_id::TEXT
                FROM iam.users
                WHERE external_auth_id = :sub
                  AND tenant_id = :tid
            """),
            {"sub": EXTERNAL_SUB_AB, "tid": TENANT_A},
        ).fetchone()
        assert row is not None
        assert row[0] == USER_AB_A