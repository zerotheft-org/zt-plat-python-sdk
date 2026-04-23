"""
Phase 2 integration test fixtures.

Connects to a real CockroachDB instance via env vars:
  - CRDB_TEST_URL  — app-level connection (e.g. app_service_dev) for test sessions
  - CRDB_ADMIN_URL — admin connection (e.g. root) for seed/cleanup
                     Must be a role with BYPASSRLS or admin group membership.

Schemas, tables, and RLS policies are already applied by migration scripts.
This conftest only seeds ephemeral test data and cleans up afterwards.

Requirements:
  - CRDB_TEST_URL env var set (app_service_dev, member of app_user)
  - CRDB_ADMIN_URL env var set (root or role with BYPASSRLS)
  - All migrations and RLS enforcement SQL already applied to the target DB

Test sessions use SET ROLE app_user so all RLS policies are enforced.
Seed/cleanup sessions use the admin connection to bypass RLS.

Seed is idempotent: all INSERTs use ON CONFLICT DO NOTHING so a crashed
previous run (which left data behind) does not block the next run.
"""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session


# ---------------------------------------------------------------------------
# Fixed test data constants — stable across all runs
# ---------------------------------------------------------------------------

TENANT_A  = "aaaaaaaa-0000-0000-0000-000000000001"
TENANT_B  = "aaaaaaaa-0000-0000-0000-000000000002"
ADMIN_USER = "aaaaaaaa-0000-0000-0000-000000000003"
USER_A      = "aaaaaaaa-0000-0000-0000-000000000004"  # tenant A only
USER_B      = "aaaaaaaa-0000-0000-0000-000000000005"  # tenant B only
USER_AB_A   = "aaaaaaaa-0000-0000-0000-000000000006"  # same human as USER_AB_B in tenant A
USER_AB_B   = "aaaaaaaa-0000-0000-0000-000000000007"  # same human as USER_AB_A in tenant B

SUBDOMAIN_A = "rls-test-tenant-a"
SUBDOMAIN_B = "rls-test-tenant-b"
EMAIL_A     = "rls-test-a@test.invalid"
EMAIL_B     = "rls-test-b@test.invalid"
EMAIL_AB    = "rls-test-ab@test.invalid"

EXTERNAL_SUB_A   = "bbbbbbbb-0000-0000-0000-000000000001"
EXTERNAL_SUB_B   = "bbbbbbbb-0000-0000-0000-000000000002"
EXTERNAL_SUB_AB  = "bbbbbbbb-0000-0000-0000-000000000003"

PLAN_FREE       = "aaaaaaaa-0000-0000-0000-000000000010"
PLAN_PRO        = "aaaaaaaa-0000-0000-0000-000000000011"
PLAN_ENTERPRISE = "aaaaaaaa-0000-0000-0000-000000000012"

TRACE_SEED_A      = "aaaaaaaa-0000-0000-0000-000000000020"
TRACE_SEED_SYSTEM = "aaaaaaaa-0000-0000-0000-000000000021"


# ---------------------------------------------------------------------------
# Seed + cleanup
# ---------------------------------------------------------------------------

def _seed(conn):
    """
    Insert ephemeral test data via the admin connection (bypasses RLS).

    All INSERTs use ON CONFLICT DO NOTHING so this function is safe to call
    even when a previous pytest session crashed before cleanup ran.

    Raises on any unexpected failure — never swallows errors silently.
    """
    try:
        # 1. Tenants
        conn.execute(text("""
            INSERT INTO core.tenants
                (tenant_id, subdomain, name, status, region, compliance_tier, realm_mode)
            VALUES
                (:tid, :subdomain, :name, 'active', 'us-east-1', 'commercial', 'shared')
            ON CONFLICT DO NOTHING
        """), [
            {"tid": TENANT_A, "subdomain": SUBDOMAIN_A, "name": "RLS Test Tenant A"},
            {"tid": TENANT_B, "subdomain": SUBDOMAIN_B, "name": "RLS Test Tenant B"},
        ])
        print("[SEED] tenants inserted", file=sys.stderr, flush=True)

        # 2. Users (tenant-scoped — tenant_id is membership)
        conn.execute(text("""
            INSERT INTO iam.users
                (user_id, tenant_id, email, first_name, last_name, status, external_auth_id)
            VALUES
                (:uid, :tid, :email, :first, :last, 'active', :external_auth_id)
            ON CONFLICT DO NOTHING
        """), [
            {
                "uid": USER_A,
                "tid": TENANT_A,
                "email": EMAIL_A,
                "first": "Alice",
                "last": "TestA",
                "external_auth_id": EXTERNAL_SUB_A,
            },
            {
                "uid": USER_B,
                "tid": TENANT_B,
                "email": EMAIL_B,
                "first": "Bob",
                "last": "TestB",
                "external_auth_id": EXTERNAL_SUB_B,
            },
            {
                "uid": USER_AB_A,
                "tid": TENANT_A,
                "email": EMAIL_AB,
                "first": "Carol",
                "last": "TestAB",
                "external_auth_id": EXTERNAL_SUB_AB,
            },
            {
                "uid": USER_AB_B,
                "tid": TENANT_B,
                "email": EMAIL_AB,
                "first": "Carol",
                "last": "TestAB",
                "external_auth_id": EXTERNAL_SUB_AB,
            },
        ])
        print("[SEED] users inserted", file=sys.stderr, flush=True)

        # 3. Plan catalog (global — no tenant_id)
        conn.execute(text("""
            INSERT INTO billing.plan_catalog (plan_id, version, name)
            VALUES (:pid, 1, :name)
            ON CONFLICT DO NOTHING
        """), [
            {"pid": PLAN_FREE,       "name": "Free"},
            {"pid": PLAN_PRO,        "name": "Pro"},
            {"pid": PLAN_ENTERPRISE, "name": "Enterprise"},
        ])
        print("[SEED] plans inserted", file=sys.stderr, flush=True)

        # 4. Tenant-scoped audit event — visible to Tenant A via app_user
        conn.execute(text("""
            INSERT INTO audit.audit_events
                (event_type, tenant_id, action, trace_id)
            VALUES
                ('tenant', :tid, 'test_seed', :trace_id)
            ON CONFLICT DO NOTHING
        """), {"tid": TENANT_A, "trace_id": TRACE_SEED_A})

        # 5. System audit event — invisible to app_user (no matching policy)
        conn.execute(text("""
            INSERT INTO audit.audit_events
                (event_type, tenant_id, action, trace_id)
            VALUES
                ('system', NULL, 'test_seed_system', :trace_id)
            ON CONFLICT DO NOTHING
        """), {"trace_id": TRACE_SEED_SYSTEM})
        print("[SEED] audit events inserted", file=sys.stderr, flush=True)

        conn.commit()
        print("[SEED] committed — all test data in place", file=sys.stderr, flush=True)

    except Exception as exc:
        conn.rollback()
        print(f"[SEED] FAILED: {exc}", file=sys.stderr, flush=True)
        raise


def _cleanup(conn):
    """Remove all ephemeral test data. Run as admin (bypasses RLS)."""
    try:
        conn.execute(text(
            "DELETE FROM audit.audit_events WHERE trace_id IN (:t1, :t2)"
        ), {"t1": TRACE_SEED_A, "t2": TRACE_SEED_SYSTEM})

        conn.execute(text(
            "DELETE FROM audit.audit_events WHERE actor_user_id = :admin"
        ), {"admin": ADMIN_USER})

        conn.execute(text(
            """
            DELETE FROM iam.users
            WHERE (tenant_id, user_id) IN (
                (:ta, :u1),
                (:tb, :u2),
                (:ta, :u3),
                (:tb, :u4)
            )
            """
        ), {
            "ta": TENANT_A,
            "tb": TENANT_B,
            "u1": USER_A,
            "u2": USER_B,
            "u3": USER_AB_A,
            "u4": USER_AB_B,
        })

        conn.execute(text(
            "DELETE FROM core.tenants WHERE tenant_id IN (:a, :b)"
        ), {"a": TENANT_A, "b": TENANT_B})

        conn.execute(text(
            "DELETE FROM billing.plan_catalog WHERE plan_id IN (:p1, :p2, :p3)"
        ), {"p1": PLAN_FREE, "p2": PLAN_PRO, "p3": PLAN_ENTERPRISE})

        conn.commit()
        print("[CLEANUP] committed — test data removed", file=sys.stderr, flush=True)

    except Exception as exc:
        conn.rollback()
        print(f"[CLEANUP] FAILED: {exc}", file=sys.stderr, flush=True)
        raise


# ---------------------------------------------------------------------------
# URL helper
# ---------------------------------------------------------------------------

def _to_crdb_url(url: str) -> str:
    """Normalise postgresql:// to cockroachdb:// dialect."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "cockroachdb://", 1)
    return url


# ---------------------------------------------------------------------------
# Session-scoped engine fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def crdb_engine():
    """
    Connect to a real CockroachDB instance, seed test data, yield engines,
    then clean up. Fails loudly if either URL is missing.
    """
    test_url = os.environ.get("CRDB_TEST_URL")
    if not test_url:
        pytest.skip(
            "CRDB_TEST_URL not set — skipping Phase 2 integration tests."
        )

    admin_url = os.environ.get("CRDB_ADMIN_URL")
    if not admin_url:
        pytest.fail(
            "CRDB_ADMIN_URL not set. Seed requires a root/admin connection "
            "that bypasses RLS. app_service_dev cannot seed tenant-scoped "
            "tables without app.current_tenant set."
        )

    print(f"\n[CRDB] test_url  = {test_url}", file=sys.stderr, flush=True)
    print(f"[CRDB] admin_url = {admin_url}", file=sys.stderr, flush=True)

    test_engine  = create_engine(_to_crdb_url(test_url),  echo=False)
    admin_engine = create_engine(_to_crdb_url(admin_url), echo=False)

    with admin_engine.connect() as conn:
        _seed(conn)

    yield (test_engine, admin_engine)

    with admin_engine.connect() as conn:
        _cleanup(conn)

    test_engine.dispose()
    admin_engine.dispose()


@pytest.fixture(scope="session")
def test_engine(crdb_engine):
    """Engine connecting as app_service_dev — subject to RLS."""
    return crdb_engine[0]


@pytest.fixture(scope="session")
def admin_engine(crdb_engine):
    """Engine connecting as root/admin — bypasses RLS."""
    return crdb_engine[1]


@pytest.fixture(scope="session")
def session_factory(test_engine):
    """Sessionmaker bound to the test (app_service_dev) engine."""
    return sessionmaker(bind=test_engine)


@pytest.fixture(scope="session")
def admin_session_factory(admin_engine):
    """Sessionmaker bound to the admin engine."""
    return sessionmaker(bind=admin_engine)


@pytest.fixture(scope="session")
def app_user_session_factory(test_engine):
    """
    Session factory that explicitly runs as app_user (subject to RLS).
    Used by DenialLogger and AuditLogger in integration tests.
    Returns a context-manager factory matching the DenialLogger contract:
        with session_factory() as session: ...
    """
    @contextmanager
    def factory():
        session = Session(bind=test_engine)
        try:
            session.execute(text("SET ROLE app_user"))
            yield session
        finally:
            session.execute(text("RESET ROLE"))
            session.rollback()
            session.close()

    return factory


# ---------------------------------------------------------------------------
# Per-test session fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tenant_a_session(session_factory):
    """
    Session scoped to Tenant A, running as app_user.
    SET ROLE ensures RLS policies are enforced.
    SET (session-level) ensures the context variable persists for the
    lifetime of the session, not just a single transaction.
    """
    session: Session = session_factory()
    session.execute(text("SET ROLE app_user"))
    session.execute(text("SELECT set_config('app.current_tenant', :tid, false)"), {"tid": TENANT_A})
    yield session
    session.execute(text("RESET ROLE"))
    session.rollback()
    session.close()


@pytest.fixture()
def tenant_b_session(session_factory):
    """Session scoped to Tenant B, running as app_user."""
    session: Session = session_factory()
    session.execute(text("SET ROLE app_user"))
    session.execute(text("SELECT set_config('app.current_tenant', :tid, false)"), {"tid": TENANT_B})
    yield session
    session.execute(text("RESET ROLE"))
    session.rollback()
    session.close()


@pytest.fixture()
def no_tenant_session(session_factory):
    """
    Session with no tenant context — simulates fail-closed behaviour.
    Empty string → internal.current_tenant_id() returns NULL →
    all tenant-scoped policies return 0 rows.
    """
    session: Session = session_factory()
    session.execute(text("SET ROLE app_user"))
    session.execute(text("SET app.current_tenant = ''"))
    yield session
    session.execute(text("RESET ROLE"))
    session.rollback()
    session.close()


@pytest.fixture()
def raw_session(admin_session_factory):
    """
    Admin session with no RLS restrictions.
    Used to verify writes that app_user cannot read
    (e.g. security.rls_denials, system audit events).
    """
    session: Session = admin_session_factory()
    yield session
    session.rollback()
    session.close()