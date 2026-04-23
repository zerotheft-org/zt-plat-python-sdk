-- ==========================================================================
-- 001_rls_baseline.sql — Executable DDL for RLS infrastructure
-- ==========================================================================
--
-- Run this ONCE against a fresh CockroachDB database to create the schemas,
-- tables, roles, functions, and policies that zerotheft-rls depends on.
--
-- Prerequisites:
--   - Connected as a superuser / admin role (e.g. root, crdb)
--   - Target database already exists (e.g. app_core_dev)
--
-- This script is idempotent: safe to re-run (uses IF NOT EXISTS / OR REPLACE).
-- ==========================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- 0. Schemas
-- ──────────────────────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS internal;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;


-- ──────────────────────────────────────────────────────────────────────────
-- 1. Roles
-- ──────────────────────────────────────────────────────────────────────────
-- app_user: NOLOGIN role that all RLS policies target.
-- Your login role (e.g. app_service_dev) must be a member of app_user.

-- CockroachDB doesn't support IF NOT EXISTS for CREATE ROLE, so guard:
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOLOGIN;
  END IF;
END
$$;


-- ──────────────────────────────────────────────────────────────────────────
-- 2. Helper functions (schema: internal)
-- ──────────────────────────────────────────────────────────────────────────

-- Returns the current tenant UUID from the session variable.
-- Returns NULL when the variable is empty or unset → fail-closed.
CREATE OR REPLACE FUNCTION internal.current_tenant_id()
RETURNS UUID AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- User-tenant helper: checks if a user row exists in the current tenant.
-- iam.users is tenant-scoped, so membership is represented by tenant_id.
CREATE OR REPLACE FUNCTION internal.user_in_current_tenant(p_user_id UUID)
RETURNS BOOLEAN AS $$
  SELECT EXISTS (
    SELECT 1 FROM iam.users
    WHERE user_id = p_user_id
      AND tenant_id = internal.current_tenant_id()
      AND status = 'active'
  );
$$ LANGUAGE SQL STABLE SECURITY DEFINER;


-- ──────────────────────────────────────────────────────────────────────────
-- 3. security.rls_denials — denial logging table
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security.rls_denials (
    denial_id    UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id    UUID,
    user_id      UUID,
    action       TEXT,
    resource     TEXT,
    trace_id     UUID,
    created_at   TIMESTAMPTZ DEFAULT now() NOT NULL
);

ALTER TABLE security.rls_denials ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.rls_denials FORCE ROW LEVEL SECURITY;

-- app_user can INSERT denials but not read them (write-only for security).
-- DROP + CREATE because CockroachDB doesn't support CREATE OR REPLACE POLICY.
DROP POLICY IF EXISTS denial_write_only ON security.rls_denials;
CREATE POLICY denial_write_only ON security.rls_denials
    AS PERMISSIVE FOR INSERT TO app_user
    WITH CHECK (true);


-- ──────────────────────────────────────────────────────────────────────────
-- 4. audit.audit_events — admin access audit trail
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit.audit_events (
    event_id       UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    event_type     TEXT        NOT NULL,
    tenant_id      UUID,
    actor_user_id  UUID,
    action         TEXT,
    resource       TEXT,
    trace_id       UUID,
    payload        JSONB,
    created_at     TIMESTAMPTZ DEFAULT now() NOT NULL
);

ALTER TABLE audit.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY;

-- app_user can only see/write tenant-scoped events for their own tenant.
DROP POLICY IF EXISTS audit_tenant_isolation ON audit.audit_events;
CREATE POLICY audit_tenant_isolation ON audit.audit_events
    AS PERMISSIVE FOR ALL TO app_user
    USING  (event_type = 'tenant' AND tenant_id = internal.current_tenant_id())
    WITH CHECK (event_type = 'tenant' AND tenant_id = internal.current_tenant_id());


-- ──────────────────────────────────────────────────────────────────────────
-- 5. Grant permissions
-- ──────────────────────────────────────────────────────────────────────────
GRANT USAGE ON SCHEMA security TO app_user;
GRANT USAGE ON SCHEMA audit    TO app_user;
GRANT USAGE ON SCHEMA internal TO app_user;

GRANT INSERT          ON security.rls_denials  TO app_user;
GRANT SELECT, INSERT  ON audit.audit_events    TO app_user;
GRANT EXECUTE ON FUNCTION internal.current_tenant_id()               TO app_user;
GRANT EXECUTE ON FUNCTION internal.user_in_current_tenant(UUID)      TO app_user;
