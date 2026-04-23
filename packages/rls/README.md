# zerotheft-rls

Tenant RLS context propagation and enforcement for zerotheft platform services.

## What This Package Does

Every HTTP request carries a JWT from Keycloak identifying which tenant the user
belongs to. This package:

1. Extracts and verifies that JWT in FastAPI middleware
2. Stores the tenant UUID in a per-request Python ContextVar
3. Before every SQL query, injects `SET LOCAL app.current_tenant = '<uuid>'`
   into the CockroachDB session
4. CRDB RLS policies read that session variable and filter rows automatically

No application code needs `WHERE tenant_id = ?`. The DB enforces it.

## Architecture

```
HTTP Request → TenantRLSMiddleware → ContextVar → SQLAlchemy Listener → SET LOCAL → CRDB RLS
                  │                                    │
                  │ JWT verify via                     │ before_cursor_execute
                  │ Keycloak JWKS                      │ fires on every query
                  │                                    │
                  ├─ 403 on failure (fail-closed)      └─ '' on missing context
                  └─ DenialLogger writes to                (RLS returns 0 rows)
                     security.rls_denials
```

### Package layout (DDD + Clean Architecture)

```
app/
├── __init__.py                    # public API re-exports
├── py.typed                       # PEP 561 marker
│
├── domain/                        # pure value objects — no I/O
│   └── tenant_context.py          # TenantContext (frozen dataclass)
│
├── application/                   # orchestration — ContextVar store
│   └── context.py                 # set/get/clear tenant context
│
├── infrastructure/                # I/O adapters — DB, HTTP, Keycloak
│   ├── keycloak_verifier.py       # async JWKS fetch + JWT verification
│   ├── rls_listener.py            # SQLAlchemy before_cursor_execute
│   ├── denial_logger.py           # writes to security.rls_denials
│   └── audit_logger.py            # writes to audit.audit_events
│
└── interfaces/                    # ASGI boundary — HTTP in/out
    ├── exceptions.py              # MissingToken, InvalidToken, ExpiredToken
    └── middleware.py              # TenantRLSMiddleware
```

## Integrating Into Your Service

### 1. Add to your Python path

From another service in the monorepo:

```python
# In your service's pyproject.toml or requirements
# Point at the rls_middleware package:
zerotheft-rls = { path = "../../platform/rls_middleware", develop = true }

# Or add to sys.path in your bootstrap if not using a package manager:
import sys
sys.path.insert(0, "/path/to/platform/rls_middleware")
```

### 2. Database prerequisites

Run the migration SQL against your CockroachDB cluster **once**:

```bash
cockroach sql --url "$CRDB_ADMIN_URL" < sql/001_rls_baseline.sql
```

This creates:
- `internal.current_tenant_id()` and `internal.user_in_current_tenant()` helper functions
- `security.rls_denials` table with write-only RLS policy
- `audit.audit_events` table with tenant-scoped RLS policy
- Required GRANT statements for the `app_user` role

Your application tables need their own RLS policies. See `sql/rls_enforcement.sql` for the pattern.

### 3. Wire into your FastAPI app

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import (
    TenantRLSMiddleware,
    KeycloakTokenVerifier,
    DenialLogger,
    AuditLogger,
    register_rls_listener,
)

# ─── Engine & session factory ───────────────────────────────────────────
engine = create_engine(
    "cockroachdb://app_service_dev:password@host:26257/app_core_dev",
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# ─── Step 1: Register SQLAlchemy listener (once at startup) ────────────
register_rls_listener(engine)

# ─── Step 2: Create verifier ───────────────────────────────────────────
# Option A: explicit config (preferred — no hidden env coupling)
verifier = KeycloakTokenVerifier(
    jwks_url="https://keycloak.example.com/realms/zt/protocol/openid-connect/certs",
    issuer="https://keycloak.example.com/realms/zt",
    audience="zerotheft-api",
)

# Option B: env-var fallback (reads KEYCLOAK_JWKS_URL, KEYCLOAK_ISSUER, KEYCLOAK_AUDIENCE)
# verifier = KeycloakTokenVerifier()

# ─── Step 3: Add middleware (AFTER cors, BEFORE routes) ────────────────
app.add_middleware(
    TenantRLSMiddleware,
    token_verifier=verifier,
    denial_logger=DenialLogger(session_factory=SessionLocal),
    audit_logger=AuditLogger(session_factory=SessionLocal),
    # skip_paths={"/health", "/ready", "/metrics"},  # defaults are sensible
    # enforcement_enabled=False,  # NEVER in staging/production
)
```

### 4. Access tenant context in route handlers

```python
from fastapi import Request
from app import TenantContext

@app.get("/api/projects")
async def list_projects(request: Request, db: Session = Depends(get_db)):
    ctx: TenantContext = request.state.tenant_context

    # RLS already filters — this returns only the current tenant's projects
    projects = db.execute(text("SELECT * FROM core.projects")).fetchall()

    # Application-layer admin check (if needed)
    if ctx.bypass_rls:
        # Admin targeting this tenant — may unmask PII, etc.
        ...

    return projects
```

### 5. Keycloak setup

Your Keycloak realm needs:

| Item | What to configure |
|------|-------------------|
| **Protocol mapper** | Add `tenant_id` claim (UUID) to access tokens. The user's active tenant is set at login. |
| **Realm role** | Create `platform_admin` role. Assign to admin users. |
| **Permission claim** | Add `tenant:investigate` to a custom `permissions` claim or as a client role under your admin client. |

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_JWKS_URL` | Yes* | — | Keycloak JWKS endpoint |
| `KEYCLOAK_ISSUER` | Yes* | — | Keycloak realm issuer URL |
| `KEYCLOAK_AUDIENCE` | Yes* | — | Keycloak client ID |
| `KEYCLOAK_ADMIN_CLIENT_ID` | No | `""` | Client ID for resource_access role lookup |
| `TENANT_CLAIM_KEY` | No | `tenant_id` | JWT claim key for tenant UUID |
| `ADMIN_ROLE_NAME` | No | `platform_admin` | Keycloak realm role for admins |
| `ADMIN_PERMISSION_CLAIM` | No | `tenant:investigate` | Required permission for admin access |
| `RLS_ENFORCEMENT_ENABLED` | No | `true` | Set `false` for local dev only |

*Not required if passed as constructor kwargs to `KeycloakTokenVerifier()`.

## Running Tests

```bash
# Phase 1 — unit tests (no DB, no Keycloak)
.venv/bin/pytest tests/phase1/ -v

# Phase 2 — integration tests (requires CRDB_TEST_URL and CRDB_ADMIN_URL in .env)
.venv/bin/pytest tests/phase2/ -v

# Keycloak smoke test (requires KEYCLOAK_* and KC_CLIENT_* vars in .env)
.venv/bin/pytest tests/test_keycloak_smoke.py -v

# All tests
.venv/bin/pytest tests/ -v

# With coverage
.venv/bin/pytest tests/ -v --cov=app --cov-report=term-missing
```

## Security Properties

- **Fail-closed**: Any auth failure → HTTP 403, never 500, zero DB calls
- **SET LOCAL scope**: Tenant variable resets per-transaction — connection pool safe
- **Admin transparency**: Admins use the same RLS as tenant users (scoped to target tenant UUID)
- **bypass_rls is app-only**: Never sent to DB — route handlers read it for PII masking
- **Fire-and-forget logging**: DenialLogger/AuditLogger never crash the request
- **JWKS rotation**: Transparent re-fetch on key ID miss — no restart needed
- **Async JWKS fetch**: Uses `httpx.AsyncClient` — doesn't block the event loop
