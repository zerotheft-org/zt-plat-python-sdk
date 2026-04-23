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

This package lives under `common.rls_middleware` alongside the other shared
`common` modules.

## Usage

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from common.rls_middleware import (
    TenantRLSMiddleware,
    KeycloakTokenVerifier,
    DenialLogger,
    AuditLogger,
    register_rls_listener,
)

engine = create_engine(
    "cockroachdb://app_service_dev:password@host:26257/app_core_dev",
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

register_rls_listener(engine)

verifier = KeycloakTokenVerifier(
    jwks_url="https://keycloak.example.com/realms/zt/protocol/openid-connect/certs",
    issuer="https://keycloak.example.com/realms/zt",
    audience="zerotheft-api",
)

app.add_middleware(
    TenantRLSMiddleware,
    token_verifier=verifier,
    denial_logger=DenialLogger(session_factory=SessionLocal),
    audit_logger=AuditLogger(session_factory=SessionLocal),
)
```