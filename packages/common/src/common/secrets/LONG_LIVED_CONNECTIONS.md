# Handling Long-Lived Connections with Secret Rotation

When secrets rotate, most application code automatically picks up the new value on
the next `secrets.get()` call — the cache is cleared, the fresh value is fetched
from AWS, and life goes on.

The exception is any object that **copies a credential at construction time and
reuses it for the lifetime of the process** — most commonly database connection pools.
This document explains the problem, the two-sided protection strategy, and how to
implement it using SQLAlchemy as the worked example.

---

## The Problem: Copied Credentials vs Live Lookups

Consider the difference between these two patterns:

```python
# ❌ Copies the credential at construction time
# Once built, this engine only knows the password it was given.
# Rotating the secret in AWS has no effect on this object.
engine = create_async_engine(settings.DATABASE_URL)

# ✅ Reads the credential at call time
# Every admin token request reads from the SecretManager.
# Cache cleared on rotation → next call fetches fresh password → works.
async def _get_admin_token(self):
    creds = json.loads(self._secrets.get("app/db-credentials"))
    ...
```

An HTTP client that authenticates per-request (like Keycloak above) gets rotation
for free. A connection pool that authenticates once when each connection is
established does not — those connections carry the old password until they are
closed and reopened.

The solution is two-sided protection:

```
Proactive: rotation event arrives → recycle engine before any requests fail
Reactive:  auth error detected    → recycle engine so the next request succeeds
```

Neither side alone is sufficient. The proactive path depends on timing (the
rotation event may arrive after AWS has already invalidated the old password during
the overlap window). The reactive path guarantees recovery but allows one request to
fail before healing.

---

## Two-Sided Protection

### Side 1 — Proactive: Rotation Callback

Register a post-rotation callback with the SecretManager. The callback fires after
the cache is cleared, so `secrets.get()` inside it already returns the fresh value.

```python
# In your app lifespan:
def on_db_rotation() -> None:
    db_creds = json.loads(secrets.get("app/db-credentials"))   # fresh from AWS
    asyncio.run_coroutine_threadsafe(
        recycle_engine(new_database_url=db_creds["url"]),
        loop,
    )

secrets.register_rotation_callback("rotation.db", on_db_rotation)
```

Execution order on a rotation event:

```
RabbitMQ message arrives (background thread)
  → cache cleared for "app/db-credentials"
  → on_db_rotation() called
      → secrets.get() fetches fresh URL from AWS
      → recycle_engine() dispatched to event loop
          → new engine built with fresh credentials
          → old engine disposed (idle conns close; active conns drain)
  → next request: get_db() pulls session from new engine ✓
```

### Side 2 — Reactive: Auth Error Interceptor

Even with the proactive callback, there is a window where:

- AWS has invalidated the old password (or is mid-rotation)
- The rotation event has not yet been received

Requests in that window will fail with a PostgreSQL authentication error
(`28P01` / `28000`). The reactive interceptor catches these and waits briefly
for the engine to be recycled before retrying the connection.

This is implemented directly in the session dependency rather than as middleware,
because the retry only makes sense at the connection-checkout level — retrying a
failed business operation is the caller's responsibility, not the session layer's.

---

## SQLAlchemy Implementation

### 1. Lazy Engine Initialization

Never build the engine at module import time. Build it in the app lifespan after
secrets are loaded.

```python
# session.py

_engine: AsyncEngine | None = None
_AsyncSessionLocal: async_sessionmaker | None = None

def init_engine(database_url: str, pool_size: int = 5, max_overflow: int = 10) -> None:
    global _engine, _AsyncSessionLocal
    _engine = create_async_engine(
        database_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,     # validates connections on checkout
        pool_timeout=30,
        connect_args={"timeout": 10, "command_timeout": 30},
        echo=False,
    )
    _AsyncSessionLocal = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)
```

### 2. Engine Recycling

`recycle_engine()` atomically swaps in a new engine. The old one is disposed —
idle connections close immediately, active connections finish their current
transaction then close naturally.

A cooldown prevents a stampede of auth errors from triggering repeated recycles.

```python
_RECYCLE_COOLDOWN_SECONDS = 15.0
_last_recycle_at = 0.0
_recycle_in_progress = False

async def recycle_engine(new_database_url: str, pool_size: int = 5, max_overflow: int = 10) -> None:
    global _engine, _last_recycle_at, _recycle_in_progress

    now = time.monotonic()
    if _recycle_in_progress or (now - _last_recycle_at) < _RECYCLE_COOLDOWN_SECONDS:
        logger.warning("Engine recycle skipped — cooldown active or recycle in progress")
        return

    _recycle_in_progress = True
    try:
        old_engine = _engine
        init_engine(new_database_url, pool_size, max_overflow)
        _last_recycle_at = time.monotonic()

        if old_engine:
            await old_engine.dispose()
    finally:
        _recycle_in_progress = False
```

> **Thread safety note**: `recycle_engine` is always called from the asyncio event
> loop (dispatched via `run_coroutine_threadsafe`). Python's GIL and the asyncio
> event loop's single-threaded execution model make the simple flag approach safe
> here — only one coroutine runs at a time on the loop.

### 3. Auth Error Detection

```python
def is_auth_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(
        marker in msg for marker in (
            "28p01",                            # PostgreSQL: invalid_password
            "28000",                            # PostgreSQL: invalid_authorization_specification
            "password authentication failed",
            "authentication failed",
        )
    )
```

### 4. Session Dependency with Checkout Retry

```python
_MAX_CHECKOUT_RETRIES = 2
_RETRY_BACKOFF_SECONDS = 2.0

async def get_db():
    if _AsyncSessionLocal is None:
        raise RuntimeError("DB not initialized — call init_engine() first.")

    last_exc = None
    for attempt in range(1, _MAX_CHECKOUT_RETRIES + 1):
        try:
            async with _AsyncSessionLocal() as session:
                yield session
                return
        except Exception as exc:
            last_exc = exc
            if is_auth_error(exc) and attempt < _MAX_CHECKOUT_RETRIES:
                wait = _RETRY_BACKOFF_SECONDS * attempt
                logger.warning(
                    "Auth error on DB checkout attempt %d/%d — waiting %.1fs for recycle",
                    attempt, _MAX_CHECKOUT_RETRIES, wait,
                )
                await asyncio.sleep(wait)
                continue
            raise

    raise last_exc
```

The retry only covers the **connection checkout** phase (before `yield`). If an
auth error surfaces during a query inside the route handler, it propagates normally
— business-level retry is the caller's responsibility. The engine will already be
queued for recycle by the next proactive or reactive trigger.

---

## Startup Sequence

Order matters. Registering callbacks before `start_subscriber()` guarantees that
any rotation event received immediately on subscribe has a callback in place.
Building the engine after registering callbacks means the callback can safely
reference the engine — it will exist by the time any rotation event could fire.

```
1. build_secret_manager()          # no network calls, no credentials yet
2. secrets.preload([...])          # fast-fail: missing secret → process exits
3. register_rotation_callback()    # callbacks ready before events can arrive
4. secrets.start_subscriber()      # background thread starts; events can now arrive
5. init_engine(secrets.get(...))   # engine built with fresh credential
6. init_keycloak_admin(secrets)    # holds manager reference, not credential value
7. yield → serve traffic
8. engine.dispose() + secrets.clear()
```

---

## What Lives in `.env` vs AWS Secrets Manager

| Stays in `.env` | Moves to AWS Secrets Manager |
|---|---|
| `SECRETS_PROVIDER`, `SECRETS_REGION`, `SECRETS_PREFIX` | `app/db-credentials` → `{"url": "postgresql+asyncpg://..."}` |
| `SUBSCRIBER_TYPE`, `RABBITMQ_HOST`, `RABBITMQ_*` | `app/keycloak-credentials` → `{"username": "...", "password": "..."}` |
| `DATABASE_POOL_SIZE`, `DATABASE_MAX_OVERFLOW` | Any other rotatable credentials |
| `DEBUG`, `LOG_LEVEL`, `CORS_ORIGINS` | |

The rule: structural / non-sensitive config stays in `.env`. Anything that rotates
or grants access goes to AWS.

---

## Keycloak: Why No Recycling Is Needed

Keycloak admin operations are stateless — there is no persistent connection or pool.
Every operation calls `_get_admin_token()` first, which POSTs to Keycloak with the
current username/password and receives a short-lived JWT. That JWT is used for the
operation and then discarded.

The only change needed is ensuring `_get_admin_token()` reads credentials from the
SecretManager at call time rather than from constructor-time copies:

```python
class KeycloakAdminClient:
    def __init__(self, secrets_manager: SecretManager) -> None:
        self._secrets = secrets_manager    # hold reference, not values

    async def _get_admin_token(self) -> str:
        creds = json.loads(self._secrets.get("app/keycloak-credentials"))
        # POST to Keycloak with creds["username"] and creds["password"]
        ...
```

When a rotation event arrives, the cache is cleared, and the very next call to
`_get_admin_token()` transparently uses the new password. No callback, no recycle,
no downtime.

---

## General Rule for Any Long-Lived Connection

When integrating a new infrastructure client with this secret manager, ask:

**Does this client copy a credential at construction time?**

- **No** (authenticates fresh per operation, like Keycloak): hold the `SecretManager`
  reference, read credentials at call time. Done.

- **Yes** (connection pool, persistent session, pre-authenticated client): implement
  a recycle function, register a rotation callback, and add a checkout retry if the
  client surfaces auth errors on existing connections.

Common examples in the "yes" category: SQLAlchemy, asyncpg raw pools, redis-py
connection pools, MongoDB Motor clients, Elasticsearch clients with HTTP auth.