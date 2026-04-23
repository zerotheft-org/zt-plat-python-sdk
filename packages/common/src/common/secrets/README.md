# Common Python Package - Secrets Management

This internal package provides **thread-safe, cache-invalidation-aware secret handling** across the monorepo services. It uses local in-memory caching with pluggable pub/sub subscribers (Redis or RabbitMQ) for distributed cache invalidation.

## 🚀 Key Features

- **Provider Agnostic**: Swap between AWS and Local Env without changing application logic
- **Subscriber Agnostic**: Swap between Redis Pub/Sub and RabbitMQ without changing application logic
- **Local Memory Cache**: Fast, single-layer cache with configurable TTL
- **Pub/Sub Invalidation**: Distributed cache invalidation across all service instances/pods
- **Targeted Cache Invalidation**: Routing key → cache key mapping clears only affected secrets on rotation
- **Thread-Safe**: RLock ensures concurrent get/refresh operations don't race
- **Startup Validation**: `preload()` ensures all required secrets exist before app starts (fail-fast)
- **Critical Error Logging**: 403/Throttling errors logged as CRITICAL for alerting
- **Graceful Degradation**: Works without any subscriber (local-only TTL mode)

## 📂 Structure

```
common/
├── config/
│   └── base.py              # Pydantic settings with provider + subscriber config
└── secrets/
    ├── manager.py           # Core logic (thread-safe)
    ├── providers/
    │   ├── __init__.py      # Factory function
    │   ├── aws.py           # AWS Secrets Manager
    │   └── env.py           # Environment variables
    └── subscribers/
        ├── redis_subscriber.py     # Redis Pub/Sub implementation
        └── rabbitmq_subscriber.py  # RabbitMQ Topic Exchange implementation
```

## 🏗 Architecture

### Cache Invalidation Flow (from aws secret manager)

```
AWS Secrets Manager (admin rotates secret)
    ↓
EventBridge (publishes rotation event)
    ↓
Lambda Function (publishes invalidation message)
    ↓
Redis Pub/Sub  OR  RabbitMQ Topic Exchange
    ↓
All pods of all services receive broadcast simultaneously
    ↓
Each pod invalidates its local cache for the specific rotated key
    ↓
Next get() → fetches fresh value from AWS
    ↓
Registered on_rotation_callback fires (if any) → e.g. recycles DB engine
```

### Why Broadcast Matters (Redis / RabbitMQ vs HTTP endpoint)

Both Redis Pub/Sub and RabbitMQ fanout/topic exchanges are **broadcast systems** — every connected pod receives the message simultaneously. This is critical because hitting an HTTP endpoint behind a load balancer only reaches one pod, leaving the rest with stale cache.

### Targeted Cache Invalidation via Routing Key Map

When a secret rotates, only the affected cache entry is cleared — not the entire cache. This is controlled by `routing_key_map`, which maps RabbitMQ routing keys to the cache keys they correspond to:

```
rotation.db      → clears ["app/db-credentials"]
rotation.keycloak → clears ["app/keycloak-client"]
```

If no routing key map is configured, or the routing key isn't in the map, the handler falls back to clearing all cached secrets.

### Thread-Safety

```python
# Scenario: refresh event arrives while another thread is reading
Thread A: refresh(["db/password"])  → acquires lock, clears cache
Thread B: get("db/password")        → waits for lock, then fetches fresh
```

The `RLock` ensures no race conditions between concurrent get/refresh operations.

## 🛠 Installation

Add to your service's `pyproject.toml`:

```toml
[tool.uv.sources]
common = { path = "../../../platform/python/common", editable = true }

[project]
dependencies = [
    "common",
    "redis>=5.0.0",   # Only if using Redis pub/sub
    "pika>=1.3.0",    # Only if using RabbitMQ
]
```

## 💡 Usage

### 1. Configure `.env`

**Local Development (no subscriber):**
```bash
SECRETS_PROVIDER=env
SECRETS_PREFIX=local/
MEMORY_TTL_SECONDS=300
# SUBSCRIBER_TYPE not set → local-only TTL mode
```

**Production with Redis Pub/Sub:**
```bash
SECRETS_PROVIDER=aws
SECRETS_REGION=us-east-1
SECRETS_PREFIX=production/
MEMORY_TTL_SECONDS=300

SUBSCRIBER_TYPE=redis
REDIS_HOST=cache.example.com
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=secret
```

**Production with RabbitMQ:**
```bash
SECRETS_PROVIDER=aws
SECRETS_REGION=us-east-1
SECRETS_PREFIX=production/
MEMORY_TTL_SECONDS=300

SUBSCRIBER_TYPE=rabbitmq
RABBITMQ_HOST=rabbitmq.internal
RABBITMQ_PORT=5672
RABBITMQ_USERNAME=myuser
RABBITMQ_PASSWORD=mypassword
RABBITMQ_EXCHANGE=secrets
# Use specific routing keys — avoid wildcard patterns like "rotation.#"
# to prevent the same event firing multiple times
RABBITMQ_ROUTING_KEYS=["rotation.db", "rotation.keycloak"]
```

> ⚠️ **Avoid wildcard patterns alongside specific keys.** If you include `rotation.#` alongside `rotation.db`, a single rotation event will fire twice — once per matching binding — and clear the cache redundantly. Use only specific routing keys.

### 2. FastAPI Integration (Recommended Pattern)

Define `SECRET_ROUTING_MAP` as a single source of truth. The preload keys are derived automatically from its values — no duplication.

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from common.config.base import BaseConfig
from common.secrets.providers import build_secret_manager

# Single source of truth: routing key → cache keys
# Adding a new secret? Add it here only.
SECRET_ROUTING_MAP = {
    "rotation.db":       ["app/db-credentials"],
    "rotation.keycloak": ["app/keycloak-client"],
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    config = BaseConfig()
    secrets = build_secret_manager(config, routing_key_map=SECRET_ROUTING_MAP)

    # Derive preload keys from the map values — no separate list to maintain
    secrets.preload([key for keys in SECRET_ROUTING_MAP.values() for key in keys])

    # Register post-rotation callbacks BEFORE starting the subscriber so that
    # any event arriving immediately on subscribe already has a handler in place.
    # Callbacks run after the cache is cleared, so secrets.get() inside them
    # already returns the fresh value fetched from AWS.
    secrets.register_rotation_callback("rotation.db", lambda: rebuild_db_engine())

    secrets.start_subscriber()

    app.state.secrets = secrets
    yield
    secrets.clear()

def get_secrets(request: Request):
    return request.app.state.secrets

app = FastAPI(lifespan=lifespan)
```

> ⚠️ **Long-lived connections** (DB connection pools, persistent sessions, etc.) copy credentials at construction time and are not automatically updated when a secret rotates. Use `register_rotation_callback()` to recycle them after rotation. See [LONG_LIVED_CONNECTIONS.md](./LONG_LIVED_CONNECTIONS.md) for the full pattern and SQLAlchemy example.

When `rotation.db` arrives on RabbitMQ, only `app/db-credentials` is cleared. `app/keycloak-client` remains cached and unaffected.

### 3. Accessing Secrets

```python
@app.get("/data")
def get_data(secrets=Depends(get_secrets)):
    db_pass = secrets.get("app/db-credentials")
    return {"status": "ok"}
```

### 4. How Routing Key Resolution Works

When a RabbitMQ message arrives, the handler resolves which cache keys to clear in this order:

1. **Routing key match** — if the routing key is in `routing_key_map`, clears only those keys
2. **Payload fallback** — if no map match, checks for `keys` field in the message body
3. **Clear all** — if neither, clears the entire cache

After the cache is cleared, the registered `on_rotation_callback` for that routing key fires (if one exists).

```python
# Example: rotation.db fires
# → routing_key_map["rotation.db"] = ["app/db-credentials"]
# → only "app/db-credentials" is cleared
# → "app/keycloak-client" stays cached ✅
# → on_rotation_callbacks["rotation.db"]() called ✅
```

### 5. Manual Construction with RabbitMQ

```python
from common.secrets.manager import SecretManager
from common.secrets.providers.aws import AWSSecretsProvider
from common.secrets.subscribers.rabbitmq_subscriber import RabbitMQRefreshSubscriber

provider = AWSSecretsProvider(region="us-east-1", prefix="prod/")

subscriber = RabbitMQRefreshSubscriber(
    host="rabbitmq.internal",
    exchange="secrets",
    routing_keys=["rotation.db", "rotation.keycloak"]
)

routing_key_map = {
    "rotation.db":       ["app/db-credentials"],
    "rotation.keycloak": ["app/keycloak-client"],
}

# on_rotation_callbacks is optional — only needed for long-lived connections
on_rotation_callbacks = {
    "rotation.db": lambda: rebuild_db_engine(),  # recycle DB pool after rotation
}

secrets = SecretManager(
    provider=provider,
    subscriber=subscriber,
    memory_ttl_seconds=300,
    routing_key_map=routing_key_map,
    on_rotation_callbacks=on_rotation_callbacks,
)

secrets.preload([key for keys in routing_key_map.values() for key in keys])
secrets.start_subscriber()
```

### 6. Manual Construction with Redis

```python
from common.secrets.manager import SecretManager
from common.secrets.providers.aws import AWSSecretsProvider
from common.secrets.subscribers.redis_subscriber import RedisRefreshSubscriber
import redis

provider = AWSSecretsProvider(region="us-east-1", prefix="prod/")

redis_client = redis.Redis(host="cache.example.com", decode_responses=False)
subscriber = RedisRefreshSubscriber(redis_client)

secrets = SecretManager(
    provider=provider,
    subscriber=subscriber,
    memory_ttl_seconds=300,
    # on_rotation_callbacks={"rotation.db": lambda: rebuild_db_engine()},  # if needed
)

secrets.preload(["database/password"])
secrets.start_subscriber()
```

### 7. No Subscriber (Local-Only)

```python
from common.secrets.manager import SecretManager
from common.secrets.providers.env import EnvSecretsProvider

provider = EnvSecretsProvider(prefix="LOCAL_")
secrets = SecretManager(provider=provider, subscriber=None)

secrets.preload(["DB_PASSWORD"])
# No subscriber to start
```


## 🔒 Security & Error Handling

### Startup Failures

If a secret is missing or provider is down during `preload()`:
- Logs **CRITICAL** error with provider name
- Raises `RuntimeError`
- Service exits with **non-zero** status code
- Kubernetes/systemd sees the failure and won't mark as healthy

### Permission Errors (403)

If AWS returns `403 Forbidden` during runtime:
- Logs **CRITICAL** alert
- Raises `PermissionError`
- Monitoring systems should alert on CRITICAL logs

### Provider Throttling

If AWS throttles requests:
- Logs **ERROR** with provider name
- Raises exception
- Service should implement retry logic or circuit breaker

### Subscriber Unavailable

If Redis or RabbitMQ is unreachable:
- Service continues in **local-only TTL mode**
- No distributed cache invalidation until subscriber reconnects
- Logged as error, not critical — TTL acts as safety net

## 🧪 Testing

### Unit Test

```python
from common.secrets.manager import SecretManager
from common.secrets.providers.env import EnvSecretsProvider

def test_thread_safety():
    provider = EnvSecretsProvider()
    manager = SecretManager(provider)

    import threading

    def worker():
        for _ in range(100):
            manager.get("DB_PASSWORD")

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
```

### Integration Test (RabbitMQ with routing key map)

```python
import time
from common.secrets.subscribers.rabbitmq_subscriber import RabbitMQRefreshSubscriber
from common.secrets.manager import SecretManager
from common.secrets.providers.env import EnvSecretsProvider

# Single source of truth — same pattern as main.py
routing_key_map = {
    "rotation.db":  ["app/db-credentials"],
    "rotation.api": ["app/api-key"],
}

provider = EnvSecretsProvider()
subscriber = RabbitMQRefreshSubscriber(
    host="localhost",
    routing_keys=list(routing_key_map.keys()),  # no wildcards
)
secrets = SecretManager(provider, subscriber, routing_key_map=routing_key_map)
secrets.preload([key for keys in routing_key_map.values() for key in keys])
secrets.start_subscriber()

time.sleep(0.5)  # allow queue binding

subscriber.publish_refresh(routing_key="rotation.db")

time.sleep(1)
# Only db-credentials evicted — api-key untouched
assert "app/db-credentials" not in secrets._local_cache
assert "app/api-key" in secrets._local_cache
```

## 🚨 Monitoring Checklist

1. **Alert on CRITICAL logs** — indicates permission/startup failures
2. **Track cache hit rate** — monitor `_access_log` for "memory" vs "provider"
3. **Monitor subscriber health** — if Redis/RabbitMQ is down, services lose distributed invalidation
4. **AWS API throttling** — track ERROR logs with "throttling" keyword
5. **Secret rotation lag** — time between AWS rotation and all services refreshing

## 🔄 Rotation Workflow

1. Admin rotates secret in AWS Secrets Manager
2. AWS EventBridge triggers Lambda (within 1-2 seconds)
3. Lambda publishes invalidation message to RabbitMQ with the appropriate routing key (e.g. `rotation.db`)
4. All pods receive broadcast via RabbitMQ Topic Exchange
5. Each pod looks up the routing key in its `SECRET_ROUTING_MAP` and clears only the affected cache entry
6. Next `get()` fetches fresh value from AWS
7. New value cached locally for TTL duration
8. Registered `on_rotation_callback` for that routing key fires — e.g. recycles the DB connection pool with the fresh credential

## ⚙️ Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETS_PROVIDER` | `env` | `"env"` or `"aws"` |
| `SECRETS_REGION` | `us-east-1` | AWS region (AWS only) |
| `SECRETS_PREFIX` | `""` | Key prefix (e.g., `"prod/"`) |
| `MEMORY_TTL_SECONDS` | `300` | Local cache TTL (5 min) |
| `SUBSCRIBER_TYPE` | `None` | `"redis"`, `"rabbitmq"`, or unset for local-only |
| `REDIS_HOST` | `None` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database index |
| `REDIS_PASSWORD` | `None` | Redis password |
| `RABBITMQ_HOST` | `None` | RabbitMQ hostname |
| `RABBITMQ_PORT` | `5672` | RabbitMQ port |
| `RABBITMQ_USERNAME` | `guest` | RabbitMQ username |
| `RABBITMQ_PASSWORD` | `guest` | RabbitMQ password |
| `RABBITMQ_EXCHANGE` | `secrets` | Exchange name on the broker |
| `RABBITMQ_ROUTING_KEYS` | `["secret.#"]` | Routing key patterns this service subscribes to — use specific keys, not wildcards |

## 📦 Factory Function Details

The `build_secret_manager()` factory in `common.secrets.providers.__init__` handles:

1. **Provider selection** — reads `SECRETS_PROVIDER` from config
2. **Subscriber selection** — reads `SUBSCRIBER_TYPE` from config
3. **Routing key map injection** — passed directly by the caller (service-defined)
4. **Rotation callback injection** — optional, passed directly by the caller (service-defined)
5. **Dependency injection** — wires provider + subscriber + map into SecretManager
6. **Validation** — raises clear errors for missing required config

```python
secrets = build_secret_manager(
    config,
    routing_key_map=SECRET_ROUTING_MAP,
    on_rotation_callbacks={"rotation.db": my_db_recycle_callback},  # optional
)
```

Both `routing_key_map` and `on_rotation_callbacks` are intentionally **not** config-file-driven — they are defined in code per service, since they map infrastructure routing keys to application-level secret names and application-level objects (engines, clients) that each service owns.