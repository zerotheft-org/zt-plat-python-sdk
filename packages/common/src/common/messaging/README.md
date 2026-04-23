# common/messaging — Shared RabbitMQ Producer

Async RabbitMQ producer for publishing messages to a topic exchange.
Used by any service that needs to publish audit events (or other events)
without each rolling its own aio-pika wiring.

## Why a shared package?

- One place to fix bugs in connection handling, serialisation, or reconnect logic
- Consistent `message_id`, `timestamp`, `app_id` headers across all publishers
- Same credential injection pattern as `common/secrets` — no settings coupling
- Services stay thin: fetch credentials → build URL → construct producer → publish

## Architecture

```
AWS Secrets Manager
    ↓ (at startup via secrets manager)
auth-service bootstrap
    ↓ json.loads(secrets.get("auth/rabbitmq-credentials"))
build_rabbitmq_url(creds)
    ↓
RabbitMQProducer(broker_url=..., exchange="audit.events", service_name="auth-service")
    ↓ await producer.connect()
    ↓ await producer.publish(routing_key="audit.tenant.user_created", body={...})
audit.events exchange (RabbitMQ)
    ↓
audit-service RabbitMQConsumer
    ↓
IngestAuditEventUseCase
```


## Installation

Add to your service's `pyproject.toml`:

```toml
[tool.uv.sources]
common = { path = "../../../platform/python/common", editable = true }

[project]
dependencies = [
    "common",
    "aio-pika>=9.0.0",   # Required for RabbitMQProducer
]
```

`aio-pika` is listed as an optional dependency in `common/pyproject.toml`
(not all services use messaging). Add it to your own service dependencies.

## Usage

### 1. Bootstrap wiring (lifespan)

```python
import json
from common.messaging import RabbitMQProducer, build_rabbitmq_url

# SECRET_ROUTING_MAP in your bootstrap:
SECRET_ROUTING_MAP = {
    ...
    "rotation.rabbitmq": ["myservice/rabbitmq-credentials"],
}

# In lifespan, after secrets are preloaded:
creds = json.loads(secrets.get("myservice/rabbitmq-credentials"))
producer = RabbitMQProducer(
    broker_url=build_rabbitmq_url(creds),
    exchange="audit.events",
    service_name="auth-service",       # shows up in logs + message headers
)
await producer.warmup()                # connect eagerly at startup
app.state.audit_producer = producer
```

### 2. Rotation callback

```python
def on_rabbitmq_rotation() -> None:
    async def _restart():
        old = state.get("audit_producer")
        if old:
            await old.disconnect()
        creds = json.loads(secrets.get("myservice/rabbitmq-credentials"))
        new_producer = RabbitMQProducer(
            broker_url=build_rabbitmq_url(creds),
            exchange="audit.events",
            service_name="auth-service",
        )
        await new_producer.warmup()
        state["audit_producer"] = new_producer
        app.state.audit_producer = new_producer

    asyncio.run_coroutine_threadsafe(_restart(), loop).result(timeout=30)
```

### 3. FastAPI dependency

```python
# dependencies.py
from fastapi import Request
from common.messaging import RabbitMQProducer

def get_audit_producer(request: Request) -> RabbitMQProducer:
    return request.app.state.audit_producer
```

### 4. Publishing from a use case

```python
from common.messaging import RabbitMQProducer

class CreateUserUseCase:
    def __init__(self, ..., audit_producer: RabbitMQProducer) -> None:
        self._audit_producer = audit_producer

    async def execute(self, cmd: CreateUserCommand) -> User:
        user = ...  # do your domain work

        await self._audit_producer.publish(
            routing_key="audit.tenant.user_created",
            body={
                "event_type": "tenant",
                "action": "user.created",
                "tenant_id": str(cmd.tenant_id),
                "actor_user_id": str(cmd.actor_user_id),
                "resource": f"user:{user.id}",
                "payload": {"email": cmd.email},
            },
            correlation_id=str(cmd.trace_id),
        )

        return user
```

### 5. Teardown

```python
# In lifespan teardown:
producer = state.get("audit_producer")
if producer:
    await producer.disconnect()
```

## Routing key convention

Use dot-separated hierarchical keys so the audit service consumer binding
`audit.#` catches everything:

```
audit.{event_type}.{action}

audit.global.user_login
audit.global.service_boot
audit.tenant.user_created
audit.tenant.user_invited
audit.system.config_changed
```

The audit service consumer is bound with routing_key `audit.#` — any key
starting with `audit.` will be delivered.

## Message format

`publish()` sets these AMQP properties automatically:

| Property | Value |
|---|---|
| `content_type` | `application/json` |
| `message_id` | Auto-generated UUID (or caller-supplied) |
| `timestamp` | UTC now |
| `app_id` | `service_name` passed to constructor |
| `delivery_mode` | `PERSISTENT` (survives broker restart) |
| `correlation_id` | Caller-supplied (use trace/request ID) |

## Error handling

`publish()` propagates aio-pika exceptions to the caller. The caller decides
whether to retry, dead-letter, or drop. For audit events, the recommended
pattern is to let the exception propagate so the HTTP request fails fast —
the client can retry — rather than silently dropping audit records.

If you need fire-and-forget with no failure propagation, wrap in try/except
at the call site and log the error.

## Health check integration

```python
@app.get("/health")
async def health(request: Request) -> dict:
    producer: RabbitMQProducer = request.app.state.audit_producer
    return {
        "status": "ok",
        "rabbitmq": "ok" if await producer.is_healthy() else "degraded",
    }
```