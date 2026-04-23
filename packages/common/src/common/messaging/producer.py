"""
common/messaging/producer.py

Async RabbitMQ producer — aio-pika, topic exchange.

Design decisions:
  - Credentials injected at construction time — no settings imports here.
    Each service passes the URL it built from its own secrets manager.
  - Robust connection — aio-pika auto-reconnects on network drops without
    any code in this class. Reconnection is transparent to callers.
  - Exchange declared on connect() — producers declare topology so the
    exchange exists even if the consumer service hasn't started yet.
  - Fire-and-forget publish with optional confirms — default is
    delivery_mode=PERSISTENT so messages survive broker restart.
  - No global state — safe to instantiate multiple producers pointing at
    different brokers (e.g. audit broker vs secrets broker).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import aio_pika
import aio_pika.abc

logger = logging.getLogger(__name__)


def build_rabbitmq_url(creds: dict) -> str:
    """
    Build an AMQP URL from a credentials dict returned by the secrets manager.

    Expected keys: user (or username), password, host, port, vhost (optional).

    Kept here so every caller (producer, consumer, bootstrap) imports from
    one place rather than each defining its own copy.
    """
    from urllib.parse import quote_plus

    user = creds.get("user") or creds.get("username", "guest")
    password = creds.get("password", "guest")
    host = creds.get("host", "localhost")
    port = int(creds.get("port", 5672))
    vhost = creds.get("vhost", "/")
    vhost_encoded = "%2F" if vhost == "/" else quote_plus(vhost)
    return f"amqp://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{vhost_encoded}"


class RabbitMQProducer:
    """
    Async RabbitMQ producer for publishing messages to a topic exchange.

    Lifecycle (mirrors the pattern used by ImmudbAdapter and RabbitMQConsumer):
      1. producer = RabbitMQProducer(broker_url=..., exchange=...)
      2. await producer.connect()      ← called from service bootstrap
      3. await producer.publish(...)   ← called from use cases / services
      4. await producer.disconnect()   ← called from lifespan teardown

    The broker_url is injected at construction time from the secrets manager
    so this class has zero knowledge of AWS, settings, or .env files.

    On credential rotation the bootstrap callback:
      1. Disconnects the old producer
      2. Builds a new producer with fresh credentials
      3. Stores the new instance on app.state

    Thread safety: this class is async-only and must be used from a single
    event loop. Do not call publish() from a background thread — use
    asyncio.run_coroutine_threadsafe() if you need to publish from a thread.
    """

    def __init__(
        self,
        broker_url: str,
        exchange: str = "audit.events",
        exchange_type: str = "topic",
        service_name: str = "unknown",
    ) -> None:
        """
        Args:
            broker_url:     Full AMQP URL — use build_rabbitmq_url() to construct.
            exchange:       Exchange to publish to. Must match the consumer's topology.
            exchange_type:  Exchange type — "topic" (default), "direct", or "fanout".
            service_name:   Used in log messages to identify the publishing service.
        """
        self._broker_url = broker_url
        self._exchange_name = exchange
        self._exchange_type = exchange_type
        self._service_name = service_name

        self._connection: aio_pika.abc.AbstractRobustConnection | None = None
        self._channel: aio_pika.abc.AbstractChannel | None = None
        self._exchange: aio_pika.abc.AbstractExchange | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Establish a robust connection and declare the exchange.

        aio-pika's RobustConnection auto-reconnects on network drops.
        The exchange is declared here so the producer works even before
        the consumer service has started (idempotent declare).

        Called once from service bootstrap — not per-publish.
        """
        try:
            self._connection = await aio_pika.connect_robust(self._broker_url)
            self._channel = await self._connection.channel()

            exchange_type_map = {
                "topic": aio_pika.ExchangeType.TOPIC,
                "direct": aio_pika.ExchangeType.DIRECT,
                "fanout": aio_pika.ExchangeType.FANOUT,
            }
            self._exchange = await self._channel.declare_exchange(
                self._exchange_name,
                exchange_type_map.get(self._exchange_type, aio_pika.ExchangeType.TOPIC),
                durable=True,
            )

            logger.info(
                "rabbitmq_producer.connected service=%s exchange=%s",
                self._service_name,
                self._exchange_name,
            )

        except Exception as exc:
            logger.error(
                "rabbitmq_producer.connect_failed service=%s error=%s",
                self._service_name,
                type(exc).__name__,
            )
            raise

    async def disconnect(self) -> None:
        """Close the connection cleanly. Called from lifespan teardown."""
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
        self._exchange = None
        self._channel = None
        self._connection = None
        logger.info("rabbitmq_producer.disconnected service=%s", self._service_name)

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def publish(
        self,
        routing_key: str,
        body: dict[str, Any],
        *,
        message_id: str | None = None,
        correlation_id: str | None = None,
        persistent: bool = True,
    ) -> None:
        """
        Publish a single JSON message to the exchange.

        Args:
            routing_key:    RabbitMQ routing key (e.g. "audit.tenant.user_created").
            body:           Message payload — must be JSON-serialisable.
            message_id:     Optional idempotency key. Auto-generated UUID if not provided.
            correlation_id: Optional trace/correlation ID for request tracing.
            persistent:     If True (default), message survives broker restart.

        Raises:
            RuntimeError:  If connect() has not been called.
            Exception:     Propagates any aio-pika publish error to the caller.
        """
        if self._exchange is None:
            raise RuntimeError(
                "RabbitMQProducer not connected — call connect() before publish()."
            )

        msg_id = message_id or str(uuid.uuid4())

        message = aio_pika.Message(
            body=json.dumps(body, default=str).encode("utf-8"),
            content_type="application/json",
            message_id=msg_id,
            correlation_id=correlation_id,
            delivery_mode=(
                aio_pika.DeliveryMode.PERSISTENT
                if persistent
                else aio_pika.DeliveryMode.NOT_PERSISTENT
            ),
            timestamp=datetime.now(timezone.utc),
            app_id=self._service_name,
        )

        await self._exchange.publish(message, routing_key=routing_key)

        logger.debug(
            "rabbitmq_producer.published service=%s routing_key=%s message_id=%s",
            self._service_name,
            routing_key,
            msg_id,
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def is_healthy(self) -> bool:
        """Used by health check endpoints."""
        return (
            self._connection is not None
            and not self._connection.is_closed
        )

    async def warmup(self) -> None:
        """
        Eagerly connect at startup so the first publish doesn't pay the
        connection cost and won't time out under tight HTTP client timeouts.
        No-op if already connected.
        """
        if self._connection is None or self._connection.is_closed:
            await self.connect()
        logger.info(
            "rabbitmq_producer.warmed_up service=%s exchange=%s",
            self._service_name,
            self._exchange_name,
        )