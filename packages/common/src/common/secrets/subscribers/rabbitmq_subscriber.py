import json
import logging
import time
from typing import Any, Callable
import pika

from common.secrets.manager import RefreshEventSubscriber

logger = logging.getLogger(__name__)


class RabbitMQRefreshSubscriber(RefreshEventSubscriber):
    """
    RabbitMQ Topic Exchange implementation for secret refresh events.
    Includes automatic reconnection and heartbeat management.
    """

    def __init__(
        self,
        host: str,
        exchange: str = "secrets",
        routing_keys: list[str] | None = None,
        port: int = 5672,
        username: str = "guest",
        password: str = "guest",
        max_retries: int = 10,  # Max reconnection attempts
    ) -> None:
        self._host = host
        self._exchange = exchange
        self._routing_keys = routing_keys or ["secret.#"]
        self._port = port
        self._credentials = pika.PlainCredentials(username, password)
        self._handlers: dict[str, Callable[[Any], None]] = {}
        self._running = False
        self._connection: pika.BlockingConnection | None = None
        self._channel = None
        self._max_retries = max_retries

        logger.info(
            "RabbitMQRefreshSubscriber initialized (exchange=%s, routing_keys=%s)",
            exchange, self._routing_keys
        )

    def subscribe(
        self,
        event: str,
        handler: Callable[[Any], None]
    ) -> None:
        """Register handler for an event name."""
        self._handlers[event] = handler
        logger.info("Handler registered for event: %s", event)

    def start(self) -> None:
        """Start consumer with automatic reconnection."""
        self._running = True
        retry_count = 0
        
        while self._running and retry_count < self._max_retries:
            try:
                self._connect_and_consume()
                retry_count = 0  # Reset on successful connection
            except Exception as e:
                if not self._running:
                    break
                    
                retry_count += 1
                wait_time = min(2 ** retry_count, 60)  # Exponential backoff, max 60s
                
                if retry_count < self._max_retries:
                    logger.warning(
                        "RabbitMQ connection failed (attempt %d/%d): %s. Retrying in %ds...",
                        retry_count, self._max_retries, e, wait_time
                    )
                    time.sleep(wait_time)
                else:
                    logger.error("Max retries reached. Giving up: %s", e)
                    break

    def _connect_and_consume(self) -> None:
        """Establish connection and start consuming."""
        params = pika.ConnectionParameters(
            host=self._host,
            port=self._port,
            credentials=self._credentials,
            heartbeat=30,  
            blocked_connection_timeout=300,  # 5 minutes
            connection_attempts=3,
            retry_delay=2
        )
        
        self._connection = pika.BlockingConnection(params)
        self._channel = self._connection.channel()
        
        # Limit messages to process at once
        self._channel.basic_qos(prefetch_count=1)

        self._channel.exchange_declare(
            exchange=self._exchange,
            exchange_type="topic",
            durable=True
        )

        result = self._channel.queue_declare(queue="", exclusive=True, auto_delete=True)
        queue_name = result.method.queue
        logger.info("Exclusive queue declared: %s", queue_name)

        for routing_key in self._routing_keys:
            self._channel.queue_bind(
                queue=queue_name,
                exchange=self._exchange,
                routing_key=routing_key
            )
            logger.info("Bound queue %s to routing_key: %s", queue_name, routing_key)

        self._channel.basic_consume(
            queue=queue_name,
            on_message_callback=self._on_message,
            auto_ack=True
        )

        logger.info("RabbitMQ consumer started, waiting for messages...")
        
        try:
            while self._running:
                self._connection.process_data_events(time_limit=1)
        
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.warning("Connection lost during consume: %s", e)
            raise
        finally:
            self._cleanup_connection()

    def _cleanup_connection(self) -> None:
        """Safely close connection."""
        try:
            if self._connection and not self._connection.is_closed:
                self._connection.close()
                logger.info("RabbitMQ connection closed")
        except Exception as e:
            # Ignore errors during shutdown - connection may already be broken
            logger.debug("Error closing RabbitMQ connection (expected during shutdown): %s", e)

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self._running = False
        logger.info("RabbitMQ subscriber stop requested")

    def _on_message(self, channel, method, properties, body) -> None:
        routing_key = method.routing_key
        logger.warning("📬 RABBITMQ MESSAGE: routing_key=%s | body=%s", routing_key, body)

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            logger.warning("Invalid JSON from routing_key %s: %s", routing_key, body)
            return

        for event_name, handler in self._handlers.items():
            try:
                handler(payload, routing_key=routing_key)  # pass routing_key
            except Exception as e:
                logger.error("Error in handler for event %s: %s", event_name, e, exc_info=True)

    def publish_refresh(
        self,
        routing_key: str = "secret.refresh",
        keys: list[str] | None = None
    ) -> None:
        """Publish a refresh event to the exchange."""
        params = pika.ConnectionParameters(
            host=self._host,
            port=self._port,
            credentials=self._credentials
        )
        connection = pika.BlockingConnection(params)
        channel = connection.channel()

        channel.exchange_declare(
            exchange=self._exchange,
            exchange_type="topic",
            durable=True
        )

        payload = json.dumps({"keys": keys})
        channel.basic_publish(
            exchange=self._exchange,
            routing_key=routing_key,
            body=payload
        )

        connection.close()
        logger.info(
            "Published refresh event to exchange=%s routing_key=%s keys=%s",
            self._exchange, routing_key, keys
        )