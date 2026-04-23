import json
import logging
import threading
from typing import Any, Callable, Dict
import redis

from common.secrets.manager import RefreshEventSubscriber

logger = logging.getLogger(__name__)


class RedisRefreshSubscriber(RefreshEventSubscriber):
    """
    Redis Pub/Sub implementation for secret refresh events.
    Listens to Redis channels and triggers cache invalidation.
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        channel_prefix: str = "secrets"
    ) -> None:
        """
        Args:
            redis_client: Configured Redis client instance
            channel_prefix: Prefix for pub/sub channels (default: "secrets")
        """
        self._redis = redis_client
        self._channel_prefix = channel_prefix
        self._pubsub = self._redis.pubsub(ignore_subscribe_messages=True)
        self._handlers: Dict[str, Callable[[Any], None]] = {}
        self._running = False
        self._thread: threading.Thread | None = None
        
        logger.info("RedisRefreshSubscriber initialized (prefix=%s)", channel_prefix)

    def subscribe(
        self,
        event: str,
        handler: Callable[[Any], None]
    ) -> None:
        """
        Subscribe to an event and register a handler.
        
        Args:
            event: Event name (e.g., "secret:refresh")
            handler: Callback function to handle messages
        """
        channel = f"{self._channel_prefix}:{event}"
        self._handlers[channel] = handler
        self._pubsub.subscribe(channel)
        logger.info("Subscribed to channel: %s", channel)

    def start(self) -> None:
        """
        Start listening for events (blocking).
        This should be called in a background thread.
        """
        self._running = True
        logger.info("Starting Redis pub/sub listener (blocking)...")
        
        try:
            for message in self._pubsub.listen():
                if not self._running:
                    break
                
                if message["type"] != "message":
                    continue
                
                channel = message["channel"]
                if isinstance(channel, bytes):
                    channel = channel.decode("utf-8")
                
                data = message["data"]
                
                # Parse JSON payload
                try:
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    payload = json.loads(data) if data else {}
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in message from %s: %s", channel, data)
                    continue
                
                # Call registered handler
                handler = self._handlers.get(channel)
                if handler:
                    try:
                        handler(payload)
                    except Exception as e:
                        logger.error("Error in handler for %s: %s", channel, e)
                else:
                    logger.warning("No handler registered for channel: %s", channel)
        
        except redis.RedisError as e:
            logger.error("Redis pub/sub error: %s", e)
        except Exception as e:
            logger.error("Unexpected error in pub/sub listener: %s", e)
        finally:
            logger.info("Redis pub/sub listener stopped")

    def stop(self) -> None:
        """
        Gracefully stop the subscriber.
        """
        self._running = False
        
        try:
            self._pubsub.unsubscribe()
            self._pubsub.close()
            logger.info("Redis pub/sub unsubscribed and closed")
        except Exception as e:
            logger.error("Error stopping Redis pub/sub: %s", e)

    def publish_refresh(self, keys: list[str] | None = None) -> None:
        """
        Utility method to publish a refresh event.
        This would typically be called by an admin tool or rotation Lambda.
        
        Args:
            keys: List of keys to refresh, or None to refresh all
        """
        channel = f"{self._channel_prefix}:secret:refresh"
        payload = json.dumps({"keys": keys})
        
        try:
            self._redis.publish(channel, payload)
            logger.info("Published refresh event to %s: keys=%s", channel, keys)
        except redis.RedisError as e:
            logger.error("Failed to publish refresh event: %s", e)