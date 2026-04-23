from abc import ABC, abstractmethod
from datetime import datetime, UTC, timedelta
from typing import Any, Callable
import logging
import threading

logger = logging.getLogger(__name__)


class SecretsProvider(ABC):
    @abstractmethod
    def get(self, key: str) -> str: ...

    @abstractmethod
    def get_many(self, keys: list[str]) -> dict[str, str]: ...


class RefreshEventSubscriber(ABC):
    @abstractmethod
    def subscribe(self, event: str, handler: Callable[[Any], None]) -> None: ...

    @abstractmethod
    def start() -> None: ...

    @abstractmethod
    def stop() -> None: ...


class SecretManager:
    """
    Runtime secrets holder with local cache and pub/sub invalidation.
    Thread-safe using RLock for concurrent access.

    on_rotation_callbacks: optional dict of routing_key -> callable
        Called AFTER cache is cleared for that routing key.
        The callable receives no arguments — it should call secrets.get()
        internally to retrieve the already-fresh value.
        Callbacks run in the subscriber background thread; dispatch async
        work via asyncio.run_coroutine_threadsafe().
    """

    def __init__(
        self,
        provider: SecretsProvider,
        subscriber: RefreshEventSubscriber | None = None,
        event_name: str = "secret:refresh",
        memory_ttl_seconds: int = 300,
        routing_key_map: dict[str, list[str]] | None = None,
        on_rotation_callbacks: dict[str, Callable[[], None]] | None = None,  # NEW
    ) -> None:
        self._provider = provider
        self._subscriber = subscriber
        self._event_name = event_name
        self._memory_ttl = memory_ttl_seconds
        self._local_cache: dict[str, tuple[str, datetime]] = {}
        self._access_log: list[dict] = []
        self._lock = threading.RLock()
        self._cache_version = 0
        self._routing_key_map = routing_key_map or {}
        self._on_rotation_callbacks = on_rotation_callbacks or {}  # NEW

        if self._subscriber:
            self._subscriber.subscribe(
                event=self._event_name,
                handler=self._handle_refresh_event
            )
            logger.info(
                "SecretsManager initialized with %s + %s subscriber (memory_ttl=%ds)",
                type(provider).__name__, type(subscriber).__name__, memory_ttl_seconds,
            )
        else:
            logger.info(
                "SecretsManager initialized with %s (memory-only ttl=%ds, no subscriber)",
                type(provider).__name__, memory_ttl_seconds,
            )

    def register_rotation_callback(self, routing_key: str, callback: Callable[[], None]) -> None:
        """
        Register (or replace) a post-rotation callback for a routing key.
        Safe to call after construction — useful when the callback depends
        on objects created after the SecretManager itself (e.g. DB engine).
        """
        self._on_rotation_callbacks[routing_key] = callback
        logger.info("Rotation callback registered for routing_key: %s", routing_key)

    def start_subscriber(self) -> None:
        if self._subscriber:
            threading.Thread(target=self._subscriber.start, daemon=True).start()
            logger.info("Subscriber started in background thread")

    def preload(self, keys: list[str]) -> None:
        try:
            secrets = self._provider.get_many(keys)
            now = datetime.now(UTC)
            expires_at = now + timedelta(seconds=self._memory_ttl)
            with self._lock:
                for key, value in secrets.items():
                    self._local_cache[key] = (value, expires_at)
            logger.info("Preloaded %d secrets: %s", len(keys), keys)
        except Exception as e:
            logger.critical(
                "STARTUP FAILED — secret preload error: %s (provider=%s)",
                e, type(self._provider).__name__,
            )
            raise RuntimeError(f"Secrets preload failed: {e}") from e

    def get(self, key: str) -> str:
        now = datetime.now(UTC)
        with self._lock:
            if key in self._local_cache:
                value, expires_at = self._local_cache[key]
                if now < expires_at:
                    self._log_access(key, source="memory")
                    return value
                else:
                    del self._local_cache[key]
                    logger.debug("Memory cache expired for: %s", key)
            version_snapshot = self._cache_version

        try:
            value = self._provider.get(key)
        except PermissionError as e:
            logger.critical(
                "PERMISSION DENIED accessing secret '%s': %s (provider=%s)",
                key, e, type(self._provider).__name__,
            )
            raise
        except Exception as e:
            logger.error(
                "Failed to fetch secret '%s' from provider: %s (provider=%s)",
                key, e, type(self._provider).__name__,
            )
            raise

        expires_at = now + timedelta(seconds=self._memory_ttl)
        with self._lock:
            if self._cache_version == version_snapshot:
                self._local_cache[key] = (value, expires_at)
                logger.info("Lazy-loaded secret from provider: %s", key)
            else:
                logger.debug(
                    "Skipping write-back for '%s', cache was invalidated during fetch", key
                )

        self._log_access(key, source="provider")
        return value

    def refresh(self, keys: list[str] | None = None) -> None:
        with self._lock:
            old_version = self._cache_version
            self._cache_version += 1
            cache_size_before = len(self._local_cache)

            if keys is None:
                cleared_keys = list(self._local_cache.keys())
                self._local_cache.clear()
                logger.warning(
                    "CACHE REFRESH: Cleared ALL %d secrets (v%d→v%d) | Keys: %s",
                    cache_size_before, old_version, self._cache_version, cleared_keys,
                )
            else:
                cleared = [k for k in keys if self._local_cache.pop(k, None)]
                logger.warning(
                    "CACHE REFRESH: Cleared %d/%d secrets (v%d→v%d) | Keys: %s",
                    len(cleared), len(keys), old_version, self._cache_version, cleared,
                )

    def _handle_refresh_event(self, message: Any, routing_key: str = "") -> None:
        try:
            logger.warning("ROTATION EVENT RECEIVED: routing_key=%s payload=%s", routing_key, message)

            # 1. Resolve which cache keys to clear
            if routing_key and routing_key in self._routing_key_map:
                keys = self._routing_key_map[routing_key]
            elif isinstance(message, dict):
                keys = message.get("keys")
            else:
                keys = None

            # 2. Clear cache — from this point secrets.get() fetches fresh from provider
            self.refresh(keys)
            logger.warning("Cache cleared for keys: %s", keys)

            # 3. Fire post-rotation callback (app-defined, runs after cache is clear
            #    so any secrets.get() inside sees fresh values)
            callback = self._on_rotation_callbacks.get(routing_key)
            if callback:
                try:
                    callback()
                    logger.info("Rotation callback completed for: %s", routing_key)
                except Exception as e:
                    logger.error(
                        "Rotation callback failed for routing_key=%s: %s",
                        routing_key, e, exc_info=True,
                    )
            else:
                logger.debug("No rotation callback registered for: %s", routing_key)

        except Exception as e:
            logger.error("Error handling refresh event: %s", e, exc_info=True)

    def clear(self) -> None:
        if self._subscriber:
            try:
                self._subscriber.stop()
                logger.info("Subscriber stopped")
            except Exception as e:
                logger.error("Error stopping subscriber: %s", e)
        with self._lock:
            self._local_cache.clear()
            self._access_log.clear()
        logger.info("SecretsManager fully cleared")

    def _log_access(self, key: str, source: str = "unknown") -> None:
        record = {
            "key": key,
            "source": source,
            "accessed_at": datetime.now(UTC).isoformat(),
        }
        self._access_log.append(record)
        logger.debug("Secret accessed: %s (from %s)", key, source)