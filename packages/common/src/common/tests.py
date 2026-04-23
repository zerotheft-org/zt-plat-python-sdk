"""
Test script to demonstrate thread-safety and pub/sub functionality
"""

import os
import time
import threading
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)s] %(levelname)s: %(message)s'
)

# Mock environment secrets
os.environ["database/password"] = "secret123"
os.environ["api/key"] = "key456"

from common.secrets.providers.env import EnvSecretsProvider
from common.secrets.manager import SecretManager


def test_thread_safety():
    """
    Test that concurrent get() and refresh() operations are thread-safe.
    """
    print("\n=== Testing Thread Safety ===\n")
    
    provider = EnvSecretsProvider()
    manager = SecretManager(provider, memory_ttl_seconds=10)
    manager.preload(["database/password"])
    
    results = {"memory": 0, "provider": 0}
    errors = []
    
    def reader_thread(thread_id: int):
        """Continuously read secrets"""
        for i in range(50):
            try:
                value = manager.get("database/password")
                log = manager._access_log[-1]
                results[log["source"]] += 1
                time.sleep(0.01)
            except Exception as e:
                errors.append(f"Thread {thread_id}: {e}")
    
    def refresh_thread():
        """Periodically refresh cache"""
        time.sleep(0.1)  # Let readers start
        for i in range(5):
            manager.refresh(["database/password"])
            logging.info("Cache refreshed")
            time.sleep(0.2)
    
    threads = []
    for i in range(5):
        t = threading.Thread(target=reader_thread, args=(i,), name=f"Reader-{i}")
        threads.append(t)
        t.start()
    
    refresh = threading.Thread(target=refresh_thread, name="Refresher")
    threads.append(refresh)
    refresh.start()
    
    for t in threads:
        t.join()
    
    print(f"\nResults:")
    print(f"  Cache hits (memory): {results['memory']}")
    print(f"  Cache misses (provider): {results['provider']}")
    print(f"  Errors: {len(errors)}")
    
    if errors:
        print("\nErrors encountered:")
        for err in errors:
            print(f"  - {err}")
    else:
        print("\n✅ No race conditions detected!")


def test_redis_pubsub_integration():
    """
    Test Redis pub/sub integration (requires Redis running).
    """
    print("\n=== Testing Redis Pub/Sub Integration ===\n")
    
    try:
        import redis
        redis_client = redis.from_url("redis://localhost:6379", decode_responses=False)
        redis_client.ping()
    except Exception as e:
        print(f"⚠️  Redis not available, skipping Redis pub/sub test: {e}")
        return
    
    from common.secrets.subscribers.redis_subscriber import RedisRefreshSubscriber
    
    provider = EnvSecretsProvider()
    subscriber = RedisRefreshSubscriber(redis_client)
    manager = SecretManager(provider, subscriber=subscriber, memory_ttl_seconds=60)
    manager.preload(["database/password", "api/key"])
    manager.start_subscriber()
    
    print("Subscriber started, waiting for events...")
    time.sleep(1)
    
    initial_value = manager.get("database/password")
    print(f"Initial value from cache: {initial_value}")
    
    print("\nPublishing refresh event...")
    subscriber.publish_refresh(keys=["database/password"])
    time.sleep(0.5)
    
    os.environ["database/password"] = "new_secret_789"
    
    new_value = manager.get("database/password")
    print(f"Value after refresh: {new_value}")
    
    if new_value == "new_secret_789":
        print("\n✅ Redis pub/sub invalidation working!")
    else:
        print("\n❌ Cache was not invalidated")
    
    manager.clear()
    redis_client.close()

    # Reset for next test
    os.environ["database/password"] = "secret123"


def test_rabbitmq_pubsub_integration():
    """
    Test RabbitMQ pub/sub integration with routing_key_map (requires RabbitMQ running).
    Verifies that only the affected secret is cleared when a rotation event arrives.
    """
    print("\n=== Testing RabbitMQ Pub/Sub Integration ===\n")

    try:
        import pika
        credentials = pika.PlainCredentials('guest', 'guest')
        params = pika.ConnectionParameters(host="localhost", port=5672, credentials=credentials)
        conn = pika.BlockingConnection(params)
        conn.close()
    except Exception as e:
        print(f"⚠️  RabbitMQ not available, skipping RabbitMQ pub/sub test: {e}")
        return

    from common.secrets.subscribers.rabbitmq_subscriber import RabbitMQRefreshSubscriber

    # Single source of truth — mirrors what the service defines in main.py
    routing_key_map = {
        "rotation.db":  ["database/password"],
        "rotation.api": ["api/key"],
    }

    provider = EnvSecretsProvider()
    subscriber = RabbitMQRefreshSubscriber(
        username="guest",
        password="guest",
        host="localhost",
        port=5672,
        exchange="secrets",
        routing_keys=list(routing_key_map.keys()),  # ["rotation.db", "rotation.api"]
    )
    manager = SecretManager(
        provider,
        subscriber=subscriber,
        memory_ttl_seconds=60,
        routing_key_map=routing_key_map,
    )

    preload_keys = [key for keys in routing_key_map.values() for key in keys]
    manager.preload(preload_keys)
    manager.start_subscriber()

    print("Subscriber started, waiting for events...")
    time.sleep(1)  # allow queue declaration and binding

    print(f"Cached keys before rotation: {list(manager._local_cache.keys())}")

    print("\nPublishing rotation.db event (should only clear database/password)...")
    subscriber.publish_refresh(routing_key="rotation.db")
    time.sleep(0.5)

    db_cleared = "database/password" not in manager._local_cache
    api_intact = "api/key" in manager._local_cache

    print(f"  database/password cleared: {db_cleared}")
    print(f"  api/key untouched:         {api_intact}")

    if db_cleared and api_intact:
        print("\n✅ Targeted cache invalidation working!")
    else:
        print("\n❌ Cache invalidation did not behave as expected")

    # Verify lazy re-fetch picks up new value
    os.environ["database/password"] = "new_secret_rabbitmq"
    new_value = manager.get("database/password")
    print(f"\nLazy re-fetch after rotation: {new_value}")

    if new_value == "new_secret_rabbitmq":
        print("✅ Fresh value fetched from provider after invalidation!")
    else:
        print("❌ Stale value returned")

    manager.clear()
    os.environ["database/password"] = "secret123"


def test_startup_failure():
    """
    Test that missing secrets cause startup failure.
    """
    print("\n=== Testing Startup Failure ===\n")
    
    provider = EnvSecretsProvider()
    manager = SecretManager(provider)
    
    try:
        manager.preload(["nonexistent/secret"])
        print("❌ Should have raised RuntimeError!")
    except RuntimeError as e:
        print(f"✅ Correctly failed with: {e}")


if __name__ == "__main__":
    test_thread_safety()
    test_redis_pubsub_integration()
    test_rabbitmq_pubsub_integration()
    test_startup_failure()
    
    print("\n=== All Tests Complete ===\n")