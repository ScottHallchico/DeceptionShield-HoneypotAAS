import asyncio
import time
import json
import uuid
from datetime import datetime, timezone
from aiokafka import AIOKafkaProducer

async def flood_kafka():
    # Adding a short delay to ensure topic is fully registered
    await asyncio.sleep(2)
    producer = AIOKafkaProducer(bootstrap_servers='localhost:9092')
    await producer.start()
    try:
        print("    [Kafka Producer] Starting flood...")
        start_time = time.time()
        for i in range(10000):
            event = {
                "event_type": "login_attempt",
                "honeypot_type": "cowrie",
                "attacker_ip": f"192.168.1.{i % 255}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": str(uuid.uuid4())
            }
            # send_and_wait ensures durability; using just send() would be even faster
            await producer.send_and_wait("raw-honeypot-events", json.dumps(event).encode('utf-8'))
        end_time = time.time()
        duration = end_time - start_time
        print(f"    [Kafka Producer] Successfully produced 10,000 events in {duration:.2f} seconds.")
        print(f"    [Kafka Producer] Throughput: {10000 / duration:.2f} messages/sec")
    finally:
        await producer.stop()

asyncio.run(flood_kafka())
