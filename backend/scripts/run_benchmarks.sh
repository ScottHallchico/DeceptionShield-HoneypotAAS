#!/bin/bash
set -e

echo "============================================================"
echo " HoneypotAAS - Performance & Load Validation Script"
echo "============================================================"
echo "This script executes load tests to validate the trueness of"
echo "the performance claims in the architecture code review."
echo "============================================================"
echo ""

# Ensure we are in the backend directory
cd "$(dirname "$0")/.."

echo "[*] Step 1: Checking if backend services are running..."
if ! curl -s http://localhost:8000/api/stats > /dev/null; then
    echo "    Error: The FastAPI backend does not seem to be running on port 8000."
    echo "    Please run 'make dev' in another terminal first."
    exit 1
fi
echo "    Backend is healthy!"
echo ""

echo "[*] Step 2: REST API Load Testing (via wrk)"
echo "    Executing 100 concurrent connections for 10 seconds against the Event Retrieval endpoint."
echo "    This tests the FastAPI asynchronous throughput and TimescaleDB read speed."
# We use docker to run wrk so you don't need to install it locally
docker run --rm --network host williamyeh/wrk -t4 -c100 -d10s http://localhost:8000/api/events
echo ""

echo "[*] Step 3: Analytics Endpoint Load Testing"
echo "    Executing 100 concurrent connections for 10 seconds against the Stats endpoint."
docker run --rm --network host williamyeh/wrk -t4 -c100 -d10s http://localhost:8000/api/stats
echo ""

echo "[*] Step 4: Kafka Ingestion Throughput Test"
echo "    Generating 10,000 synthetic attack logs and flooding the Kafka queue."
echo "    [Kafka Setup] Ensuring topic exists..."
docker exec backend_kafka_1 kafka-topics --create --topic raw-honeypot-events --bootstrap-server kafka:29092 --partitions 1 --replication-factor 1 --if-not-exists 2>/dev/null || true

cat << 'EOF' > scripts/kafka_benchmark.py
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
EOF

# Run the python script
.venv/bin/python scripts/kafka_benchmark.py
echo ""

echo "[*] Step 5: TimescaleDB Hypertable Verification"
echo "    Validating that the 'events' table is properly partitioned by time."
# Find the DB container dynamically
DB_CONTAINER=$(docker ps -qf "ancestor=timescale/timescaledb-ha:pg16")
if [ -n "$DB_CONTAINER" ]; then
    docker exec -t "$DB_CONTAINER" psql -U postgres -d honeypotaas -c "SELECT hypertable_name, num_chunks FROM timescaledb_information.hypertables;"
else
    echo "    Warning: Could not find the TimescaleDB container to verify hypertables."
fi

echo ""
echo "============================================================"
echo " Validation Complete."
echo "============================================================"
