-- HoneypotAAS Database Initialization
-- Enables required Postgres extensions and creates the TimescaleDB hypertable.

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";       -- pgvector for RAG embeddings
CREATE EXTENSION IF NOT EXISTS "timescaledb";   -- TimescaleDB for time-series events

-- Note: Table creation is handled by Alembic migrations (SQLAlchemy models).
-- This script only ensures extensions are available before migrations run.

-- Create the events hypertable after the table exists
-- (This should be run after the first Alembic migration)
-- SELECT create_hypertable('events', 'timestamp', if_not_exists => TRUE);
