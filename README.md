# HoneypotAAS — Cybersecurity Deception Network for SMBs

A full-stack honeypot-as-a-service platform that deploys decoy servers to attract and analyze attacker behavior, automatically blocking threats across your real network infrastructure.

## Architecture

```
Attacker → Honeypots (isolated VPC) → Filebeat → Kafka → Normalizer → Postgres+TimescaleDB
                                                                          ↓
                                                              FastAPI REST + WebSocket → React Dashboard
                                                              Auto-Response Engine → AWS SG / pfSense
                                                              AI Threat Assistant (RAG) → Claude API
```

## Quick Start

### Local Development

```bash
# 1. Copy environment variables
cp backend/.env.example backend/.env

# 2. Start infrastructure (Postgres + Kafka) and API
make dev

# 3. Seed demo data (in another terminal)
make db-seed

# 4. Run tests
make test
```

### Full Stack (Docker Compose)

```bash
make dev-full
```

### One-Click Cloud Deploy

```bash
make deploy
```

## Backend API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | JWT authentication |
| GET | `/api/events` | Paginated, filterable events |
| GET | `/api/events/{session_id}` | Session detail (for replay) |
| GET | `/api/attackers` | Aggregated attacker list |
| GET | `/api/stats` | Dashboard summary metrics |
| GET | `/api/honeypots` | Fleet status |
| POST | `/api/honeypots/{id}/redeploy` | Trigger IP rotation |
| GET | `/api/blocklist` | Blocked IPs with audit trail |
| POST | `/api/blocklist/{ip}/unblock` | Manual unblock |
| GET | `/api/rules` | Auto-response rules |
| PUT | `/api/rules/{id}` | Update rule thresholds |
| POST | `/api/assistant/query` | AI Threat Assistant |
| WS | `/ws/live` | Real-time event stream |

## Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy, aiokafka
- **Database**: PostgreSQL + TimescaleDB + pgvector
- **Queue**: Apache Kafka
- **Honeypots**: Cowrie (SSH), Dionaea (SMB/FTP), Custom Flask (WordPress), Custom asyncio (RDP)
- **AI**: Claude API (Anthropic) + OpenAI embeddings for RAG
- **Infra**: Docker, Terraform, AWS (ECS/SG), pfSense
- **Enrichment**: MaxMind GeoIP, AbuseIPDB, MITRE ATT&CK mapping

## Project Structure

```
backend/
├── app/
│   ├── api/
│   │   ├── routes/          # REST endpoints
│   │   └── websocket/       # WebSocket broadcaster
│   ├── core/                # Config, auth, logging
│   ├── db/                  # Database session
│   ├── models/              # SQLAlchemy ORM models
│   ├── schemas/             # Pydantic validation schemas
│   └── services/
│       ├── enrichment/      # GeoIP, reputation, MITRE, normalizer, stats
│       ├── response_engine/ # Auto-block rules + AWS SG / pfSense
│       ├── assistant/       # RAG: intent parsing, retrieval, Claude API
│       └── log_shipping/    # Kafka consumer
├── honeypots/               # Docker images for each honeypot type
├── scripts/                 # DB init, Filebeat config, seed data
├── tests/                   # Unit and integration tests
└── terraform/               # Infrastructure as Code
```
