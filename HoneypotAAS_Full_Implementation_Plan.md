# Cybersecurity Deception Network for SMBs (Honeypot-as-a-Service)
## Full-Scope Implementation Plan (Backend / Frontend / Integration)

This is the complete architecture and build plan with no scope-cutting — every component described here is meant to actually be built and deployed as a working prototype, not simulated.

> **Status note:** The frontend (Part 2) has been built and is functional against a mock backend — dashboard, session replay, fleet management, blocklist, settings, auth, and the AI Threat Assistant (section 1.11 / 2.2) are all implemented and verified (type-checked, unit-tested, production build passing). The backend (Part 1) and cloud deployment (Part 3) are the build plan below, not yet implemented. Deviations from the original spec are called out inline where they occurred (e.g., TanStack Router instead of React Router v6, Vitest instead of Jest).

---

## SYSTEM OVERVIEW

```
                              ┌─────────────────────────────────────────┐
                              │        ISOLATED HONEYPOT VPC             │
                              │  (no route to real business network)     │
                              │                                           │
   [Attacker traffic] ───────▶│  Cowrie (SSH/Telnet)                     │
                              │  Dionaea (SMB/FTP/MySQL/HTTP)             │
                              │  Custom Fake-WordPress-Admin (Flask)      │
                              │  Custom Fake-RDP listener (asyncio)       │
                              └───────────────┬───────────────────────────┘
                                              │ logs (JSON/syslog)
                                              ▼
                              ┌─────────────────────────────────────────┐
                              │       LOG SHIPPING / QUEUE LAYER          │
                              │  Filebeat/Fluent Bit → Kafka/Redis Streams │
                              └───────────────┬───────────────────────────┘
                                              ▼
                              ┌─────────────────────────────────────────┐
                              │       NORMALIZATION & INGESTION           │
                              │  Consumer service → schema validation →   │
                              │  GeoIP + reputation enrichment            │
                              └───────────────┬───────────────────────────┘
                                              ▼
                    ┌─────────────────────────┴─────────────────────────┐
                    ▼                                                    ▼
        ┌───────────────────────┐                          ┌───────────────────────┐
        │  Postgres + TimescaleDB │                          │   WebSocket Broadcaster │
        │  + pgvector (events,     │                          │   (Socket.IO / native)  │
        │   attackers, sessions,   │                          └───────────┬───────────┘
        │   blocklist, embeddings) │                                      ▼
        └───────────┬─────────────┘                          ┌───────────────────────┐
                    │                                         │   React Dashboard      │
                    ▼                                         │   (live node map,      │
        ┌───────────────────────┐   ┌───────────────────┐    │    event feed, stats,  │
        │  Auto-Response Engine  │   │  AI Threat         │◀──│    Threat Assistant)   │
        │  (rule evaluation)      │   │  Assistant (RAG)   │   └───────────────────────┘
        └───────────┬─────────────┘   │  hybrid retrieval  │
                    ▼                 │  + Claude API       │
        ┌───────────────────────┐    └───────────────────┘
        │  AWS Security Group API │
        │  / pfSense REST API      │
        │  (real network protection)│
        └───────────────────────┘
```

---

## PART 1 — BACKEND IMPLEMENTATION PLAN

### 1.1 Honeypot layer

**Honeypots to deploy (all containerized):**

| Honeypot | Protocol/Service mimicked | Purpose |
|---|---|---|
| Cowrie | SSH (22) + Telnet | Captures brute-force credentials, full shell session logs, malware downloads (wget/curl commands) |
| Dionaea | SMB, FTP, MySQL, HTTP, TFTP | Captures binary payload drops, exploit attempts against legacy protocols |
| Custom `wp-admin` decoy (Flask) | Fake WordPress `/wp-admin` login + fake plugin directory | Captures credential stuffing, common CMS exploit probes (XML-RPC abuse, plugin enumeration) |
| Custom RDP decoy (Python `asyncio`, RDP handshake stub) | RDP (3389) | Captures RDP brute-force scanners (extremely common SMB attack vector — Shodan-indexed scanners hit this constantly) |
| Fake file server (Samba honeypot or Dionaea SMB module) | SMB file share | Captures lateral-movement-style scanning behavior |

**Build steps:**
1. Build each honeypot as its own Docker image, each with resource limits (`--memory`, `--cpus`) and read-only root filesystem where possible, to contain any compromise
2. Configure each honeypot to log structured JSON (Cowrie natively supports this; Dionaea via its JSON log module; custom decoys log JSON directly)
3. Network-isolate the honeypot layer: dedicated Docker bridge network / dedicated AWS VPC with **no peering route to production infrastructure** — this is a hard requirement, not optional, since a honeypot's entire threat model assumes it may be fully compromised
4. Add per-honeypot instance IDs and tags so multi-honeypot deployments (e.g., simulating a whole fake office network) are trackable individually in the dashboard

### 1.2 Infrastructure as Code (Terraform)

**Modules to write:**
- `modules/network` — VPC, isolated subnet for honeypots, separate subnet for backend/DB, NAT gateway, security groups (default-deny, explicit allow rules per honeypot port)
- `modules/honeypot-cluster` — ECS Fargate task definitions (or EC2 Auto Scaling Group) per honeypot type, so honeypots can scale horizontally and be redeployed/rotated automatically (rotating honeypot IPs periodically increases realism and avoids attacker fingerprinting of a static decoy)
- `modules/data-layer` — RDS Postgres instance (with TimescaleDB extension enabled via `shared_preload_libraries`), or self-managed Postgres+Timescale on EC2 if RDS doesn't support the extension in your region
- `modules/messaging` — MSK (managed Kafka) or ElastiCache Redis for the log queue, sized for expected event volume
- `modules/backend` — ECS service or EC2 for the FastAPI app, Application Load Balancer, auto-scaling policy based on CPU/queue depth
- `modules/firewall-integration` — IAM role with least-privilege permissions scoped to Security Group modification only, plus a separate module for pfSense API credentials (stored in Secrets Manager, never in code)
- `modules/observability` — CloudWatch log groups, alarms on honeypot container health, dashboard for infra metrics

**One-click deployment:** wrap `terraform apply` behind a single script/Makefile target (`make deploy`) that provisions the full stack — this directly satisfies the product's own "one-click deployment platform" pitch, so the deployment tooling itself should double as a demo of the core value prop.

### 1.3 Log shipping & queue layer

1. Deploy Filebeat (or Fluent Bit, lighter footprint) as a sidecar container per honeypot, tailing each honeypot's JSON log file
2. Ship to Kafka (MSK) topic `raw-honeypot-events`, partitioned by honeypot type for parallel consumption
3. Reasoning for a queue instead of direct HTTP POST from honeypot → backend: decouples ingestion from honeypot compromise risk (a compromised honeypot container should never hold credentials to write directly into your core database), and buffers traffic spikes during active attack scanning bursts

### 1.4 Normalization & enrichment service

1. Kafka consumer service (Python, `confluent-kafka` or `aiokafka`) that:
   - Validates each raw log line against a JSON schema per honeypot type
   - Normalizes into the unified event schema (below)
   - Enriches with GeoIP (MaxMind GeoLite2 — local DB file, no per-request external call needed) and IP reputation (AbuseIPDB API, cached with TTL to respect rate limits)
   - Deduplicates repeated identical events within a short window (a scanner sending the same payload 50x/sec shouldn't create 50 dashboard events)
2. Writes normalized events to Postgres/TimescaleDB and publishes to a second Kafka topic `normalized-events` for the WebSocket broadcaster to consume

**Unified event schema:**
```json
{
  "id": "uuid",
  "honeypot_id": "cowrie-ssh-01",
  "honeypot_type": "cowrie | dionaea | wp-decoy | rdp-decoy | smb-decoy",
  "attacker_ip": "203.0.113.45",
  "geo": {"country": "XX", "city": "...", "lat": 0, "lon": 0, "asn": "AS...", "org": "..."},
  "reputation": {"abuseipdb_score": 0, "known_malicious": true},
  "event_type": "login_attempt | command_exec | file_download | exploit_probe | port_scan",
  "technique": "brute_force | credential_reuse | payload_drop | cve_exploit_attempt",
  "mitre_attck_id": "T1110 | T1190 | ...",
  "payload": "raw command/credentials/exploit string",
  "session_id": "uuid, links related events in one attack session",
  "timestamp": "ISO8601",
  "severity": "low | medium | high | critical"
}
```

Mapping raw commands/techniques to MITRE ATT&CK IDs is a genuinely strong differentiator for a hackathon judge panel evaluating "Technical Implementation" and "Innovation" — it's a small addition (a lookup table matching Cowrie command patterns to common ATT&CK techniques) with disproportionate credibility payoff.

### 1.5 Database schema (Postgres + TimescaleDB)

- `events` (hypertable, partitioned by `timestamp`) — the raw enriched event stream
- `attackers` — deduplicated by IP, aggregates: first_seen, last_seen, total_events, honeypots_hit, current_block_status
- `sessions` — groups related events from one attacker's continuous interaction (critical for Cowrie session replay in the frontend)
- `blocklist` — ip, blocked_at, expires_at, reason, rule_triggered, action_taken (SG rule ID or pfSense rule ID for auditability/rollback)
- `honeypot_instances` — id, type, deployed_at, region, status, IP address (for the dashboard's "fleet health" view)
- `response_rules` — configurable thresholds (e.g., "3 failed logins/60s → block 24h"), editable from the dashboard settings page
- `events.embedding` — `vector(1536)` column (pgvector) holding the embedded event-summary sentence, IVFFlat/HNSW indexed, used by the Threat Assistant (section 1.11)
- `assistant_conversations` / `assistant_messages` — conversation threads and turns for the Threat Assistant, so multi-turn follow-up questions have context

### 1.6 Backend API (FastAPI)

**REST endpoints:**
- `GET /api/events` — paginated, filterable by honeypot, severity, technique, date range
- `GET /api/events/{session_id}` — full session detail (for replay view)
- `GET /api/attackers` — aggregated attacker list, sortable by threat score
- `GET /api/stats` — dashboard summary metrics
- `GET /api/honeypots` — fleet status
- `POST /api/honeypots/{id}/redeploy` — trigger Terraform-driven redeployment/IP rotation of a specific honeypot
- `GET /api/blocklist`, `POST /api/blocklist/{ip}/unblock` — manual override capability
- `GET /api/rules`, `PUT /api/rules/{id}` — response rule configuration
- `POST /api/auth/login` — JWT-based auth for dashboard access
- `POST /api/assistant/query` — Threat Assistant natural-language query (see section 1.11)

**WebSocket:**
- `/ws/live` — pushes every normalized event the instant it's written, plus periodic stats heartbeat (every 5s) so the dashboard doesn't need to poll

### 1.7 Automated response engine

1. Rule evaluation service subscribes to `normalized-events`, evaluates configurable rules (threshold-based to start; can extend to anomaly scoring later)
2. On rule trigger:
   - Writes to `blocklist` table
   - Calls **AWS Security Group API via boto3** (`revoke`/`authorize` ingress rules on the production-facing SG) — this is the "real network" protection half of the product
   - In parallel, calls **pfSense REST API** (pfSense's `/api/v1/firewall/rule` endpoint) to add a block rule, for SMBs running pfSense as their edge firewall rather than AWS-native networking — supporting both covers the actual heterogeneity of SMB infrastructure
3. Every block has a TTL and an audit trail (who/what triggered it, what rule, when it expires) — this matters both operationally (avoid permanently blocking a legitimate IP that got flagged once) and for the "Impact & Problem Solving" judging criterion, since an SMB owner needs to trust and audit automated actions taken against their network
4. Safety mechanism: maintain an allowlist (office IP ranges, known partner IPs) that the rule engine checks before ever blocking, to prevent self-lockout

### 1.8 Threat intelligence & payload analysis
- Integrate YARA rules against any file/payload dropped into Dionaea's malware capture directory, to auto-flag known malware families
- Optional: sandbox detonation via a service like Cuckoo (heavy — only if scope allows) or simply hash-check dropped files against VirusTotal's free API

### 1.9 Alerting
- Webhook/Slack/email notification on `critical` severity events or on any new block action, so the SMB owner gets pushed alerts without needing to watch the dashboard live

### 1.10 Testing
- Unit tests for schema validation, rule engine logic, enrichment functions
- Integration tests: spin up honeypots in a test compose stack, run scripted attacks (`hydra` against Cowrie SSH, `nmap` service scans against Dionaea, scripted POSTs against the WordPress decoy), assert events flow correctly end-to-end through to the blocklist
- Load test the Kafka→ingestion pipeline with a synthetic event flood to validate it holds up under a real scanning burst (some scanners hit hundreds of times per minute)

### 1.11 AI Threat Assistant (RAG)

A natural-language query interface so an SMB owner (who is not a SOC analyst) can ask plain-English questions about what's happening on their network instead of reading a raw event table. This is a strong "Innovation" and "Impact & Problem Solving" differentiator — it's the difference between "here's a dashboard" and "here's a dashboard that answers questions like a security analyst would."

**Frontend status:** already implemented (`ThreatAssistant.tsx`) — floating chat widget, calls `POST /api/assistant/query`, renders citations linking into session replay. In mock mode it does real retrieval/aggregation over the seeded event store with templated synthesis (`src/lib/assistantRetrieval.ts`), matching the exact response shape the real backend below returns, so no frontend changes are needed once this endpoint exists.

**Retrieval strategy — hybrid, not pure vector search:**
- **Structured path** (fast, exact): questions with a countable/aggregate shape — "how many," "which IPs," "top N," "in the last hour" — are answered by generating a scoped SQL query against `events`/`attackers` (parameterized query templates keyed off parsed intent: IP, honeypot, severity, technique, time window — same intent fields the frontend mock already parses, so the parsing logic is portable to the backend almost as-is)
- **Semantic path** (fuzzy, exploratory): questions like "what's this attacker up to" or "anything unusual today" go through vector similarity search over embedded event summaries
- Most real questions use both: structured filtering to narrow the candidate set, then semantic ranking within it

**Embedding pipeline:**
1. On each normalized event write (section 1.4), also generate a short natural-language summary of the event (e.g., *"203.0.113.45 attempted SSH login with credentials root:toor against cowrie-ssh-01, brute_force technique, MITRE T1110"*) — a template-generated sentence, not the raw payload, since raw payloads are often binary/obfuscated and embed poorly
2. Embed that summary (OpenAI `text-embedding-3-small`, or Bedrock Titan Embeddings if staying AWS-native) and store the vector in a `pgvector` column on the `events` table (`ALTER TABLE events ADD COLUMN embedding vector(1536)`, IVFFlat or HNSW index) — this avoids standing up a separate vector database; pgvector on the same TimescaleDB instance is enough at hackathon/SMB scale
3. Also embed a rolling per-attacker summary (updated periodically, not per-event) for "what's this attacker's overall pattern" questions without re-embedding every historical event

**Query-time flow (`POST /api/assistant/query`):**
1. Parse the question for structured intent (regex/keyword extraction, same logic as the frontend mock) — IP, honeypot, severity, technique, time window
2. Run the structured filter to get a candidate event set
3. Embed the question itself, run pgvector cosine-similarity search scoped to that candidate set (`ORDER BY embedding <=> $query_embedding LIMIT 8`) to rank by relevance rather than just recency
4. Assemble a grounding context from the top-K retrieved events/summaries plus any relevant aggregate stats
5. Call the **Claude API** (Anthropic) with the question + grounding context, explicit system instructions to **answer only from the provided context and cite specific event IDs it used** — this is the anti-hallucination discipline that makes the feature trustworthy rather than a toy; if nothing relevant was retrieved, the model should say so rather than guess
6. Return `{ conversation_id, message: { content, citations }, retrieved_event_count }` — citations carry `event_id`/`session_id`/`attacker_ip` so the frontend can deep-link into session replay (already wired)

**Conversation state:** store conversation turns in Postgres (`assistant_conversations`, `assistant_messages`) keyed by `conversation_id`, so multi-turn follow-ups ("what about just the critical ones?") can reference prior turns — pass the last 2-3 turns back to Claude as conversation history alongside the fresh retrieval.

**Endpoint contract:**
```
POST /api/assistant/query
{ "question": "what's hit the RDP decoy in the last hour?", "conversation_id": "uuid | omit for new thread" }

→ 200 OK
{
  "conversation_id": "uuid",
  "retrieved_event_count": 4,
  "message": {
    "id": "uuid",
    "role": "assistant",
    "content": "4 events in the last hour, all against rdp-decoy-01, from 3 distinct IPs...",
    "citations": [
      { "label": "critical · rdp-decoy-01 · 198.51.100.7", "event_id": "...", "session_id": "...", "attacker_ip": "198.51.100.7" }
    ],
    "created_at": "ISO8601"
  }
}
```

**Cost/latency guardrails:** cache embeddings (never re-embed an unchanged event), rate-limit assistant queries per session, cap retrieved context size, and set a hard timeout with a graceful "couldn't answer in time, here's the raw filtered event list instead" fallback so the assistant degrades gracefully rather than hanging the UI.

**Backend tech stack:** Python (FastAPI, `aiokafka`/`confluent-kafka`, boto3, SQLAlchemy), Cowrie, Dionaea, Flask (decoy services), Postgres + TimescaleDB + pgvector, Kafka (AWS MSK) or Redis Streams, Docker/ECS Fargate, Terraform, MaxMind GeoLite2, AbuseIPDB API, pfSense REST API, Anthropic Claude API (Threat Assistant), OpenAI/Bedrock embeddings

---

## PART 2 — FRONTEND IMPLEMENTATION PLAN

### 2.1 Application structure
- React + TypeScript + Vite
- Routing: **TanStack Router** (file-based, via TanStack Start) — `/login`, `/dashboard`, `/honeypots`, `/attackers`, `/sessions/:id`, `/blocklist`, `/settings`. *(Deviation from original spec of React Router v6 + plain SPA — functionally equivalent, adds file-based routing and an SSR-capable server entry. Flagged, not a blocker.)*
- State/data: TanStack Query for REST data fetching/caching, Zustand for local UI state, a dedicated WebSocket context provider (`LiveEventsProvider`) for the live event stream
- Styling: Tailwind CSS, dark theme by default (SOC dashboards are conventionally dark for a reason — extended monitoring use and threat-color contrast)

**Build status: implemented.** All pages below exist, type-check cleanly, and pass a production build.

### 2.2 Core pages/components

**Live Threat Map (main dashboard, primary visual)**
- Cytoscape.js force-directed graph: central node cluster = "Your Honeypot Network," each active attacker = a node, edges to the honeypot(s) they've touched
- Node sizing scales with event count from that IP; node color scales with severity (green→amber→red)
- New nodes animate in (pulse effect) on WebSocket event arrival
- Click a node → side panel with that attacker's full profile (geo, reputation score, techniques used, session list)

**Live Event Feed**
- Reverse-chronological scrolling list, virtualized (react-window) since volume can get high during active scans
- Color-coded rows by severity, filterable by honeypot/technique inline

**Attack Session Replay**
- For Cowrie sessions specifically: render the captured shell session as a terminal replay (Cowrie logs full TTY input) — this is a strong demo moment, literally showing judges an attacker's live typed commands in a fake shell
- Use `xterm.js` to render captured session logs as a scrubbable terminal playback

**Stats & Analytics Panel**
- Recharts: attacks/hour time series (via TimescaleDB continuous aggregates), top attacking countries (choropleth or simple bar), top techniques (mapped to MITRE ATT&CK categories), honeypot-by-honeypot hit breakdown

**Fleet Management Page**
- Table of deployed honeypots, health status, uptime, "redeploy/rotate IP" button wired to `POST /api/honeypots/{id}/redeploy`

**Blocklist & Response Page**
- Table of currently blocked IPs, rule that triggered each, expiry countdown, manual unblock action, full audit log
- Response rule editor: form-based UI to adjust thresholds without redeploying backend code

**Settings**
- Alert channel configuration (Slack webhook URL, email), allowlist management, API key for pfSense/AWS credentials entry (never displayed again after save — write-only field)

**AI Threat Assistant (implemented — `ThreatAssistant.tsx`)**
- Floating chat widget, bottom-right, expandable panel with suggested starter questions
- Natural-language query parsing (IP, honeypot, severity, technique, relative time window) done client-side in mock mode (`src/lib/assistantRetrieval.ts`), server-side once the backend endpoint exists — same intent-extraction logic ports directly (see section 1.11)
- Answers include citations that deep-link into session replay (`/sessions/:id`) or select the attacker on the dashboard graph, so every claim the assistant makes is independently verifiable rather than trusted blindly
- Mounted globally in `AppShell` so it's available from every authenticated page, not just the dashboard

### 2.3 Real-time integration
- Single WebSocket connection established on dashboard mount, reconnect-with-backoff logic for resilience
- Incoming events update: Cytoscape graph state, event feed list (prepend), stats panel counters — all driven off one event stream via a pub/sub pattern inside the WebSocket context, so components subscribe only to what they need

### 2.4 Auth
- JWT-based login page, token stored in memory (not localStorage, to reduce XSS token-theft risk — a nice detail for a *security product's own* frontend to get right) with refresh-token rotation via httpOnly cookie
- **Implemented:** `requireAuth` beforeLoad guard on every protected route (`/dashboard`, `/attackers`, `/blocklist`, `/honeypots`, `/settings`, `/sessions/:id`), redirecting unauthenticated visitors to `/login` with a `?redirect=` param so they land back on their intended destination after signing in

### 2.5 Testing
- Component/unit tests: **Vitest** (not Jest — the project already ships Vitest as a dependency, so kept it rather than adding a second test runner) covering pure logic: graph model state updates (`graphModel.test.ts`), event feed filtering (`severity.test.ts`), and Threat Assistant intent parsing/retrieval (`assistantRetrieval.test.ts`) — 26 tests, all passing
- E2E: **Playwright**, one spec covering login → live event appears in the feed → click opens the attacker detail panel, plus an unauthenticated-redirect check

**Frontend tech stack:** React, TypeScript, Vite, Tailwind, TanStack Router/Start, Cytoscape.js, xterm.js, Recharts, TanStack Query, Zustand, Zod, native WebSocket client, Vitest + Testing Library, Playwright

---

## PART 3 — INTEGRATION PLAN

### 3.1 Contract-first development
Lock and version the unified event schema (section 1.4) and the full OpenAPI spec for the REST API before deep implementation on either side — generate the OpenAPI spec directly from FastAPI (`/openapi.json`) and use `openapi-typescript` to auto-generate TypeScript types for the frontend, so the two sides can never silently drift out of sync. The frontend's `src/types/api.ts` (including the `AssistantMessage`/`AssistantQueryRequest`/`AssistantQueryResponse` types for section 1.11) is the reference contract the backend should match exactly.

### 3.1a Threat Assistant integration
The frontend's mock-mode assistant (`src/lib/assistantRetrieval.ts`) already implements the intent-parsing half of section 1.11's retrieval strategy in TypeScript. When the real backend endpoint lands, port that same parsing logic to Python (or keep parsing client-side and send the parsed intent alongside the raw question, so the backend doesn't have to re-derive it) — either way, avoid diverging the two implementations, since inconsistent parsing between mock and live mode would make the demo behave differently depending on `VITE_USE_MOCK_BACKEND`.

### 3.2 Local development environment
- Single `docker-compose.yml` at the repo root spinning up: all honeypots, Kafka/Redis, Postgres+Timescale, backend API, frontend dev server
- `.env.example` documenting every required secret (AWS keys, pfSense API creds, AbuseIPDB key, MaxMind license key)
- Seed script to populate the dashboard with historical synthetic events for demo/screenshot purposes without needing to wait for real attack traffic

### 3.3 Cloud deployment topology
- Honeypot layer: isolated VPC, Fargate tasks, public IPs intentionally exposed (that's the point — they need to be discoverable/attackable)
- Backend: private subnet, behind an ALB, only reachable from the frontend and from the honeypot VPC's Kafka topic (no direct honeypot→backend network path — everything flows through the queue)
- Database: private subnet, RDS with automated backups, TimescaleDB retention policy (e.g., auto-drop raw events after 90 days, keep aggregates indefinitely)
- Frontend: static build deployed to S3 + CloudFront (or Vercel for simplicity), calling the backend ALB over HTTPS
- All secrets (pfSense creds, AWS creds for SG modification, API keys) in AWS Secrets Manager, injected as environment variables at container start — never committed to the repo

### 3.4 CI/CD pipeline
- GitHub Actions:
  - On PR: run backend unit/integration tests, frontend component tests, lint both
  - On merge to `main`: build and push Docker images to ECR, run `terraform plan` (manual approval gate for `apply` on infra changes), deploy backend to ECS, deploy frontend build to S3/CloudFront
  - Separate scheduled workflow: run the full attack-simulation integration test suite nightly against the staging environment, alert if the pipeline breaks silently

### 3.5 Security considerations specific to integration
- The honeypot layer must be treated as **always potentially compromised** — the queue-based, one-directional data flow (honeypot → Filebeat → Kafka → consumer) with no credentials or write access from the honeypot side into the core database is the key architectural decision that makes this safe
- Rate-limit and validate everything the normalization service accepts from Kafka, since a sophisticated attacker who fingerprints a honeypot may attempt to inject malformed data to attack the ingestion pipeline itself
- The Security Group / pfSense API credentials used by the response engine should be scoped to the absolute minimum permission (only modify specific rule sets, never full account access)

### 3.6 End-to-end validation plan
1. Deploy full stack to a staging AWS account
2. Run scripted attacks against each honeypot type from an external test box (outside the VPC, simulating a real internet attacker): Hydra brute force against Cowrie, `nmap`/`curl` probes against Dionaea services, scripted login POSTs against the WordPress decoy, RDP connection attempts against the RDP decoy
3. Verify, for each: event appears in the dashboard within ~1-2 seconds (log → Kafka → normalize → DB → WebSocket → UI render), attacker node appears/updates correctly on the graph, session replay works for the Cowrie case, and the auto-block threshold correctly triggers and the resulting Security Group / pfSense rule is verifiably in place (test that the same attacker IP is now actually refused)
4. Verify unblock/expiry path: manually unblock via dashboard, confirm the SG/pfSense rule is removed

### 3.7 Documentation & demo assets
- Architecture diagram (the one at the top of this doc, cleaned up) for the deck
- A recorded demo video showing the full loop (attack → dashboard visualization → auto-block → verified network protection) as insurance against live-demo flakiness, in addition to a live run if conditions allow
- README with one-command local setup (`make dev`) and one-command cloud deploy (`make deploy`), directly demonstrating the "one-click deployment" product claim

### 3.8 Build phases (sequenced, not time-boxed)

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Frontend built against mock backend: all pages, auth guard, tests, AI Threat Assistant (mock-mode retrieval) | ✅ Done |
| 1 | Honeypots running locally in Docker Compose, logging structured JSON | Not started |
| 2 | Log shipping + Kafka + normalization service writing enriched events to Postgres | Not started |
| 3 | Backend REST API + WebSocket broadcaster, event schema finalized and typed on both sides | Not started |
| 4 | Frontend rewired from mock to live WebSocket (flip `VITE_USE_MOCK_BACKEND`) | Not started |
| 5 | Auto-response engine (rule evaluation → AWS SG + pfSense API calls) + blocklist UI | Not started |
| 6 | Session replay data source switched to real Cowrie sessions, MITRE ATT&CK mapping, threat intel enrichment | Not started |
| 7 | AI Threat Assistant backend: pgvector embeddings, hybrid retrieval, Claude API grounding (section 1.11) | Not started |
| 8 | Terraform full cloud deployment, CI/CD pipeline, staging environment | Not started |
| 9 | End-to-end attack simulation validation, security hardening pass, documentation, demo recording | Not started |
