.PHONY: dev deploy test lint seed clean

# ── Local Development ─────────────────────────────────────────
dev:
	docker compose up -d postgres kafka zookeeper
	@echo "Waiting for services..."
	@sleep 5
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

dev-full:
	docker compose up -d

dev-down:
	docker compose down

# ── Database ──────────────────────────────────────────────────
db-migrate:
	cd backend && alembic upgrade head

db-seed:
	cd backend && python -m scripts.seed_data 500

db-reset:
	docker compose down -v
	docker compose up -d postgres
	@sleep 3
	$(MAKE) db-migrate
	$(MAKE) db-seed

# ── Testing ───────────────────────────────────────────────────
test:
	cd backend && python -m pytest tests/ -v --tb=short

test-unit:
	cd backend && python -m pytest tests/unit/ -v --tb=short

test-cov:
	cd backend && python -m pytest tests/ -v --cov=app --cov-report=term-missing

# ── Code Quality ──────────────────────────────────────────────
lint:
	cd backend && ruff check app/ tests/

format:
	cd backend && ruff format app/ tests/

typecheck:
	cd backend && mypy app/ --ignore-missing-imports

# ── Cloud Deployment ──────────────────────────────────────────
deploy:
	cd backend/terraform && terraform init && terraform apply -auto-approve

plan:
	cd backend/terraform && terraform plan

# ── Utilities ─────────────────────────────────────────────────
clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
