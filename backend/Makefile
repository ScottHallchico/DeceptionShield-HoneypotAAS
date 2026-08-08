.PHONY: dev test lint format db-reset db-seed

dev:
	docker-compose up -d

test:
	pytest tests/unit/ -v

lint:
	ruff check app/ tests/
	mypy app/

format:
	ruff format app/ tests/

db-reset:
	docker-compose down -v --remove-orphans
	docker-compose rm -f
	docker-compose up -d db zookeeper kafka
	sleep 5
	PYTHONPATH=. .venv/bin/alembic upgrade head
	PYTHONPATH=. .venv/bin/python scripts/seed_data.py

db-seed:
	python scripts/seed_data.py
