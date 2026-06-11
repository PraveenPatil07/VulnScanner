.PHONY: install dev build test clean podman-up podman-down dev-worker dev-redis

install:
	cd backend && pip install -r requirements.txt -r requirements-dev.txt
	cd frontend && npm ci

dev-redis:
	podman run --rm --name cvs-redis -p 6379:6379 docker.io/library/redis:7-alpine

dev-backend:
	uvicorn backend.main:app --reload --reload-dir backend --reload-exclude backend/venv --host 0.0.0.0 --port 8000

dev-worker:
	celery -A backend.celery_app:celery_app worker --loglevel=info -Q scans,reports --concurrency=2 --pool=solo

dev-frontend:
	cd frontend && npm run dev

build:
	cd frontend && npm run build

test:
	cd backend && pytest -v

clean:
	rm -rf storage/*
	rm -rf frontend/dist
	find backend -type d -name __pycache__ -exec rm -rf {} +

podman-up:
	podman compose up --build -d

podman-down:
	podman compose down
