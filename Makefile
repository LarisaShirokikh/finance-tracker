# Makefile for Finance Tracker development

.PHONY: help install test test-unit test-integration test-auth test-cov lint format type-check run dev docker-up docker-down clean

# Default target
help:
	@echo "Finance Tracker Development Commands"
	@echo "=================================="
	@echo ""
	@echo "Setup:"
	@echo "  install     Install dependencies with Poetry"
	@echo "  install-dev Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test        Run all tests"
	@echo "  test-unit   Run only unit tests (fast)"
	@echo "  test-integration  Run only integration tests" 
	@echo "  test-auth   Run only authentication tests"
	@echo "  test-redis  Run only Redis tests"
	@echo "  test-cov    Run tests with coverage report"
	@echo "  test-watch  Run tests in watch mode"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint        Run all linters (flake8, mypy, isort check)"
	@echo "  format      Format code (black, isort)"
	@echo "  type-check  Run type checking with mypy"
	@echo "  security    Run security checks"
	@echo ""
	@echo "Development:"
	@echo "  run         Run FastAPI development server"
	@echo "  dev         Run with auto-reload and debug"
	@echo "  shell       Start Python shell with app context"
	@echo ""
	@echo "Docker:"
	@echo "  docker-up   Start all services (PostgreSQL, Redis, Keycloak)"
	@echo "  docker-down Stop all services"
	@echo "  docker-logs Show service logs"
	@echo ""
	@echo "Utilities:"
	@echo "  clean       Clean cache and temporary files"
	@echo "  deps        Show dependency tree"
	@echo "  outdated    Show outdated packages"

# =============================================================================
# SETUP
# =============================================================================

install:
	@echo "📦 Installing dependencies..."
	poetry install

install-dev:
	@echo "📦 Installing development dependencies..."
	poetry install --with dev
	poetry run pre-commit install

# =============================================================================
# TESTING
# =============================================================================

test:
	@echo "🧪 Running all tests..."
	poetry run pytest

test-unit:
	@echo "🧪 Running unit tests..."
	poetry run pytest -m unit

test-integration:
	@echo "🧪 Running integration tests..."
	poetry run pytest -m integration

test-auth:
	@echo "🧪 Running authentication tests..."
	poetry run pytest -m auth

test-redis:
	@echo "🧪 Running Redis tests..."
	poetry run pytest -m redis

test-api:
	@echo "🧪 Running API tests..."
	poetry run pytest -m api

test-security:
	@echo "🧪 Running security tests..."
	poetry run pytest -m security

test-cov:
	@echo "🧪 Running tests with coverage..."
	poetry run pytest --cov=app --cov-report=html --cov-report=term-missing
	@echo "📊 Coverage report generated in htmlcov/"

test-watch:
	@echo "🧪 Running tests in watch mode..."
	poetry run ptw -- --testmon

test-parallel:
	@echo "🧪 Running tests in parallel..."
	poetry run pytest -n auto

test-fast:
	@echo "🧪 Running fast tests only..."
	poetry run pytest -m "not slow"

test-slow:
	@echo "🧪 Running slow tests only..."
	poetry run pytest -m slow

# =============================================================================
# CODE QUALITY
# =============================================================================

lint:
	@echo "🔍 Running linters..."
	poetry run flake8 app tests
	poetry run mypy app
	poetry run isort --check-only app tests

format:
	@echo "✨ Formatting code..."
	poetry run black app tests
	poetry run isort app tests

type-check:
	@echo "🔍 Running type checks..."
	poetry run mypy app

security:
	@echo "🔒 Running security checks..."
	poetry run bandit -r app/

pre-commit:
	@echo "🔍 Running pre-commit hooks..."
	poetry run pre-commit run --all-files

# =============================================================================
# DEVELOPMENT
# =============================================================================

run:
	@echo "🚀 Starting FastAPI server..."
	poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000

dev:
	@echo "🚀 Starting development server with auto-reload..."
	poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --log-level debug

shell:
	@echo "🐍 Starting Python shell..."
	poetry run python

# =============================================================================
# DOCKER
# =============================================================================

docker-up:
	@echo "🐳 Starting all services..."
	docker-compose up -d postgres keycloak_postgres redis keycloak
	@echo "⏳ Waiting for services to be ready..."
	sleep 10
	@echo "✅ Services started!"
	@echo "📊 Redis UI: http://localhost:8081 (admin/admin123)"
	@echo "🔐 Keycloak: http://localhost:8080 (admin/admin_password_dev)"

docker-down:
	@echo "🐳 Stopping all services..."
	docker-compose down

docker-logs:
	@echo "📋 Showing service logs..."
	docker-compose logs -f

docker-redis:
	@echo "🔴 Starting Redis only..."
	docker-compose up -d redis

docker-keycloak:
	@echo "🔐 Starting Keycloak only..."
	docker-compose up -d postgres keycloak_postgres keycloak

docker-clean:
	@echo "🧹 Cleaning Docker resources..."
	docker-compose down -v
	docker system prune -f

# =============================================================================
# DATABASE
# =============================================================================

db-upgrade:
	@echo "📈 Running database migrations..."
	poetry run alembic upgrade head

db-downgrade:
	@echo "📉 Rolling back database migration..."
	poetry run alembic downgrade -1

db-migration:
	@echo "📝 Creating new migration..."
	@read -p "Migration message: " message; \
	poetry run alembic revision --autogenerate -m "$$message"

db-reset:
	@echo "⚠️  Resetting database..."
	@echo "This will delete all data! Press Ctrl+C to cancel."
	@sleep 5
	docker-compose down -v postgres
	docker-compose up -d postgres
	sleep 5
	poetry run alembic upgrade head

# =============================================================================
# UTILITIES
# =============================================================================

clean:
	@echo "🧹 Cleaning cache and temporary files..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/
	@echo "✅ Cleanup complete!"

deps:
	@echo "📊 Dependency tree:"
	poetry show --tree

outdated:
	@echo "📊 Outdated packages:"
	poetry show --outdated

update:
	@echo "📦 Updating dependencies..."
	poetry update

# =============================================================================
# PRODUCTION
# =============================================================================

build:
	@echo "🏗️ Building application..."
	poetry build

install-prod:
	@echo "📦 Installing production dependencies..."
	poetry install --only main

# =============================================================================
# TESTING SHORTCUTS
# =============================================================================

# Quick test commands for development
tdd: test-watch
t: test-fast
tu: test-unit
ti: test-integration
ta: test-auth
tc: test-cov

# =============================================================================
# CI/CD HELPERS
# =============================================================================

ci-test:
	@echo "🚀 Running CI test suite..."
	poetry run pytest --junitxml=test-results.xml --cov=app --cov-report=xml

ci-lint:
	@echo "🔍 Running CI linting..."
	poetry run flake8 app tests --format=junit-xml --output-file=flake8-results.xml
	poetry run mypy app --junit-xml=mypy-results.xml

ci-security:
	@echo "🔒 Running CI security checks..."
	poetry run bandit -r app/ -f json -o bandit-results.json

# =============================================================================
# KEYCLOAK SETUP
# =============================================================================

setup-keycloak:
	@echo "🔐 Setting up Keycloak realm and client..."
	@echo "1. Open http://localhost:8080"
	@echo "2. Login: admin / admin_password_dev"
	@echo "3. Create realm: finance-realm"
	@echo "4. Create client: finance-tracker"
	@echo "5. Set client settings:"
	@echo "   - Client Protocol: openid-connect"
	@echo "   - Access Type: confidential"
	@echo "   - Valid Redirect URIs: http://localhost:8000/api/v1/auth/callback"
	@echo "6. Copy client secret to .env file"

# =============================================================================
# REDIS OPERATIONS
# =============================================================================

redis-cli:
	@echo "🔴 Connecting to Redis..."
	docker exec -it finance_redis redis-cli -a redis_dev_password

redis-monitor:
	@echo "🔴 Monitoring Redis commands..."
	docker exec -it finance_redis redis-cli -a redis_dev_password monitor

redis-flush:
	@echo "🔴 Flushing Redis database..."
	docker exec -it finance_redis redis-cli -a redis_dev_password flushdb

# =============================================================================
# DEVELOPMENT WORKFLOW
# =============================================================================

start: docker-up
	@echo "⏳ Waiting for services..."
	sleep 15
	$(MAKE) dev

stop: docker-down

restart: stop start

full-test: clean docker-up
	@echo "⏳ Waiting for services..."
	sleep 15
	$(MAKE) test-cov
	$(MAKE) lint

# =============================================================================
# HELP FOR SPECIFIC COMMANDS
# =============================================================================

help-test:
	@echo "Testing Commands Help"
	@echo "===================="
	@echo ""
	@echo "test        - Run all tests"
	@echo "test-unit   - Only unit tests (fast, no external deps)"
	@echo "test-integration - Integration tests (require Redis/Keycloak)"
	@echo "test-auth   - Authentication related tests"
	@echo "test-cov    - Tests with HTML coverage report"
	@echo "test-watch  - Auto-run tests on file changes"
	@echo ""
	@echo "Markers:"
	@echo "  -m unit           - Only unit tests"
	@echo "  -m integration    - Only integration tests"
	@echo "  -m 'not slow'     - Skip slow tests"
	@echo "  -m auth           - Only auth tests"
	@echo ""
	@echo "Examples:"
	@echo "  poetry run pytest tests/test_redis_client.py"
	@echo "  poetry run pytest -k test_oauth"
	@echo "  poetry run pytest -v --tb=long"

help-docker:
	@echo "Docker Commands Help"
	@echo "==================="
	@echo ""
	@echo "docker-up      - Start PostgreSQL + Redis + Keycloak"
	@echo "docker-down    - Stop all services"
	@echo "docker-logs    - Show logs from all services"
	@echo "docker-redis   - Start only Redis"
	@echo "docker-keycloak - Start only Keycloak"
	@echo ""
	@echo "Service URLs:"
	@echo "  Redis UI:  http://localhost:8081 (admin/admin123)"
	@echo "  Keycloak:  http://localhost:8080 (admin/admin_password_dev)"
	@echo "  App:       http://localhost:8000"