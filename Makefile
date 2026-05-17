.PHONY: help install venv dev run test env docker-build docker-run clean

PYTHON ?= python3
VENV ?= venv
PIP := $(VENV)/bin/pip
UVICORN := $(VENV)/bin/uvicorn
PYTEST := $(VENV)/bin/pytest

APP_MODULE := app.main:app
HOST ?= 127.0.0.1
PORT ?= 8000
DOCKER_IMAGE ?= gcp-fastapi

.DEFAULT_GOAL := help

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

venv: ## Create virtual environment
	$(PYTHON) -m venv $(VENV)

install: venv ## Install Python dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

env: ## Copy .env.example to .env if missing
	@test -f .env || cp .env.example .env
	@echo ".env ready — edit OAuth credentials and SECRET_KEY before running."

dev: install env ## Run development server with auto-reload
	$(UVICORN) $(APP_MODULE) --reload --host $(HOST) --port $(PORT)

run: install env ## Run production-style server (no reload)
	$(UVICORN) $(APP_MODULE) --host 0.0.0.0 --port $(PORT)

test: install ## Run tests
	$(PYTEST) -v --pass-with-no-tests

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) .

docker-run: env ## Run app in Docker (requires .env)
	docker run --rm -p $(PORT):8000 --env-file .env $(DOCKER_IMAGE)

clean: ## Remove venv, caches, and bytecode
	rm -rf $(VENV) .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
