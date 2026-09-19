.PHONY: install lint format typecheck test cov audit build docker clean check

PY ?= python

install:
	$(PY) -m pip install -e ".[dev]"

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff check . --fix
	$(PY) -m ruff format .

typecheck:
	$(PY) -m mypy

test:
	$(PY) -m pytest

cov:
	$(PY) -m pytest --cov --cov-report=term-missing --cov-report=xml

audit:
	$(PY) -m pip_audit -r requirements.txt

build:
	$(PY) -m build
	$(PY) -m twine check dist/*

docker:
	docker build -t agentic-ai-platform-ops-center .

check: lint typecheck cov

clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov .opscenter
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
