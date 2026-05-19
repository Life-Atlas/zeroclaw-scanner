.PHONY: install lint test scan report

install:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check src/ tests/
	mypy src/ --ignore-missing-imports

test:
	pytest tests/ -v --tb=short

scan:
	python -m zeroclaw.cli scan --target .

report:
	python -m zeroclaw.cli report --format terminal
