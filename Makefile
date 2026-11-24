.PHONY: install lint fmt typecheck test validate bench baseline check

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

typecheck:
	uv run mypy

test:
	uv run pytest

validate:
	uv run agent-redteam validate

bench:
	uv run agent-redteam bench --out-dir out

# Refresh the committed baseline and README figures after an intentional change.
baseline: bench
	cp out/results/*.json benchmarks/baseline/
	cp out/report/report.md out/report/*.png docs/results/

check: lint typecheck test validate
