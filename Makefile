# CABID development tasks.
#
# Everything here is stdlib + dev-only tools. `make check` is what CI runs; if it
# passes locally it should pass there.

PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin
PY     := $(BIN)/python
PIP    := $(BIN)/pip
CABID  := $(BIN)/cabid
COV_MIN ?= 90
IMAGE  ?= cabid:dev

.DEFAULT_GOAL := help
.PHONY: help venv install test coverage lint types check benchmark docs-clean clean \
        build wheel docker smoke fmt

help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -q --upgrade pip

venv: $(BIN)/python ## create the virtualenv

install: venv ## editable install with dev tooling
	$(PIP) install -q -e '.[test]'

test: install ## run the test suite
	$(PY) -m pytest

coverage: install ## run tests under coverage and enforce the floor
	$(PY) -m coverage run -m pytest
	$(PY) -m coverage report --skip-covered
	$(PY) -m coverage report --fail-under=$(COV_MIN) >/dev/null
	@echo "coverage: at or above $(COV_MIN)%"

lint: install ## pyflakes
	$(BIN)/pyflakes cabid tests

types: install ## mypy
	$(BIN)/mypy cabid

check: lint types coverage ## everything CI enforces
	@echo "all checks passed"

benchmark: install ## deterministic synthetic benchmark
	$(CABID) benchmark --output /tmp/cabid-benchmark.json --seed 20261113 --per-class 50

smoke: install ## end-to-end CLI smoke test over the bundled datasets
	$(CABID) analyze datasets/synthetic/example.jsonl -f json -o /tmp/cabid-smoke.json -q
	$(CABID) analyze datasets/synthetic/tree-example.jsonl --explain-score -f md \
		-o /tmp/cabid-smoke.md -q
	$(CABID) timeline datasets/synthetic/tree-example.jsonl -f txt -o /tmp/cabid-smoke.txt
	$(CABID) export-stix /tmp/cabid-smoke.json -o /tmp/cabid-smoke-stix.json -q
	$(CABID) import-sigma docs/cabid-sigma.example.yml -o /tmp/cabid-smoke-rules.json -q
	$(CABID) analyze datasets/synthetic/tree-example.jsonl -r /tmp/cabid-smoke-rules.json -q \
		-o /tmp/cabid-smoke-rules-report.json
	$(CABID) doctor -f json > /tmp/cabid-doctor.json
	@echo "smoke: ok"

build: install ## build sdist and wheel
	$(PY) -m build

wheel: build ## alias for build

docker: ## build the container image
	docker build -t $(IMAGE) .

clean: ## remove caches and build output
	rm -rf build dist htmlcov .coverage coverage.xml .mypy_cache .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.egg-info' -type d -prune -exec rm -rf {} +
