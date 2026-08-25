# Marionette — contributor convenience targets.
#
# Everything here is a thin wrapper over the commands CI actually runs, so a
# green `make check` locally means a green pipeline. POSIX sh only: this is
# expected to work identically on macOS and Linux.
#
#   make install      editable install with dev extras
#   make test         the unit suite
#   make lint         technique + fleet lint (marionette validate)
#   make run          the whole pack against the built-in range
#   make check        lint + test + run, in the order CI does them
#   make flake-check  repeat the suite N times to catch races (N=5)
#   make clean        remove build/test artifacts

SHELL := /bin/sh

PYTHON ?= python3
PIP    ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
MARIONETTE ?= $(PYTHON) -m marionette.cli

# Iterations for `make flake-check`. Override: make flake-check N=20
N ?= 5

# Extra flags forwarded to pytest / marionette run.
PYTEST_ARGS ?=
RUN_ARGS    ?=

.DEFAULT_GOAL := help

.PHONY: help install test test-fast lint run check flake-check clean coverage

help:
	@echo "targets:"
	@echo "  install      pip install -e '.[dev]'"
	@echo "  test         run the unit suite"
	@echo "  test-fast    the suite without the slow subprocess tests"
	@echo "  lint         marionette validate (technique pack + example fleet)"
	@echo "  run          marionette run against the built-in range"
	@echo "  check        lint, test, run — what CI does"
	@echo "  flake-check  run the suite N times (N=$(N)) to catch races"
	@echo "  clean        remove caches and build artifacts"

install:
	$(PIP) install -e ".[dev]"

test:
	$(PYTEST) -q $(PYTEST_ARGS)

# Skips the handful of subprocess/timeout tests that dominate the runtime.
# `make test` remains the gate; this is for the edit-run loop.
test-fast:
	$(PYTEST) -q -m "not slow" $(PYTEST_ARGS)

# The technique pack must lint clean before it is worth executing.
lint:
	$(MARIONETTE) validate --targets-file targets.example.yaml

run:
	$(MARIONETTE) run $(RUN_ARGS)

check: lint test run

# Two of this project's real bugs were intermittent (a fail_fast race in the
# engine, and order-dependence between techniques). One green run proves
# nothing about either, so repeat and require every iteration to pass.
flake-check:
	@fails=0; i=1; \
	while [ $$i -le $(N) ]; do \
	  printf '--- iteration %s/%s ---\n' "$$i" "$(N)"; \
	  if $(PYTEST) -q $(PYTEST_ARGS); then :; else fails=$$((fails + 1)); fi; \
	  $(MARIONETTE) run --quiet || fails=$$((fails + 1)); \
	  i=$$((i + 1)); \
	done; \
	if [ $$fails -ne 0 ]; then \
	  echo "$$fails failure(s) across $(N) iterations — flaky"; exit 1; \
	fi; \
	echo "$(N)/$(N) iterations clean"

clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	rm -rf *.egg-info
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -f marionette-results.json marionette-results.xml
