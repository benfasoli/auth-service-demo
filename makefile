.PHONY: all
all: install lint test

.PHONY: install
install:
	python3.10 -m venv .venv
	.venv/bin/pip install .[dev]

.PHONY: clean
clean:
	find . -name '*.py[co]' -type f -exec rm -f {} +
	find . -name '__pycache__' -type d -exec rm -fr {} +
	rm -fr .coverage*
	rm -fr .coverage_html
	rm -fr .mypy_cache
	rm -fr .pytest_cache
	rm -fr .ruff_cache
	rm -fr .venv

.PHONY: format
format:
	.venv/bin/black  .

.PHONY: lint
lint:
	.venv/bin/black --check --diff .
	ruff .
	.venv/bin/mypy .

.PHONY: test
test:
	.venv/bin/pytest --cov-report=html:.coverage_html --cov-report=term-missing --cov-config=pyproject.toml --cov=src --cov=tests
