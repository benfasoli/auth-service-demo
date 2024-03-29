.PHONY: all
all: install lint test

.PHONY: install
install:
	python3.10 -m venv .venv
	.venv/bin/pip install .[dev]

.PHONY: clean
clean:
	rm -fr .venv
	rm -fr .coverage*
	rm -fr .coverage_html
	rm -fr .mypy_cache
	rm -fr .pytest_cache
	rm -fr .ruff_cache
	find . -name '*.py[co]' -type f -exec rm -f {} +
	find . -name '__pycache__' -type d -exec rm -fr {} +

.PHONY: format
format:
	.venv/bin/black  .

.PHONY: lint
lint:
	.venv/bin/black --check --diff .
	.venv/bin/ruff .
	.venv/bin/mypy .

.PHONY: serve
serve:
	.venv/bin/uvicorn src.main:app --reload

.PHONY: test
test:
	.venv/bin/pytest --cov-report=html:.coverage_html --cov-report=term-missing --cov-config=pyproject.toml --cov=src --cov=tests
