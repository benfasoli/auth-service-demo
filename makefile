install:
	python3.10 -m venv .venv
	.venv/bin/pip install .[dev]

clean:
	find . -name '*.py[co]' -type f -exec rm -f {} +
	find . -name '__pycache__' -type d -exec rm -fr {} +
	rm -fr .coverage*
	rm -fr .mypy_cache
	rm -fr .pytest_cache
	rm -fr .ruff_cache
	rm -fr .venv

lint:
	.venv/bin/black --check --diff .
	.venv/bin/ruff .
	.venv/bin/mypy .

test:
	.venv/bin/pytest --cov-report=term-missing --cov-config=pyproject.toml --cov=src --cov=tests