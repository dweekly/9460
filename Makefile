.PHONY: help install install-dev format lint typecheck test test-coverage test-watch clean build quality security pre-commit

help:  ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install:  ## Install production dependencies
	pip install -r requirements.txt

install-dev:  ## Install all dependencies including dev tools
	pip install -r requirements-dev.txt
	pre-commit install
	pre-commit install --hook-type pre-push

format:  ## Format code with black and isort
	black --line-length=100 .
	isort --profile=black --line-length=100 .

lint:  ## Run all linters
	black --check --line-length=100 .
	isort --check-only --profile=black --line-length=100 .
	flake8 --max-line-length=100 --extend-ignore=E203,W503 .

typecheck:  ## Run mypy type checking
	mypy --strict --ignore-missing-imports src/

test:  ## Run all tests
	pytest -v

test-coverage:  ## Run tests with coverage report
	pytest --cov=src --cov-report=term-missing --cov-report=html --cov-fail-under=70

test-watch:  ## Run tests in watch mode
	pytest-watch -- -v

test-unit:  ## Run only unit tests
	pytest -v -m unit

test-integration:  ## Run only integration tests
	pytest -v -m integration

clean:  ## Clean build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.orig" -delete

build:  ## Build distribution packages
	python -m build

quality:  ## Run all quality checks (lint, typecheck, test)
	@echo "Running code quality checks..."
	@make lint
	@make typecheck
	@make test-coverage

security:  ## Run security audit
	pip-audit
	bandit -r src/ -f json -o bandit-report.json

pre-commit:  ## Run pre-commit hooks on all files
	pre-commit run --all-files

pre-commit-update:  ## Update pre-commit hooks to latest versions
	pre-commit autoupdate

deps-update:  ## Update dependencies to latest versions
	pip-compile --upgrade requirements.in
	pip-compile --upgrade requirements-dev.in

deps-check:  ## Check for outdated dependencies
	pip list --outdated

complexity:  ## Check code complexity
	radon cc src/ -a -nb
	xenon --max-absolute B --max-modules B --max-average A src/

profile:  ## Profile the main script
	python -m cProfile -o profile.stats main.py --limit 10
	python -m pstats profile.stats

docs:  ## Build documentation
	sphinx-build -b html docs/ docs/_build/

docs-serve:  ## Serve documentation locally
	sphinx-autobuild docs/ docs/_build/ --port 8000

run:  ## Run the RFC 9460 checker
	python main.py

run-sample:  ## Run checker on sample domains (limit to 10)
	python main.py --limit 10

run-full:  ## Run checker on all domains
	python main.py

run-verbose:  ## Run checker with verbose output
	python main.py --verbose --limit 10

run-debug:  ## Run checker with debug output
	python main.py --debug --limit 5

serve-results:  ## Start local web server for GitHub Pages site
	cd docs && python -m http.server 8000

ci:  ## Run CI pipeline locally
	@echo "Running CI pipeline..."
	@make quality
	@make security
	@echo "CI pipeline completed successfully!"

setup-githooks:  ## Set up git hooks for the project
	@echo "#!/bin/sh" > .git/hooks/pre-push
	@echo "make quality" >> .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "Git hooks configured successfully!"

docker-build:  ## Build Docker image
	docker build -t rfc9460-checker:latest .

docker-run:  ## Run Docker container
	docker run --rm -v $(PWD)/results:/app/results rfc9460-checker:latest

# Development shortcuts
f: format
l: lint
t: test
tc: test-coverage
c: clean
