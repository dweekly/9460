# Development Standards and Engineering Best Practices

This document outlines the engineering best practices and standards for the RFC 9460 Compliance Checker project. All code contributions must adhere to these standards.

## Code Quality Tools

### Python Toolchain

#### Required Tools
- **Black**: Code formatting (line length: 100)
- **isort**: Import sorting
- **flake8**: Linting and style checking
- **mypy**: Static type checking
- **pytest**: Testing framework
- **pytest-cov**: Code coverage
- **pre-commit**: Git hooks for automated checks

#### Installation
```bash
pip install -r requirements-dev.txt
```

## Pre-commit Hooks

### Setup
```bash
pre-commit install
pre-commit install --hook-type pre-push
```

### Configuration (.pre-commit-config.yaml)
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        language_version: python3.11
        args: [--line-length=100]

  - repo: https://github.com/pycqa/isort
    rev: 5.13.2
    hooks:
      - id: isort
        args: [--profile=black, --line-length=100]

  - repo: https://github.com/pycqa/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=100, --extend-ignore=E203]
        additional_dependencies: [flake8-docstrings, flake8-typing-imports]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        args: [--strict, --ignore-missing-imports]
        additional_dependencies: [types-all]

  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-push]

      - id: pytest-coverage
        name: pytest-coverage
        entry: pytest --cov=src --cov-report=term-missing --cov-fail-under=80
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-push]
```

## Code Standards

### Python Style Guide

#### Type Hints
All functions must have complete type hints:
```python
from typing import Dict, List, Optional, Any

async def query_https_record(
    domain: str,
    subdomain: str = ""
) -> Dict[str, Any]:
    """Query HTTPS record for a domain.

    Args:
        domain: The base domain to query
        subdomain: Optional subdomain prefix

    Returns:
        Dictionary containing HTTPS record data

    Raises:
        DNSException: If DNS query fails
    """
    pass
```

#### Docstrings
Use Google-style docstrings for all public functions, classes, and modules:
```python
def analyze_compliance(data: pd.DataFrame) -> Dict[str, float]:
    """Analyze RFC 9460 compliance metrics.

    Args:
        data: DataFrame containing DNS query results

    Returns:
        Dictionary with compliance metrics:
            - adoption_rate: Percentage with HTTPS records
            - http3_support: Percentage with HTTP/3
            - ech_deployment: Percentage with ECH

    Examples:
        >>> df = pd.read_csv('results.csv')
        >>> metrics = analyze_compliance(df)
        >>> print(f"Adoption: {metrics['adoption_rate']}%")
    """
    pass
```

#### Error Handling
Explicit error handling with custom exceptions:
```python
class RFC9460Error(Exception):
    """Base exception for RFC 9460 checker."""
    pass

class DNSQueryError(RFC9460Error):
    """Raised when DNS query fails."""
    pass

class DataValidationError(RFC9460Error):
    """Raised when data validation fails."""
    pass
```

### Testing Standards

#### Test Coverage Requirements
- Minimum 80% code coverage
- 100% coverage for critical paths
- All public APIs must have tests

#### Test Structure
```python
import pytest
from unittest.mock import Mock, patch

class TestRFC9460Checker:
    """Test suite for RFC9460Checker class."""

    @pytest.fixture
    def checker(self):
        """Create checker instance for testing."""
        return RFC9460Checker()

    def test_query_https_record_success(self, checker, mock_dns_response):
        """Test successful HTTPS record query."""
        # Given
        domain = "example.com"

        # When
        result = checker.query_https_record(domain)

        # Then
        assert result['has_https_record'] is True
        assert 'h3' in result['alpn_protocols']

    def test_query_https_record_timeout(self, checker):
        """Test timeout handling in HTTPS query."""
        with pytest.raises(DNSQueryError, match="Timeout"):
            checker.query_https_record("timeout.example.com")
```

#### Testing Commands
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_checker.py

# Run with verbose output
pytest -v

# Run only marked tests
pytest -m "not slow"
```

## Continuous Integration

### GitHub Actions Workflow (.github/workflows/ci.yml)
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements-dev.txt
      - run: black --check .
      - run: isort --check-only .
      - run: flake8 .
      - run: mypy .

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.8', '3.9', '3.10', '3.11']
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements-dev.txt
      - run: pytest --cov=src --cov-report=xml
      - uses: codecov/codecov-action@v3
```

## Project Structure Standards

### Directory Layout
```
src/
├── __init__.py
├── checker/
│   ├── __init__.py
│   ├── dns_client.py      # DNS query logic
│   ├── parser.py          # Record parsing
│   └── validator.py       # Data validation
├── analyzer/
│   ├── __init__.py
│   ├── metrics.py         # Metric calculations
│   └── reporter.py        # Report generation
└── utils/
    ├── __init__.py
    ├── config.py          # Configuration management
    └── logging.py         # Logging setup

tests/
├── conftest.py           # Shared fixtures
├── unit/
│   ├── test_dns_client.py
│   ├── test_parser.py
│   └── test_metrics.py
├── integration/
│   └── test_checker_integration.py
└── fixtures/
    └── dns_responses.json
```

### Configuration Management

#### pyproject.toml
```toml
[tool.black]
line-length = 100
target-version = ['py38', 'py39', 'py310', 'py311']

[tool.isort]
profile = "black"
line_length = 100

[tool.mypy]
python_version = "3.8"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
minversion = "7.0"
testpaths = ["tests"]
addopts = "-ra -q --strict-markers"
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks integration tests",
]

[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/test_*.py"]

[tool.coverage.report]
precision = 2
show_missing = true
skip_covered = false
```

## Development Workflow

### 1. Setup Development Environment
```bash
# Clone repository
git clone <repo-url>
cd rfc9460-check

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type pre-push
```

### 2. Before Committing
```bash
# Format code
black .
isort .

# Run linting
flake8 .
mypy .

# Run tests
pytest

# Or run all checks at once
pre-commit run --all-files
```

### 3. Manual Quality Checks
```bash
# Check code complexity
flake8 --max-complexity=10 src/

# Security audit
pip-audit

# Check dependencies
pip-compile --upgrade requirements.in
```

## Performance Standards

### Async Best Practices
```python
import asyncio
from asyncio_throttle import Throttler

class OptimizedChecker:
    def __init__(self):
        self.throttler = Throttler(rate_limit=10)
        self.semaphore = asyncio.Semaphore(20)

    async def check_domains(self, domains: List[str]) -> List[Dict]:
        """Check multiple domains concurrently."""
        tasks = [self._check_with_limit(d) for d in domains]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_with_limit(self, domain: str) -> Dict:
        """Check domain with rate limiting."""
        async with self.semaphore:
            async with self.throttler:
                return await self.query_https_record(domain)
```

### Caching Strategy
```python
from functools import lru_cache
from typing import Optional
import time

class CachedResolver:
    def __init__(self, cache_ttl: int = 3600):
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, tuple[Any, float]] = {}

    def get_cached(self, key: str) -> Optional[Any]:
        """Get cached value if not expired."""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return value
        return None
```

## Documentation Standards

### README Requirements
- Clear installation instructions
- Usage examples
- API documentation
- Contributing guidelines
- License information

### Code Comments
- Explain "why" not "what"
- Document complex algorithms
- Add TODO/FIXME with issue numbers
- Keep comments up-to-date

## Security Standards

### Dependency Management
```bash
# Regular security audits
pip-audit

# Pin dependencies
pip-compile --generate-hashes requirements.in

# Check for updates
pip list --outdated
```

### Secrets Management
- Never commit secrets
- Use environment variables
- Document required env vars
- Provide .env.example file

## Release Process

### Version Management
Use semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking changes
- MINOR: New features
- PATCH: Bug fixes

### Release Checklist
- [ ] All tests passing
- [ ] Coverage > 80%
- [ ] No linting errors
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped
- [ ] Git tag created
- [ ] GitHub release created

## Commands Reference

```bash
# Linting and Formatting
make lint           # Run all linters
make format         # Format code
make typecheck      # Run mypy

# Testing
make test           # Run all tests
make test-coverage  # Run with coverage
make test-watch     # Run in watch mode

# Development
make install        # Install all dependencies
make clean          # Clean build artifacts
make build          # Build distribution

# Quality
make quality        # Run all quality checks
make security       # Security audit
```

## Monitoring and Observability

### Logging Standards
```python
import logging
import structlog

logger = structlog.get_logger(__name__)

logger.info(
    "dns_query_completed",
    domain=domain,
    duration=duration,
    has_record=result['has_https_record']
)
```

### Metrics Collection
- Query success/failure rates
- Response times
- Cache hit rates
- Error frequencies

## Troubleshooting

### Common Issues

#### Pre-commit Hook Failures
```bash
# Skip hooks temporarily (not recommended)
git commit --no-verify

# Fix and retry
pre-commit run --all-files
git add -u
git commit
```

#### Type Checking Issues
```bash
# Install type stubs
mypy --install-types

# Ignore specific error
# type: ignore[error-code]
```

## Contributing

All contributions must:
1. Pass all pre-commit hooks
2. Include tests for new features
3. Update documentation
4. Follow code standards
5. Be reviewed before merging

---

*These standards ensure code quality, maintainability, and reliability across the project.*
