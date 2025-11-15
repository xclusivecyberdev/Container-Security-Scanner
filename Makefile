# Makefile for Docker Security Scanner

.PHONY: help install test lint clean docker run dashboard docs

help:
	@echo "Docker Security Scanner - Make targets"
	@echo ""
	@echo "  install     Install dependencies and package"
	@echo "  test        Run tests"
	@echo "  lint        Run linter"
	@echo "  clean       Clean build artifacts"
	@echo "  docker      Build Docker image"
	@echo "  run         Run example scan"
	@echo "  dashboard   Start web dashboard"
	@echo "  docs        Generate documentation"

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt
	pip install -e .
	@echo "✅ Installation complete"

test:
	@echo "Running tests..."
	pytest tests/ -v --cov=src --cov-report=html
	@echo "✅ Tests complete"

lint:
	@echo "Running linter..."
	flake8 src/ --max-line-length=120 --ignore=E501,W503
	@echo "✅ Linting complete"

clean:
	@echo "Cleaning build artifacts..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache htmlcov .coverage
	rm -rf reports/*.html reports/*.pdf reports/*.json
	@echo "✅ Cleanup complete"

docker:
	@echo "Building Docker image..."
	docker build -t docker-security-scanner:latest .
	@echo "✅ Docker image built"

docker-dashboard:
	@echo "Building dashboard Docker image..."
	docker build -t docker-security-scanner-dashboard:latest -f Dockerfile.dashboard .
	@echo "✅ Dashboard image built"

run:
	@echo "Running example scan on alpine:latest..."
	docker pull alpine:latest > /dev/null 2>&1
	python -m cli.main scan-image alpine:latest

dashboard:
	@echo "Starting web dashboard..."
	@echo "Access at http://localhost:5000"
	cd src/dashboard && python app.py

quickstart:
	@echo "Running quick start..."
	chmod +x quickstart.sh
	./quickstart.sh

# Development targets
dev-install:
	pip install -r requirements.txt
	pip install -e .[dev]
	pip install pytest pytest-cov flake8 black mypy

format:
	@echo "Formatting code..."
	black src/ tests/
	@echo "✅ Formatting complete"

type-check:
	@echo "Running type checker..."
	mypy src/
	@echo "✅ Type checking complete"

# CI/CD examples
ci-test:
	@echo "Running CI tests..."
	pytest tests/ -v --cov=src --cov-report=xml

# Release targets
build:
	@echo "Building distribution..."
	python setup.py sdist bdist_wheel
	@echo "✅ Build complete"

release: clean build
	@echo "Releasing package..."
	twine upload dist/*
	@echo "✅ Release complete"
