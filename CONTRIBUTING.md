# Contributing to Docker Security Scanner

Thank you for considering contributing to Docker Security Scanner! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:

- Clear description of the bug
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, Docker version)
- Relevant logs or screenshots

### Suggesting Features

We welcome feature suggestions! Please create an issue with:

- Clear description of the feature
- Use case and benefits
- Possible implementation approach

### Pull Requests

1. **Fork the repository**
   ```bash
   git clone https://github.com/yourusername/Container-Security-Scanner.git
   cd Container-Security-Scanner
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Write clear, commented code
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Run tests**
   ```bash
   make test
   make lint
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add feature: your feature description"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Provide a clear description
   - Reference any related issues
   - Include screenshots if applicable

## Development Setup

### Prerequisites

- Python 3.8+
- Docker
- Git

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/xclusivecyberdev/Container-Security-Scanner.git
cd Container-Security-Scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
make dev-install

# Run tests
make test
```

## Coding Standards

### Python Style

- Follow PEP 8
- Use Black for formatting
- Maximum line length: 120 characters
- Use type hints where appropriate

```bash
# Format code
make format

# Check linting
make lint

# Type checking
make type-check
```

### Documentation

- Add docstrings to all functions and classes
- Update README.md for user-facing changes
- Update USAGE.md for new features
- Include inline comments for complex logic

### Testing

- Write unit tests for new features
- Maintain or improve code coverage
- Use pytest for testing
- Mock external dependencies

```python
# Example test
def test_scanner_feature():
    """Test description."""
    scanner = MyScanner()
    result = scanner.scan('test:latest')
    assert len(result) > 0
```

## Project Structure

```
Container-Security-Scanner/
├── src/
│   ├── scanners/       # Core scanners
│   ├── analyzers/      # Advanced analyzers
│   ├── reporters/      # Report generators
│   ├── cli/           # CLI interface
│   └── dashboard/     # Web dashboard
├── tests/             # Test suite
├── examples/          # Example scripts
├── docs/             # Documentation
└── README.md         # Main documentation
```

## Adding a New Scanner

1. **Create scanner class**

```python
# src/scanners/my_scanner.py
from .base_scanner import BaseScanner, ScanResult

class MyScanner(BaseScanner):
    def __init__(self):
        super().__init__("MyScanner")

    def scan(self, target):
        self.clear_results()

        # Your scanning logic here
        self.add_result(ScanResult(
            scanner_name=self.name,
            severity='HIGH',
            title='Issue Title',
            description='Issue description',
            remediation='How to fix'
        ))

        return self.get_results()
```

2. **Add tests**

```python
# tests/test_my_scanner.py
def test_my_scanner():
    scanner = MyScanner()
    results = scanner.scan('test:latest')
    assert len(results) > 0
```

3. **Update CLI**

Add scanner to `src/cli/main.py`

4. **Update documentation**

Add scanner to README.md and USAGE.md

## Release Process

1. Update version in `setup.py`
2. Update CHANGELOG.md
3. Create release branch
4. Run full test suite
5. Create GitHub release
6. Build and publish package

## Questions?

- Open an issue for questions
- Check existing issues and documentation
- Join discussions on GitHub Discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing! 🎉
