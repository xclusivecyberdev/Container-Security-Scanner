# Docker Container Security Scanner

<div align="center">

![Security Scanner](https://img.shields.io/badge/Security-Scanner-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen)
![Docker](https://img.shields.io/badge/Docker-Required-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A comprehensive Docker container security scanner that analyzes images and containers for vulnerabilities, misconfigurations, exposed secrets, privilege escalation risks, and compliance with Docker security benchmarks.

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [CI/CD Integration](#cicd-integration)

</div>

---

## Features

### 🔍 Comprehensive Security Analysis

- **Base Image Vulnerability Scanning**: Identifies vulnerabilities in base Docker images
- **Package CVE Scanning**: Detects vulnerable packages using CVE databases
  - Debian/Ubuntu (dpkg)
  - Alpine (apk)
  - RedHat/CentOS (rpm)
  - Python packages (pip)
  - Node.js packages (npm)
- **Security Misconfiguration Detection**: Identifies Docker security misconfigurations
- **Secrets & Credentials Scanning**: Finds exposed secrets, API keys, and credentials
- **Privilege Escalation Analysis**: Detects SUID binaries, sudo misconfigurations, and dangerous capabilities
- **CIS Benchmark Compliance**: Checks compliance with CIS Docker Benchmark v1.6.0

### 🛠️ Multiple Interfaces

- **CLI Tool**: Command-line interface for CI/CD integration
- **Web Dashboard**: Interactive web-based dashboard
- **REST API**: Programmatic access for automation
- **Report Generation**: Multiple output formats (JSON, HTML, PDF, Text)

### 🔄 CI/CD Integration

- **GitHub Actions**: Pre-built workflows
- **GitLab CI**: Pipeline templates
- **Jenkins**: Jenkinsfile examples
- **Docker Compose**: Easy deployment

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Docker Engine
- pip (Python package manager)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/xclusivecyberdev/Container-Security-Scanner.git
cd Container-Security-Scanner

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Docker Installation

```bash
# Build the Docker image
docker build -t docker-security-scanner .

# Run the scanner
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  docker-security-scanner scan-image nginx:latest
```

---

## Quick Start

### Scan a Docker Image

```bash
# Basic scan
python -m cli.main scan-image nginx:latest

# Scan with specific severity threshold
python -m cli.main scan-image nginx:latest --severity HIGH

# Generate HTML report
python -m cli.main scan-image nginx:latest --format html --output report.html

# Generate PDF report
python -m cli.main scan-image nginx:latest --format pdf --output report.pdf

# Run specific scanners only
python -m cli.main scan-image nginx:latest \
  --scan-secrets \
  --scan-misconfig \
  --scan-benchmark
```

### Scan a Running Container

```bash
# Scan a running container
python -m cli.main scan-container my-container

# Generate JSON output
python -m cli.main scan-container my-container \
  --format json \
  --output container-scan.json
```

### Launch Web Dashboard

```bash
# Start the web dashboard
cd src/dashboard
python app.py

# Access at http://localhost:5000
```

---

## Scanners & Analyzers

### 1. Base Image Vulnerability Scanner

Analyzes Docker base images for:
- Use of vulnerable or EOL base images
- Floating tags (`:latest`)
- Image age and update status
- Third-party image verification

**Example Output:**
```
[HIGH] Outdated Base Image
  Description: Image is 425 days old (over 1 year)
  Remediation: Update to a more recent base image version
```

### 2. Package Vulnerability Scanner

Scans installed packages against CVE databases:
- Operating system packages (apt, apk, yum)
- Python packages (pip)
- Node.js packages (npm)
- Known CVE matching with CVSS scores

**Example Output:**
```
[CRITICAL] Vulnerable Package: openssl
  CVE: CVE-2022-0778
  CVSS Score: 7.5
  Description: Infinite loop in BN_mod_sqrt()
  Remediation: Update openssl to version 1.1.1n or later
```

### 3. Misconfiguration Scanner

Detects Docker security misconfigurations:
- Running as root user
- Exposed sensitive ports
- Missing healthchecks
- Privileged mode
- Dangerous capabilities
- Host namespace sharing
- Resource limits

**Example Output:**
```
[HIGH] Running as Root User
  Description: Container is configured to run as root user
  Remediation: Add USER directive in Dockerfile to run as non-root user
```

### 4. Secrets Scanner

Finds exposed secrets and credentials:
- AWS Access Keys & Secret Keys
- GitHub Tokens
- API Keys
- Private Keys (RSA, SSH)
- Database Connection Strings
- JWT Tokens
- Environment variable secrets

**Example Output:**
```
[CRITICAL] Secret in Environment Variable: AWS Access Key
  Description: Detected AWS Access Key in environment variable AWS_ACCESS_KEY_ID
  Remediation: Remove secrets from environment variables. Use Docker secrets or external secret management.
```

### 5. Privilege Escalation Analyzer

Identifies privilege escalation risks:
- SUID/SGID binaries
- Sudo misconfigurations
- Dangerous Linux capabilities
- Container breakout vectors
- Docker socket mounting

**Example Output:**
```
[CRITICAL] Docker Socket Mounted - Container Escape Vector
  Description: Docker socket is mounted, allowing full Docker API access from container
  Remediation: Remove docker.sock mount. Use Docker-in-Docker if needed.
```

### 6. CIS Benchmark Compliance Checker

Validates against CIS Docker Benchmark:
- Image configuration checks
- Container runtime configuration
- Security options (AppArmor, SELinux, seccomp)
- Network isolation
- Resource management

**Example Output:**
```
[HIGH] CIS 5.4 - Privileged container
  Description: Container is running in privileged mode
  Remediation: Remove --privileged flag
```

---

## Report Formats

### Text Output (Console)

```bash
python -m cli.main scan-image nginx:latest
```

Clean, color-coded terminal output with severity grouping.

### JSON Report

```bash
python -m cli.main scan-image nginx:latest --format json --output scan.json
```

Machine-readable format for automation and integration.

### HTML Report

```bash
python -m cli.main scan-image nginx:latest --format html --output report.html
```

Interactive HTML report with charts and filtering.

### PDF Report

```bash
python -m cli.main scan-image nginx:latest --format pdf --output report.pdf
```

Professional PDF report for documentation and compliance.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Docker Security Scan
  run: |
    pip install -r requirements.txt
    python -m cli.main scan-image myapp:latest \
      --format json \
      --output scan-results.json \
      --severity HIGH

- name: Check for Critical Vulnerabilities
  run: |
    CRITICAL=$(jq '.summary.CRITICAL' scan-results.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

See [examples/ci-cd/github-actions.yml](examples/ci-cd/github-actions.yml) for complete workflow.

### GitLab CI

```yaml
security-scan:
  stage: security
  script:
    - python -m cli.main scan-image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
      --format json --output scan.json
    - |
      if [ $(jq '.summary.CRITICAL' scan.json) -gt 0 ]; then
        exit 1
      fi
```

See [examples/ci-cd/gitlab-ci.yml](examples/ci-cd/gitlab-ci.yml) for complete pipeline.

### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh """
            python -m cli.main scan-image ${IMAGE_NAME} \
                --format json --output scan-results.json
        """

        script {
            def results = readJSON file: 'scan-results.json'
            if (results.summary.CRITICAL > 0) {
                error("Critical vulnerabilities detected")
            }
        }
    }
}
```

See [examples/ci-cd/Jenkinsfile](examples/ci-cd/Jenkinsfile) for complete pipeline.

---

## Configuration

Create a `scan-config.yaml` file:

```yaml
scanners:
  image_vulnerability:
    enabled: true

  package_vulnerability:
    enabled: true
    databases:
      - nvd
      - alpine

  secrets:
    enabled: true
    exclude_patterns:
      - '*.git/*'
      - 'node_modules/*'

thresholds:
  critical:
    max_allowed: 0
    action: fail

  high:
    max_allowed: 5
    action: warn
```

See [examples/configs/scan-config.yaml](examples/configs/scan-config.yaml) for full example.

---

## Web Dashboard

The web dashboard provides an interactive interface for scanning and viewing results.

### Starting the Dashboard

```bash
cd src/dashboard
python app.py
```

Access at: `http://localhost:5000`

### Features

- **Image & Container Selection**: Browse and select Docker images/containers
- **Interactive Scanning**: Run scans with custom scanner selection
- **Real-time Results**: View scan results as they complete
- **Severity Filtering**: Filter findings by severity level
- **Export Options**: Export reports in multiple formats
- **Scan History**: Track and compare previous scans

### Dashboard Screenshots

The dashboard includes:
- Summary cards showing severity counts
- Detailed findings with remediation steps
- Severity-based color coding
- Expandable finding details

---

## API Reference

### CLI Commands

```bash
# List available scanners
python -m cli.main list-scanners

# Scan image with all scanners
python -m cli.main scan-image <image-name>

# Scan container
python -m cli.main scan-container <container-name>

# Options
--format, -f        Output format (text, json, html, pdf)
--output, -o        Output file path
--severity, -s      Minimum severity level
--scan-all          Run all scanners (default)
--scan-image        Scan base image only
--scan-packages     Scan packages only
--scan-misconfig    Scan misconfigurations only
--scan-secrets      Scan secrets only
--scan-privileges   Analyze privileges only
--scan-benchmark    Check benchmark compliance only
```

### REST API Endpoints

```
GET  /api/images                    List all Docker images
GET  /api/containers                List all containers
POST /api/scan/image                Scan a Docker image
POST /api/scan/container            Scan a container
GET  /api/scans                     Get scan history
GET  /api/scan/<id>                 Get specific scan results
GET  /api/scan/<id>/export          Export scan results
GET  /api/stats                     Get overall statistics
```

---

## Examples

### Example 1: Automated Security Gate

```bash
#!/bin/bash
IMAGE=$1

# Run scan
python -m cli.main scan-image $IMAGE --format json --output scan.json

# Parse results
CRITICAL=$(jq '.summary.CRITICAL' scan.json)
HIGH=$(jq '.summary.HIGH' scan.json)

# Decision logic
if [ "$CRITICAL" -gt 0 ]; then
    echo "FAIL: Critical vulnerabilities detected"
    exit 1
elif [ "$HIGH" -gt 10 ]; then
    echo "WARN: Too many high-severity issues"
    exit 1
else
    echo "PASS: Security scan passed"
    exit 0
fi
```

### Example 2: Multi-Image Comparison

```bash
#!/bin/bash
for image in nginx:1.20 nginx:1.21 nginx:latest; do
    echo "Scanning $image..."
    python -m cli.main scan-image $image \
        --format json \
        --output "scan-${image//:/-}.json"
done
```

### Example 3: Scheduled Security Audits

```bash
#!/bin/bash
# Add to crontab: 0 2 * * * /path/to/audit.sh

IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}")

for IMAGE in $IMAGES; do
    python -m cli.main scan-image $IMAGE \
        --format html \
        --output "/reports/$(date +%Y%m%d)-${IMAGE//:/-}.html"
done
```

---

## Architecture

```
Container-Security-Scanner/
├── src/
│   ├── scanners/           # Security scanners
│   │   ├── base_scanner.py
│   │   ├── image_scanner.py
│   │   ├── package_scanner.py
│   │   ├── misconfiguration_scanner.py
│   │   └── secrets_scanner.py
│   ├── analyzers/          # Advanced analyzers
│   │   ├── privilege_analyzer.py
│   │   └── benchmark_analyzer.py
│   ├── reporters/          # Report generators
│   │   └── report_generator.py
│   ├── cli/               # CLI interface
│   │   └── main.py
│   └── dashboard/         # Web dashboard
│       ├── app.py
│       └── templates/
├── examples/
│   ├── ci-cd/             # CI/CD examples
│   └── configs/           # Configuration examples
├── tests/                 # Test suite
├── docs/                  # Documentation
└── requirements.txt       # Dependencies
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/Container-Security-Scanner.git
cd Container-Security-Scanner

# Install development dependencies
pip install -r requirements.txt
pip install -e .[dev]

# Run tests
pytest

# Run linter
flake8 src/
```

---

## Security Considerations

- **Docker Socket Access**: The scanner requires access to the Docker socket (`/var/run/docker.sock`)
- **Privileged Operations**: Some scans may require elevated permissions
- **Data Privacy**: Scanned results may contain sensitive information; handle appropriately
- **CVE Database**: Consider using authenticated access to CVE databases for rate limiting

---

## Limitations

- **CVE Database**: Uses example/mock CVE data. In production, integrate with real vulnerability databases:
  - [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
  - [OSV](https://osv.dev/)
  - [Trivy](https://github.com/aquasecurity/trivy)
- **Language Coverage**: Currently supports Python, Node.js packages. Can be extended for others
- **Performance**: Large images may take time to scan. Consider implementing caching
- **Platform**: Primarily tested on Linux. Windows/macOS support may vary

---

## Roadmap

- [ ] Integration with real CVE databases (NVD, OSV)
- [ ] Container runtime monitoring
- [ ] Kubernetes security scanning
- [ ] SBOM (Software Bill of Materials) generation
- [ ] Integration with SIEM systems
- [ ] Machine learning for anomaly detection
- [ ] Multi-architecture support
- [ ] Policy-as-code framework

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Inspired by [Docker Bench for Security](https://github.com/docker/docker-bench-security)
- CIS Docker Benchmark v1.6.0
- OWASP Container Security
- Docker Security Best Practices

---

## Support

- **Issues**: [GitHub Issues](https://github.com/xclusivecyberdev/Container-Security-Scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xclusivecyberdev/Container-Security-Scanner/discussions)
- **Documentation**: [Wiki](https://github.com/xclusivecyberdev/Container-Security-Scanner/wiki)

---

## Citation

If you use this tool in your research or projects, please cite:

```bibtex
@software{docker_security_scanner,
  author = {Docker Security Scanner Team},
  title = {Docker Container Security Scanner},
  year = {2024},
  url = {https://github.com/xclusivecyberdev/Container-Security-Scanner}
}
```

---

<div align="center">

**[⬆ back to top](#docker-container-security-scanner)**

Made with ❤️ for the security community

</div>
