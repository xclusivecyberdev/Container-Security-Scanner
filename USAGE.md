# Usage Guide

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Advanced Scanning](#advanced-scanning)
3. [Report Generation](#report-generation)
4. [Web Dashboard](#web-dashboard)
5. [CI/CD Integration](#cicd-integration)
6. [Configuration](#configuration)
7. [Best Practices](#best-practices)

---

## Basic Usage

### Scanning a Docker Image

The most basic usage is to scan a Docker image:

```bash
python -m cli.main scan-image nginx:latest
```

This will run all available scanners and display results in the terminal.

### Scanning a Running Container

To scan a running container:

```bash
python -m cli.main scan-container my-container
```

### Listing Available Scanners

To see all available scanners:

```bash
python -m cli.main list-scanners
```

---

## Advanced Scanning

### Running Specific Scanners

You can run only specific scanners:

```bash
# Only scan for secrets
python -m cli.main scan-image myapp:latest --scan-secrets

# Scan for misconfigurations and benchmark compliance
python -m cli.main scan-image myapp:latest \
  --scan-misconfig \
  --scan-benchmark

# Multiple specific scanners
python -m cli.main scan-image myapp:latest \
  --scan-secrets \
  --scan-packages \
  --scan-privileges
```

### Filtering by Severity

Filter results by minimum severity level:

```bash
# Only show HIGH and CRITICAL issues
python -m cli.main scan-image nginx:latest --severity HIGH

# Only show CRITICAL issues
python -m cli.main scan-image nginx:latest --severity CRITICAL
```

---

## Report Generation

### JSON Reports

Generate machine-readable JSON reports:

```bash
python -m cli.main scan-image nginx:latest \
  --format json \
  --output scan-results.json
```

JSON structure:
```json
{
  "scan_metadata": {
    "target": "nginx:latest",
    "type": "image",
    "scan_date": "2024-01-01T00:00:00",
    "total_findings": 42
  },
  "summary": {
    "CRITICAL": 2,
    "HIGH": 10,
    "MEDIUM": 15,
    "LOW": 10,
    "INFO": 5
  },
  "findings": [...]
}
```

### HTML Reports

Generate interactive HTML reports:

```bash
python -m cli.main scan-image nginx:latest \
  --format html \
  --output security-report.html
```

The HTML report includes:
- Color-coded severity indicators
- Expandable finding details
- Summary charts
- Remediation guidance

### PDF Reports

Generate professional PDF reports:

```bash
python -m cli.main scan-image nginx:latest \
  --format pdf \
  --output security-report.pdf
```

PDF reports are ideal for:
- Compliance documentation
- Executive summaries
- Audit trails

### Text Reports

Save text reports to file:

```bash
python -m cli.main scan-image nginx:latest \
  --format text \
  --output scan-results.txt
```

---

## Web Dashboard

### Starting the Dashboard

```bash
cd src/dashboard
python app.py
```

Access at: http://localhost:5000

### Dashboard Features

1. **Select Target**
   - Choose between images and containers
   - Auto-populated from your Docker environment

2. **Configure Scan**
   - Select specific scanners
   - Set severity thresholds

3. **View Results**
   - Interactive result viewer
   - Filter by severity
   - Export reports

4. **Scan History**
   - Track previous scans
   - Compare results over time

### API Endpoints

The dashboard provides REST API endpoints:

```bash
# List images
curl http://localhost:5000/api/images

# Scan an image
curl -X POST http://localhost:5000/api/scan/image \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:latest", "scanners": ["all"]}'

# Get scan results
curl http://localhost:5000/api/scan/0

# Get statistics
curl http://localhost:5000/api/stats
```

---

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:latest .

      - name: Install scanner
        run: |
          pip install -r requirements.txt
          pip install -e .

      - name: Run security scan
        run: |
          python -m cli.main scan-image myapp:latest \
            --format json \
            --output scan-results.json

      - name: Check results
        run: |
          CRITICAL=$(jq '.summary.CRITICAL' scan-results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: scan-results.json
```

### GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  image: python:3.10
  services:
    - docker:dind
  script:
    - pip install -r requirements.txt
    - pip install -e .
    - docker build -t $CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA .
    - python -m cli.main scan-image $CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA
        --format json --output scan.json
    - |
      if [ $(jq '.summary.CRITICAL' scan.json) -gt 0 ]; then
        exit 1
      fi
  artifacts:
    paths:
      - scan.json
```

### Jenkins

Add to `Jenkinsfile`:

```groovy
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    python -m cli.main scan-image myapp:${BUILD_NUMBER} \
                        --format json --output scan.json
                '''

                script {
                    def results = readJSON file: 'scan.json'
                    if (results.summary.CRITICAL > 0) {
                        error("Critical vulnerabilities detected")
                    }
                }
            }
        }
    }
}
```

---

## Configuration

### Configuration File

Create `scan-config.yaml`:

```yaml
scanners:
  image_vulnerability:
    enabled: true
    timeout: 300

  package_vulnerability:
    enabled: true
    timeout: 600

  secrets:
    enabled: true
    max_file_size: 10485760
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

Use configuration:

```bash
python -m cli.main scan-image nginx:latest --config scan-config.yaml
```

### Environment Variables

Set environment variables:

```bash
# Set API keys
export NVD_API_KEY="your-api-key"

# Configure output directory
export SCAN_OUTPUT_DIR="/path/to/reports"

# Set severity threshold
export MIN_SEVERITY="HIGH"
```

---

## Best Practices

### 1. Regular Scanning

Scan images regularly:

```bash
# Scan all local images
for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
    python -m cli.main scan-image $image --format json \
        --output "reports/${image//[:\/]/-}.json"
done
```

### 2. Pre-Deployment Gates

Always scan before deployment:

```bash
#!/bin/bash
IMAGE=$1

python -m cli.main scan-image $IMAGE --format json --output scan.json

CRITICAL=$(jq '.summary.CRITICAL' scan.json)

if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Deployment blocked: Critical vulnerabilities"
    exit 1
fi

echo "✅ Security check passed"
```

### 3. Automated Remediation

Create remediation scripts:

```python
import json

with open('scan-results.json') as f:
    results = json.load(f)

for finding in results['findings']:
    if finding['severity'] == 'CRITICAL':
        print(f"CRITICAL: {finding['title']}")
        print(f"Fix: {finding['remediation']}")
        print()
```

### 4. Continuous Monitoring

Set up scheduled scans:

```bash
# Add to crontab
0 2 * * * /path/to/scan-all-images.sh
```

### 5. Integration with SIEM

Export to SIEM systems:

```bash
python -m cli.main scan-image nginx:latest \
    --format json | \
    curl -X POST https://siem.example.com/api/events \
        -H "Content-Type: application/json" \
        -d @-
```

---

## Troubleshooting

### Docker Socket Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Or run with sudo
sudo python -m cli.main scan-image nginx:latest
```

### Large Images Timeout

Increase timeout in configuration:

```yaml
scanners:
  package_vulnerability:
    timeout: 1200  # 20 minutes
```

### Memory Issues

Run specific scanners separately:

```bash
# Scan in stages
python -m cli.main scan-image large-image:latest --scan-image
python -m cli.main scan-image large-image:latest --scan-packages
python -m cli.main scan-image large-image:latest --scan-secrets
```

---

## Examples

### Example 1: Nightly Security Audit

```bash
#!/bin/bash
# nightly-audit.sh

DATE=$(date +%Y-%m-%d)
REPORT_DIR="/reports/$DATE"
mkdir -p "$REPORT_DIR"

for image in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
    echo "Scanning $image..."

    python -m cli.main scan-image "$image" \
        --format html \
        --output "$REPORT_DIR/${image//[:\/]/-}.html"
done

echo "Audit complete. Reports in $REPORT_DIR"
```

### Example 2: Pre-Push Hook

```bash
#!/bin/bash
# .git/hooks/pre-push

IMAGE=$(git config --get docker.image)

if [ -n "$IMAGE" ]; then
    echo "Running security scan on $IMAGE..."

    python -m cli.main scan-image "$IMAGE" \
        --format json \
        --output /tmp/scan.json \
        --severity HIGH

    CRITICAL=$(jq '.summary.CRITICAL' /tmp/scan.json)

    if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Push blocked: Critical vulnerabilities found"
        exit 1
    fi
fi
```

### Example 3: Multi-Stage Pipeline

```bash
#!/bin/bash
# pipeline.sh

# Stage 1: Build
docker build -t myapp:latest .

# Stage 2: Quick scan
python -m cli.main scan-image myapp:latest \
    --scan-secrets \
    --scan-misconfig \
    --severity CRITICAL

# Stage 3: Full scan (if quick scan passes)
python -m cli.main scan-image myapp:latest \
    --format json \
    --output full-scan.json

# Stage 4: Deploy (if all checks pass)
docker push myapp:latest
```

---

For more information, see the [README](README.md) or open an issue on GitHub.
