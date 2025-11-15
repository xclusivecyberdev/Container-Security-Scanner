# Dockerfile for Docker Security Scanner CLI

FROM python:3.10-slim

LABEL maintainer="security@example.com"
LABEL description="Docker Container Security Scanner"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    docker.io \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install -e .

# Set entrypoint
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]
