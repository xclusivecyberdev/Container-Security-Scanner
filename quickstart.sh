#!/bin/bash
# Quick start script for Docker Security Scanner

set -e

echo "🔒 Docker Security Scanner - Quick Start"
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker."
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker."
    exit 1
fi

echo "✅ Prerequisites checked"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt
pip install -e .

echo ""
echo "✅ Installation complete!"
echo ""

# Run a test scan
echo "🔍 Running a test scan on alpine:latest..."
echo ""

# Pull alpine image if not present
docker pull alpine:latest > /dev/null 2>&1

# Run scan
python -m cli.main scan-image alpine:latest --severity MEDIUM

echo ""
echo "========================================"
echo "🎉 Quick start complete!"
echo ""
echo "Next steps:"
echo "  1. Scan your own images:"
echo "     python -m cli.main scan-image <image-name>"
echo ""
echo "  2. Start the web dashboard:"
echo "     cd src/dashboard && python app.py"
echo ""
echo "  3. View help:"
echo "     python -m cli.main --help"
echo ""
echo "For more information, see README.md and USAGE.md"
