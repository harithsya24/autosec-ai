#!/bin/bash

# AutoSec AI - Test Runner Script
# Runs all tests and generates coverage report

echo "Running AutoSec AI Test Suite..."
echo "=================================="

# Activate virtual environment if not already active
if [ -z "$VIRTUAL_ENV" ]; then
    echo " Virtual environment not active. Activating..."
    source .venv/bin/activate || source venv/bin/activate
fi

# Install test dependencies if needed
echo " Checking test dependencies..."
pip install -q pytest pytest-asyncio pytest-cov httpx

echo ""
echo " Running tests..."
echo "-------------------"

# Run pytest with coverage
pytest tests/ -v --tb=short --cov=backend --cov-report=term-missing

# Check exit code
if [ $? -eq 0 ]; then
    echo ""
    echo " All tests passed!"
else
    echo ""
    echo " Some tests failed. Check output above."
    exit 1
fi

echo ""
echo " Test Summary Complete"