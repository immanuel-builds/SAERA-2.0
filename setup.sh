#!/bin/bash

# SAERA - Security Assessment & External Risk Analysis - Setup Script
# This script automates the initial setup of the Django project

set -e  # Exit on any error

echo "SAERA - Security Setup Console"
echo "=================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "Note: nmap is not installed. The built-in socket scanner will be used."
    echo "Install nmap for richer service detection and larger CIDR scans:"
    echo "  macOS: brew install nmap"
    echo "  Ubuntu/Debian: sudo apt-get install nmap"
    echo ""
else
    echo "nmap is installed - enhanced scanning available."
fi

# Check if Redis is running
echo "Checking for Redis..."
REDIS_RUNNING=0
if command -v redis-cli &> /dev/null && redis-cli ping &> /dev/null; then
    REDIS_RUNNING=1
fi

if [ "$REDIS_RUNNING" -eq 1 ]; then
    echo "Redis is running."
else
    echo "Warning: Redis is not running or not installed."
    echo "The app will run in synchronous mode."
    echo ""
fi

# Create virtual environment
echo "[1/8] Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "[2/8] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[3/8] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[4/8] Installing Python dependencies..."
pip install -r requirements.txt

# Copy .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "[5/8] Creating .env file from template..."
    cp .env.example .env
    echo "Please edit .env file and set your SECRET_KEY and other configuration."
else
    echo "[5/8] .env file already exists, skipping..."
fi

if [ "$REDIS_RUNNING" -eq 0 ]; then
    if grep -qi '^CELERY_TASK_ALWAYS_EAGER=' .env; then
        sed -i.bak 's/^CELERY_TASK_ALWAYS_EAGER=.*/CELERY_TASK_ALWAYS_EAGER=True/' .env
        rm -f .env.bak
    else
        echo "CELERY_TASK_ALWAYS_EAGER=True" >> .env
    fi
fi

# Make migrations
echo "[6/8] Creating database migrations..."
python manage.py makemigrations

#Apply migrations
echo "[7/8] Applying database migrations..."
python manage.py migrate

# Create media directories
echo "[8/8] Creating media directories..."
mkdir -p media/reports

echo ""
echo "=================================="
echo "Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Edit .env file and set your configuration"
echo "2. Create a superuser: python manage.py createsuperuser"
echo "3. Start Django: python manage.py runserver"
echo "4. Optional async mode: start Redis, set CELERY_TASK_ALWAYS_EAGER=False, then run celery -A config worker -l info"
echo ""
echo "Access the application at: http://localhost:8000"
echo ""
echo "IMPORTANT: Only use this tool on networks you own or have permission to test!"
echo ""
