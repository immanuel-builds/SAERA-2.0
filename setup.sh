#!/bin/bash

# NetVuln - simple setup script

set -e

echo "NetVuln Setup"
echo "============="
echo ""

if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed."
    exit 1
fi

if ! command -v nmap &> /dev/null; then
    echo "Note: nmap is not installed. The project can still run, but scan results may be limited."
else
    echo "nmap is installed."
fi

echo "[1/6] Creating virtual environment..."
python3 -m venv venv

echo "[2/6] Activating virtual environment..."
source venv/bin/activate

echo "[3/6] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f .env ]; then
    echo "[4/6] Creating .env file..."
    cp .env.example .env
else
    echo "[4/6] .env already exists."
fi

echo "[5/6] Applying migrations..."
python manage.py migrate

echo "[6/6] Creating media directories..."
mkdir -p media

echo ""
echo "Setup complete."
echo "Run the app with:"
echo "  python manage.py runserver"
echo ""
echo "Only scan systems you own or have written permission to test."
