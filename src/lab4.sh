#!/bin/bash
# lab4.sh - Creates a virtual environment, installs required packages, runs lab4.py, and deactivates the environment.

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

echo "Upgrading pip and installing required packages..."
pip install --upgrade pip
pip install pyshark requests

echo "Running lab4.py..."
python3 lab4.py

echo "Deactivating virtual environment..."
deactivate
