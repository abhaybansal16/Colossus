#!/bin/bash

# Check for root privileges, as we'll be writing to /usr/local/bin
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo: sudo bash install.sh"
  exit 1
fi

echo "✅ Starting Colossus installation..."

# 1. Check for dependencies
if ! command -v python3 &> /dev/null || ! command -v pip3 &> /dev/null; then
    echo "❌ Error: python3 and/or pip3 are not installed. Please install them and try again."
    exit 1
fi
echo "   - Python 3 and pip3 found."
pip3 install colorama > /dev/null 2>&1
echo "   - Dependencies installed."

# 2. Make the script executable
echo "   - Making Colossus executable..."
chmod +x colossus

# 3. Create the destination directory if it doesn't exist (THIS IS THE KEY)
echo "   - Ensuring /usr/local/bin exists..."
mkdir -p /usr/local/bin

# 4. Move the script to the directory
echo "   - Installing Colossus to /usr/local/bin/..."
mv colossus /usr/local/bin/

echo ""
echo "✅ Colossus installation complete! 🎉"
echo "   Open a new terminal and try it out by running: colossus -h"