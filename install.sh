#!/bin/bash

# Ensure script is executable
chmod +x cyber_sentinel.py

# Install dependencies
pip install -r requirements.txt

# Set up the command alias
echo "alias cybersentinel='python3 $(pwd)/cyber_sentinel.py'" >> ~/.bashrc
source ~/.bashrc

echo "CyberSentinel is ready to use! Type 'cybersentinel' to start."