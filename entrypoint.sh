#!/bin/sh
set -e

# Change to the action directory where our code lives
cd /action

# Run the Python module
exec python -m src.main

