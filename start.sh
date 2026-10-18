#!/bin/bash
# VulnExplain — start backend
# Usage: GEMINI_API_KEY=your_key ./start.sh

set -e
cd "$(dirname "$0")/backend"

if [ -z "$GEMINI_API_KEY" ]; then
  echo "⚠️  GEMINI_API_KEY not set. AI explanations will be disabled."
  echo "   Run: GEMINI_API_KEY=your_key ./start.sh"
fi

if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
  venv/bin/pip install -r requirements.txt -q
fi

echo ""
echo "VulnExplain running at http://localhost:8000"
echo "Open http://localhost:8000 in your browser"
echo ""

GEMINI_API_KEY="$GEMINI_API_KEY" venv/bin/python main.py
