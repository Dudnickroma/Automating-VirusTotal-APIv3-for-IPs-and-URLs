#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Python dependencies from requirements.txt..."
python3 -m pip install --user -r "$ROOT_DIR/requirements.txt"

if [[ -z "${VT_API_KEY:-}" ]]; then
  echo
  echo "VT_API_KEY is not set."
  echo "That's okay: the Python script now prompts for your API key securely at runtime."
  echo "(Or set it once in your environment with: export VT_API_KEY=\"your_api_key_here\")"
fi

echo
echo "Setup complete. VT_API_KEY is available."
echo "Run a single URL scan with:"
echo '  python3 vt-ip-url-analysis.py -s google.com'
