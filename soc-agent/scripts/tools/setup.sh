#!/usr/bin/env bash
# Create a per-integration venv and install dependencies.
# Run once after cloning, or after updating requirements.txt.
# Uses uv if available, falls back to stdlib venv + pip.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

if [ ! -f "$REQ_FILE" ]; then
    echo "error: $REQ_FILE not found" >&2
    exit 1
fi

echo "Setting up venv at $VENV_DIR ..."

if command -v uv &>/dev/null; then
    uv venv "$VENV_DIR" -q
    uv pip install -q -p "$VENV_DIR/bin/python3" -r "$REQ_FILE"
else
    echo "note: uv not found, falling back to stdlib venv + pip (slower)" >&2
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python3" -m pip install -q -r "$REQ_FILE"
fi

echo "Done. Activate with: source $VENV_DIR/bin/activate"
