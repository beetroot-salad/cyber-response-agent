#!/usr/bin/env bash
# Wrapper for the invlang query tool.
# Handles venv activation and module path setup.
# Usage: bash soc-agent/scripts/invlang/run.sh [FLAGS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${SCRIPT_DIR}/../../.venv"

if [[ ! -f "${VENV}/bin/activate" ]]; then
  echo "Error: venv not found at ${VENV}. Run: cd soc-agent && uv sync --extra dev" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "${VENV}/bin/activate"

exec python3 -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}/..')
from invlang.cli import main
sys.exit(main())
" "$@"
