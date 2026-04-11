#!/usr/bin/env bash
# Deterministic init for a soc-agent working directory.
#
# Runs from the soc-agent root (the directory containing this script's parent).
# Idempotent: safe to re-run on an existing workspace. Does NOT invoke the LLM
# and does NOT touch credentials. Preflight and /connect handle those.
#
# Usage:
#   bash scripts/init.sh
#
# What it does:
#   1. Validates Python 3.11+ and git are on PATH.
#   2. Initializes a git repo if the target is not already one.
#   3. Ensures .gitignore covers runs/, .env, __pycache__, .venv/.
#   4. Creates the directory scaffold expected by /connect and /investigate.
#   5. Prints next steps.
#
# What it does NOT do:
#   - Install SIEM-specific deps (that's per-adapter, handled by /connect).
#   - Configure credentials (user's responsibility; /connect tells them which
#     env vars to set but never asks for values).
#   - Modify Claude Code settings (that's the plugin manifest's job).
#   - Touch anything outside the soc-agent directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOC_AGENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '[init] %s\n' "$*"; }
err() { printf '[init] error: %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# 1. Preconditions
# ---------------------------------------------------------------------------

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found on PATH"
    exit 2
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%.*}"
PY_MINOR="${PY_VERSION#*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    err "python 3.11+ required, found $PY_VERSION"
    exit 2
fi

if ! command -v git >/dev/null 2>&1; then
    err "git not found on PATH"
    exit 2
fi

log "python $PY_VERSION OK"
log "git $(git --version | awk '{print $3}') OK"

cd "$SOC_AGENT_DIR"

# ---------------------------------------------------------------------------
# 2. Git init (skip if already a repo)
# ---------------------------------------------------------------------------

if git rev-parse --git-dir >/dev/null 2>&1; then
    log "already inside a git repo — skipping git init"
else
    log "initializing git repo at $SOC_AGENT_DIR"
    git init -q
fi

# ---------------------------------------------------------------------------
# 3. .gitignore — additive, idempotent
# ---------------------------------------------------------------------------

GITIGNORE="$SOC_AGENT_DIR/.gitignore"
touch "$GITIGNORE"

ensure_ignore() {
    local pattern="$1"
    if ! grep -Fxq "$pattern" "$GITIGNORE" 2>/dev/null; then
        printf '%s\n' "$pattern" >> "$GITIGNORE"
        log "added to .gitignore: $pattern"
    fi
}

ensure_ignore "runs/"
ensure_ignore ".env"
ensure_ignore "__pycache__/"
ensure_ignore ".venv/"
ensure_ignore "*.pyc"

# ---------------------------------------------------------------------------
# 4. Directory scaffold
# ---------------------------------------------------------------------------
#
# Existing directories are left alone. Missing ones get created with a
# .gitkeep so git tracks them before they have real content. We do NOT
# touch knowledge/signatures/ or knowledge/common-investigation/ — those
# ship with the plugin.

SCAFFOLD_DIRS=(
    "knowledge/environment/context"
    "knowledge/environment/data-sources"
    "knowledge/environment/operations"
    "knowledge/environment/systems"
    "scripts/tools"
    "runs"
)

for d in "${SCAFFOLD_DIRS[@]}"; do
    if [ ! -d "$SOC_AGENT_DIR/$d" ]; then
        mkdir -p "$SOC_AGENT_DIR/$d"
        touch "$SOC_AGENT_DIR/$d/.gitkeep"
        log "created $d/"
    fi
done

# ---------------------------------------------------------------------------
# 5. Next steps
# ---------------------------------------------------------------------------

cat <<'EOF'

[init] done.

Next steps:
  1. Run /connect in Claude Code to connect your first security system.
     (SIEM, EDR, asset DB, identity system — anything with a queryable API.)

  2. Run `python3 scripts/preflight.py` any time to check the state of
     connected systems and the knowledge base.

  3. Once at least one system is connected, run /investigate on an alert.

See docs/design-v3-init-and-connect.md for the full design.
EOF
