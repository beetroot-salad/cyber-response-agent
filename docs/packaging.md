# Packaging & Dependency Strategy

## Principles

1. **Core is stdlib-only.** Hooks, schemas, and scripts use only the Python standard library. This keeps the safety-critical path (validation, state machine) free from external dep risk and installable everywhere.
2. **System-specific deps are per-integration.** Each SIEM CLI manages its own venv and requirements. No cross-contamination between integrations, no conflicts with the host environment.
3. **Dev tools are a separate optional group.** pytest, black, mypy, etc. live in `pyproject.toml [dev]` and are installed via `uv pip install -e '.[dev]'`.

## Why not pyyaml?

The custom YAML parser (`hooks/scripts/frontmatter.py`, ~110 LOC) handles the subset we use: scalars, inline/block lists, one level of nesting. It exists so hooks have zero external dependencies. The trade-off is a small maintenance surface vs. guaranteed portability for safety-critical code. If parsing needs grow beyond this subset, revisit — but for now the custom parser is well-tested and sufficient.

## Dependency layout

```
pyproject.toml
  dependencies = []              # stdlib-only core
  [project.optional-dependencies]
    dev = [pytest, black, ...]   # development tools

scripts/siem/
  requirements.txt               # opensearch-py (Wazuh integration)
  .venv/                          # auto-bootstrapped, git-ignored
  wazuh_cli.py                    # creates .venv on first run
```

## Per-integration venv bootstrap

SIEM CLI scripts auto-create an isolated venv on first invocation:

1. Script checks if it's running from its own `.venv/`
2. If not, creates the venv and installs `requirements.txt` (uses `uv` if available, falls back to stdlib `venv` + `pip`)
3. Re-execs itself with the venv's Python via `os.execv`

Subsequent runs skip straight to step 3 (venv already exists). To force a rebuild, delete the `.venv/` directory.

This pattern repeats for any future integration: add a `requirements.txt` next to the CLI script, copy the `_ensure_venv()` function.

## Why per-integration venvs (not a project-level venv for all deps)

The plugin ships into the user's environment, not as a container image. A project-level venv mixing all SIEM deps could conflict with pre-installed packages (e.g. the user has `opensearch-py==2.x`). Per-integration venvs isolate each CLI's deps completely — the user's environment is never touched, and different integrations can't conflict with each other.

## Install workflow

**Devcontainer** (development):
```bash
# Dockerfile.dev installs system packages + uv
# postCreateCommand installs dev tools:
uv pip install --system -e '.[dev]'
# SIEM venv bootstraps automatically on first CLI invocation
```

**Analyst machine** (distribution):
```bash
# Only need Python 3.11+ and the plugin directory
# No pip install required for core functionality
# SIEM CLI bootstraps its own deps on first run
```
