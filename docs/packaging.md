# Packaging & Dependency Strategy

## Principles

1. **Core is stdlib-only.** Hooks, schemas, and scripts use only the Python standard library. This keeps the safety-critical path (validation, state machine) free from external dep risk and installable everywhere.
2. **System-specific deps are per-integration.** Each SIEM CLI has its own venv and requirements, managed by a setup script. No cross-contamination between integrations, no conflicts with the host environment.
3. **Dev tools are a separate optional group.** pytest, black, mypy, etc. live in `pyproject.toml [dev]` and are installed via `uv pip install -e '.[dev]'`.
4. **CLI scripts don't manage their own runtime.** Setup is explicit (run `setup.sh`), not lazy. The CLI either works or gives a clear error pointing to the setup step.

## Why not pyyaml?

The custom YAML parser (`hooks/scripts/frontmatter.py`, ~110 LOC) handles the subset we use: scalars, inline/block lists, one level of nesting. It exists so hooks have zero external dependencies. The trade-off is a small maintenance surface vs. guaranteed portability for safety-critical code. If parsing needs grow beyond this subset, revisit — but for now the custom parser is well-tested and sufficient.

## Dependency layout

```
pyproject.toml
  dependencies = []              # stdlib-only core
  [project.optional-dependencies]
    dev = [pytest, black, ...]   # development tools

scripts/tools/
  setup.sh                        # creates .venv, installs deps (run once)
  requirements.txt                # pinned deps shared across all adapters
  .venv/                          # created by setup.sh, git-ignored
  wazuh_cli.py                    # Wazuh SIEM adapter
  host_query.py                   # Playground host-inspection adapter
```

## Per-integration venv setup

Each SIEM integration directory has a `setup.sh` + `requirements.txt`:

1. `setup.sh` creates a `.venv/` and installs from `requirements.txt`
2. Uses `uv` if available, falls back to stdlib `venv` + `pip`
3. Run once after cloning, or after updating `requirements.txt`
4. To rebuild: delete `.venv/` and re-run `setup.sh`

The CLI script itself has no setup logic — if deps are missing, it prints an error with the setup command and exits.

This pattern repeats for any future integration: add `setup.sh`, `requirements.txt`, and the CLI script.

## Why per-integration venvs (not a project-level venv for all deps)

The plugin ships into the user's environment, not as a container image. A project-level venv mixing all SIEM deps could conflict with pre-installed packages (e.g. the user has `opensearch-py==2.x`). Per-integration venvs isolate each CLI's deps completely — the user's environment is never touched, and different integrations can't conflict with each other.

## Install workflow

**Devcontainer** (development):
```bash
# Dockerfile.dev installs system packages + uv
# postCreateCommand runs both:
uv pip install --system -e '.[dev]'
scripts/tools/setup.sh
```

**Analyst machine** (distribution):
```bash
# Only need Python 3.11+ and the plugin directory
# No pip install required for core functionality
# Set up adapter tool deps (creates scripts/tools/.venv with opensearch-py etc.):
scripts/tools/setup.sh
# Then activate the venv or invoke tools via .venv/bin/python3
```
