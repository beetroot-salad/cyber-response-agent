# Packaging & Dependency Strategy

## Principles

1. **Core is stdlib-only.** Hooks, schemas, and scripts use only the Python standard library. This keeps the safety-critical path (validation, state machine) free from external dep risk and installable everywhere.
2. **All deps declared in `pyproject.toml` extras.** Agent deps (pyyaml, polars) and connector deps (opensearch-py, etc.) each get a named extra. One venv, one lockfile.
3. **Dev tools are the `[dev]` extra.** pytest, black, mypy, and all connector extras are pulled into `[dev]`. `uv sync --extra dev` installs everything for local development.
4. **CLI scripts don't manage their own runtime.** If a dep is missing, the CLI prints `uv sync --extra {extra}  (from soc-agent/)` and exits 2. Setup is explicit, not lazy.

## Why not pyyaml?

The custom YAML parser (`hooks/scripts/frontmatter.py`, ~110 LOC) handles the subset we use: scalars, inline/block lists, one level of nesting. It exists so hooks have zero external dependencies. The trade-off is a small maintenance surface vs. guaranteed portability for safety-critical code. If parsing needs grow beyond this subset, revisit — but for now the custom parser is well-tested and sufficient.

## Dependency layout

```
soc-agent/
  pyproject.toml          # all dep declarations (core + extras)
  uv.lock                 # pinned lockfile — committed to git
  .venv/                  # shared venv — created by uv sync, git-ignored

  [project.optional-dependencies]
    query  = [polars]           # invlang query tool (scripts/invlang/)
    wazuh  = [opensearch-py]    # Wazuh SIEM connector (scripts/tools/wazuh_cli.py)
    dev    = [pytest, black, polars, opensearch-py, ...]  # everything for dev

scripts/tools/
  wazuh_cli.py            # Wazuh SIEM adapter (uses opensearch-py)
  stub_ticket_cli.py      # Reference ActionContract ticketing connector
```

## Adding a new adapter with external deps

1. Write the CLI at `scripts/tools/{system}_cli.py`
2. Add a `[{system}]` extra to `pyproject.toml`:
   ```toml
   [{system}] = ["vendor-sdk>=x.y"]
   ```
3. Add the same dep to `[dev]`
4. Run `uv sync --extra dev` from `soc-agent/` — updates `.venv/` and `uv.lock`
5. Commit `pyproject.toml` and `uv.lock` alongside the adapter script

All adapters share `soc-agent/.venv/bin/python3`. Preflight resolves the venv path automatically from the adapter's location.

## Install workflow

**Devcontainer** (development):
```bash
# postCreateCommand runs:
cd /workspace/soc-agent && uv sync --extra dev
```

**Analyst machine** (distribution):
```bash
# Python 3.11+ and uv required
cd soc-agent && uv sync --extra {system}   # only the connector you need
# or: uv sync --extra dev                  # everything
```
