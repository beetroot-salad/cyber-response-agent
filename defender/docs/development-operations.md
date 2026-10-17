# Development operations

Read only when bootstrapping a development environment, running an investigation, or diagnosing tenant setup.
These are existing CLI procedures, not the desired user onboarding API. Tenant registration belongs
in the product API and its register-tenant command; this cleanup does not implement that interface.
Check the current command's help before using a procedure below.

In this devcontainer use `DEFENDER_DATA_ROOT=/workspace/.defender-data` (gitignored), so the
remote Docker daemon can resolve bind sources. There is no default data root; name the tenant.

## Existing commands and setup

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'   # bootstrap (entrypoints re-exec into .venv themselves)
export DEFENDER_DATA_ROOT=/path/outside/the/checkout   # every run names its tenant; there is no default (#1078)
git clone <tenant repo> "$DEFENDER_DATA_ROOT/playground/knowledge"   # the tenant's settings + agent knowledge, on the host
python3 defender/scripts/tenant.py migrate playground "$DEFENDER_DATA_ROOT/playground/knowledge"   # one-off, INSTEAD of the clone, for a data root made before #1120 (no knowledge/ yet); then setup
python3 defender/scripts/tenant.py setup playground    # once, after the clone exits 0, before the first run
python3 defender/run.py <alert.json> --tenant playground   # one investigation → run dir under $DEFENDER_DATA_ROOT/playground/runs/; --no-learn skips curation enqueue
python3 defender/learning/branch/cli.py --tenant playground <run_id> <branch_message_id>   # fork a finished run (by id, under the tenant's runs) into a family of worlds and grade it
python3 defender/learning/loop.py --author-drain     # fold the findings queue into lessons; --lead-author-drain is the sibling stage
python3 defender/api/serve.py --tenant <id>           # the stub platform API on 127.0.0.1:8000, seeded for the named tenant(s) (needs the `api` extra: `uv sync --extra dev --extra runtime --extra api`, as CI does — a bare `uv sync --extra api` uninstalls the others); tokens `<id>-analyst`
```

Run `tenant.py setup` once, from the main checkout, with `DEFENDER_DATA_ROOT` set (there is no
default data root), after the clone into `<root>/<id>/knowledge` has exited 0 (clone with a
credential helper or an ssh agent, never a credential in the URL; setup adopts the folder and
copies nothing), and no run, fork or drain in flight on any checkout of the host, as the same
user that runs defender; a destination already occupied makes setup refuse, naming it in the
message. (Adopting an existing (B)/(C) installation whose old entries are root-owned may need
setup run as root — that adoption case only.)
