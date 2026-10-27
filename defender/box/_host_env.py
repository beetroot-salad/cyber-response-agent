"""The environment every host child starts from: one scrub of provider API keys and issuer login
variables, and a run's variables on top of it."""

from __future__ import annotations

import os
import re
from pathlib import Path

from defender import providers
from defender.records import RunPaths

#: Variables that may carry knowledge-delivery login material (an OpenBao/Vault token, an
#: AppRole `role_id`/`secret_id`, a forge token): no host child is ever handed one (#1108 P4 O8,
#: P-4: login material is file-only and reaches a delivery process only by its config file). A
#: name is matched anywhere in it, so `ISSUERS_URL` and `BAOTOKEN` are login names too.
_ISSUER_NAME = re.compile(
    r"BAO|VAULT|OPENBAO|ISSUER|APPROLE|ROLE_ID|SECRET_ID|FORGEJO_TOKEN", re.IGNORECASE)


def _issuer_variable(name: str) -> bool:
    return _ISSUER_NAME.search(name) is not None


def provider_scrubbed_environ() -> dict[str, str]:
    """The process's environment as a copy, with every registered provider's API-key variable
    and every issuer/forge login variable (`_issuer_variable`) removed — the base of every host
    child's environment (`run_env` adds a run's variables on top; the branch launcher's write
    door, which has no run yet, takes it as is). The ONE scrub, so no host child is handed a
    registered provider's key or an operator's issuer token by a caller that forgot to drop it."""

    env = {k: v for k, v in os.environ.items() if not _issuer_variable(k)}
    for var in providers.api_key_vars():
        env.pop(var, None)
    return env


def run_env(
    defender_dir: Path, run_dir: Path, *, tenant_agent: Path | None = None,
) -> dict[str, str]:
    env = provider_scrubbed_environ()
    env["DEFENDER_DIR"] = str(defender_dir)
    env.pop("DEFENDER_AGENT_DIR", None)
    if tenant_agent is not None:
        env["DEFENDER_AGENT_DIR"] = str(tenant_agent)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = RunPaths(run_dir).runs_base_export()
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # Prepended: host subprocesses also need the operator's own PYTHONPATH entries.
    env["PYTHONPATH"] = _prepend(str(defender_dir.parent), env.get("PYTHONPATH"))
    # A host lane never carries the in-box mark, even if the operator's shell set it.
    env.pop("DEFENDER_BOX", None)
    return env


def _prepend(head: str, tail: str | None) -> str:
    return f"{head}{os.pathsep}{tail}" if tail else head
