#!/usr/bin/env python3
"""defender/cli/tenant.py — the connect skill's tenant command (#1214: what is left of the tenant
lifecycle's operator command once the lifecycle became a service).

    python3 defender/cli/tenant.py check --folder <path>

Tenants are created, rotated and offboarded by platform administrators through the API; the
tenant management service and the execution host's actor do the work (the repo from the template,
the bot and its credential, the host folder and its clone, a first publish). What the command
once did for a tenant on the host is a request to the API now (#1471): the readiness check
(`POST /api/tenants/{tenant_id}/readiness`) judges a tenant's repo and stored records, the adoption request carries a
catalog adapter's base files, and a person's edit to the tenant repo undoes a lesson.

`check --folder <path>` judges a tenant repo's working folder with no data root and no tenant
record at all (tenant CI). It reports what acceptance does not refuse: the grant census against
the RUNNING code (a verb the adapters declare that the table leaves undecided, a row for a verb
nobody declares), retired settings files left in the repo, the tacit-knowledge registry, the
feedback setting, and — for a git clone — that `agent/.tenant-id` is what the tenant's repo
commits (failing closed when git cannot answer). `setup`, `scaffold`, `new-id`, `migrate`,
`update` and `propose` are retired.

Exit status: 0 clean, 1 a finding or a refusal, 2 a usage error. A check that could not judge (the
grant census not taken, `.tenant-id` unverifiable) is one more finding, not a separate code, and
the checks that need no census still run. Every refusal is printed as `[tenant.py] <message>`.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# Hand-rolled rather than `venv_guard.reexec_into_venv`, matching `run.py`: this must run
# BEFORE any `defender.*` import resolves, and reaching that helper is itself such an import.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _DEFENDER_DIR.parent
_VENV = _DEFENDER_DIR / ".venv"
_VENV_PY = _VENV / "bin" / "python3"
# Re-exec only from OUTSIDE the checkout's venv: an interpreter already running in it (by any
# of its names, `python` or `python3`) is the venv, and a command that re-execs itself spawns a
# process DC2 says it never spawns. Either sign counts — the venv's prefix, or an interpreter
# started from the venv's own `bin/` — so a venv missing its `pyvenv.cfg` (whose prefix is
# the base install's) is exec'd at most once, never in a loop.
if (__name__ == "__main__" and _VENV_PY.is_file()
        and Path(sys.prefix).resolve() != _VENV.resolve()
        and Path(sys.executable).parent != _VENV / "bin"):
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if __name__ == "__main__":
    # An operator command writes nothing it does not name, the checkout it runs from included:
    # no bytecode cache lands beside the modules it imports (a refused command leaves every
    # tree as it found it). Only when run: an importer's interpreter is not this command's.
    sys.dont_write_bytecode = True
    # This checkout first — first, not merely present: `defender` is a namespace tree, so each
    # module comes from the first path entry holding it. The command judges a tenant against
    # the code it runs, never against another checkout that a `PYTHONPATH` entry or an
    # editable install points at.
    _root = str(_REPO_ROOT)
    sys.path[:] = [_root, *(entry for entry in sys.path if entry != _root)]

from defender import _git
from defender import tenancy  # noqa: E402
from defender._io import read_plain_bytes  # noqa: E402
from defender.tenancy import AGENT_HALF, SETTINGS_HALF, TENANT_ID_FILE  # noqa: E402
from defender.systems.verbs import is_platform_served  # noqa: E402
from defender.systems.verb_dispositions import (  # noqa: E402
    DispositionError,
    dispositions_path,
)
from defender.records.formats import TenantRefused  # noqa: E402
from defender.cli import _tenant_secrets  # noqa: E402

#: How long one git call of `check`'s committed read may take: each is a local lookup of one
#: path, so a call still running is blocked (a FIFO where git expects a file), not slow.
_COMMITTED_READ_TIMEOUT = 15

#: The words `check` fails closed with when git cannot say whether `.tenant-id` is committed.
_CANNOT_VERIFY = "cannot verify .tenant-id is committed"


_say = _tenant_secrets.say


# ==========================================================================================
# check --folder
# ==========================================================================================

def check_folder(folder: Path) -> int:
    """`check --folder <path>`: a tenant repo's working folder judged by every rule that needs
    no data root. `agent/.tenant-id` is held to the id grammar only when present, and no
    containment is applied — that belongs to a process that mounts the folder."""
    try:
        tenancy.check_knowledge_folder(folder, tenant_id=None)
    except TenantRefused as refused:
        _say(refused)
        # The registry file is judged apart from the folder's acceptance (#1390 A8).
        for finding in _registry_findings(folder):
            _say(finding)
        return 1
    return _report(_findings(folder))


def _findings(knowledge: Path, *, systems: Any = None) -> list[str]:
    """Everything `check --folder` reports about a folder acceptance (or the folder rules) passed: the
    settings files load, the grant table loads, the grant census both ways against the running checkout, and the committed
    `.tenant-id`. A census that cannot be taken costs only the census: its finding says the
    table went unchecked and why, and every other rule still runs."""
    settings = knowledge / SETTINGS_HALF
    findings: list[str] = []
    from defender.cli._tenant_records_check import census_findings, leftover_findings
    findings += leftover_findings(knowledge)
    # Here, not at the top: the census reaches the lead-author's whole extraction stack, which
    # only `check` uses — `update` and `propose` start without paying for it.
    from defender.cli import _tenant_census

    table = dispositions_path(settings)
    census: _tenant_census.Census | None = None
    try:
        census = _tenant_census.take_census(_DEFENDER_DIR)
    except _tenant_census.CensusUnavailable as blind:
        findings.append(
            f"{table} was not checked against the running checkout's adapters (for verbs nobody "
            f"decides, or rows no adapter declares): the grant census could not be taken — {blind}")
    if census is not None:
        findings += [f"adapter `{name}` refused: {why}" for name, why in census.refused.items()
                     if is_platform_served(name)]
    findings += _tenant_findings(knowledge)
    try:
        if census is not None:
            findings += census_findings(_tenant_census.table_findings(settings, census), systems).lines(table)
        else:
            _tenant_census.folder_findings(settings)  # the table still loads, or its refusal is the finding
    except DispositionError as unloadable:
        findings.append(str(unloadable))
    return findings


def _tenant_findings(knowledge: Path) -> list[str]:
    """The findings that need nothing of the tenant's systems: the registry, the feedback setting, the registry's
    grants and the committed `.tenant-id`."""
    findings = [*_registry_findings(knowledge), *_feedback_findings(knowledge), *_registry_grant_findings(knowledge)]
    committed = _tenant_id_committed(knowledge)
    if committed is not None:
        findings.append(committed)
    return findings


def _feedback_findings(knowledge: Path) -> list[str]:
    """The feedback setting (#1414 O1): `feedback_findings` over the folder's `settings/`."""
    from defender.cli._tenant_records_check import feedback_findings

    return feedback_findings(knowledge / SETTINGS_HALF)


def _registry_findings(knowledge: Path) -> list[str]:
    """The tacit-knowledge registry file (`registry_findings` over the folder's `agent/`)."""
    from defender.cli._tenant_records_check import registry_findings

    return registry_findings(knowledge / AGENT_HALF)


def _registry_grant_findings(knowledge: Path) -> list[str]:
    """The registry file against the grant table (`registry_grant_findings`), its note on stderr."""
    from defender.cli._tenant_records_check import registry_grant_findings

    return registry_grant_findings(knowledge / AGENT_HALF, knowledge / SETTINGS_HALF, note=_say)


def _report(findings: list[str]) -> int:
    for finding in findings:
        _say(finding)
    return 1 if findings else 0


def _tenant_id_committed(folder: Path, timeout: float = _COMMITTED_READ_TIMEOUT) -> str | None:
    """For a folder that is a git work tree: `None` when HEAD commits its `agent/.tenant-id`
    as it stands — byte for byte, except that a CRLF checkout of an LF commit (`core.autocrlf`,
    an `eol=crlf` attribute) matches — else the finding: the file untracked, staged only, or
    changed since the commit, or git unable to answer (absent, refusing the repo, any error),
    which fails closed. HEAD's blob is read raw, so git runs no filter or configured command
    over either side. A plain folder has no repo to ask and is exempt. The read ignores an
    exported `GIT_DIR`, and a `.git` that git does not read as a repository rooted at the
    folder (git would answer from an enclosing repo) fails closed too: the answer is the
    folder's own repository's or none. Replace objects are ignored (a `refs/replace` entry
    could stand an edited blob in for the committed one, and a clone does not carry it), and
    each git call is bounded by `timeout` seconds: a `.git` holding a FIFO fails closed rather
    than hanging."""
    rel = TENANT_ID_FILE.as_posix()
    if not os.path.lexists(folder / ".git") or not os.path.lexists(folder / rel):
        return None
    env = {**_git.env_for_cwd(), "GIT_NO_REPLACE_OBJECTS": "1"}
    bound = timeout
    try:
        top = _git.git(["rev-parse", "--show-toplevel"], cwd=folder, env=env, timeout=bound)
        if Path(top).resolve() != folder.resolve():
            return (f"{_CANNOT_VERIFY}: {folder / '.git'} is not a repository of its own — "
                    f"git reads {top}'s instead")
        if _no_commits_yet(folder, env, bound):
            listed = ""  # a repo with no commit commits nothing: "not committed", below
        else:
            listed = _git.git(["ls-tree", "HEAD", "--", rel], cwd=folder, env=env, timeout=bound)
        committed = (_git.git_blob_bytes(folder, listed.split()[2], env=env, timeout=bound)
                     if listed else None)
    except subprocess.TimeoutExpired:
        return f"{_CANNOT_VERIFY}: git did not answer within {bound}s over {folder / '.git'}"
    except OSError as unstarted:
        return f"{_CANNOT_VERIFY}: {_git.unstarted(unstarted)} ({unstarted})"
    except _git.GitError as failed:
        return f"{_CANNOT_VERIFY}: git could not read {folder}'s repository: {failed.stderr}"
    if committed is None:
        return (f"{folder / rel} is not committed: the tenant repo's HEAD does not hold it — "
                "commit it, so every clone names its tenant")
    try:
        working = read_plain_bytes(folder / rel)
    except OSError as unreadable:
        return f"{_CANNOT_VERIFY}: {folder / rel} could not be read: {unreadable}"
    if committed not in (working, working.replace(b"\r\n", b"\n")):
        return (f"{folder / rel} differs from what the tenant repo's HEAD commits — the clone "
                "is another tenant's, or the file was edited by hand; restore it or commit it")
    return None


def _no_commits_yet(folder: Path, env: dict[str, str], bound: float) -> bool:
    """The repository holds no commit at all (a fresh `git init`). A repo with commits whose
    HEAD does not resolve is not this — it is one git cannot read, which the caller's
    `ls-tree` turns into "cannot verify"."""
    return not _git.git(["rev-list", "--max-count=1", "--all"], cwd=folder, env=env,
                        timeout=bound)


# ==========================================================================================
# the command line
# ==========================================================================================

def main(argv: list[str], *, directory: object = None) -> int:
    """The command line: `check --folder <path>`, the only subcommand. `directory` is accepted and ignored: the
    command reads no tenant records, so callers that still hand one in (a launcher's shape) are not a usage error."""
    del directory
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    check_p = sub.add_parser("check", help="judge a tenant repo's working folder")
    check_p.add_argument("--folder", type=Path, required=True)
    ns = p.parse_args(argv)
    return check_folder(ns.folder)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    # Every git call this command makes acts on the folder it names — a tenant's clone, the
    # running checkout the census reads — never on a repository an operator's shell exported
    # (J-PO1), so the repo-locating variables go for the process.
    for _name in _git.REPO_LOCATING_ENV:
        os.environ.pop(_name, None)
    sys.exit(main(sys.argv[1:]))
