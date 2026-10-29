#!/usr/bin/env python3
"""defender/cli/tenant.py — the connect skill's tenant command (#1214: what is left of the tenant
lifecycle's operator command once the lifecycle became a service).

    python3 defender/cli/tenant.py check <tenant-id> | --folder <path>
    python3 defender/cli/tenant.py update <tenant-id>
    python3 defender/cli/tenant.py propose <tenant-id> <staged dir>

Tenants are created, rotated and offboarded by platform administrators through the API; the
tenant management service and the execution host's actor do the work (the repo from the template,
the bot and its credential, the host folder and its clone, a first publish). The tenant record —
its state, its forge wiring, its credential generations, its last publish outcome — lives in
PostgreSQL, and this command reads it from `DEFENDER_DATABASE_DSN`: `check <id>`, `update` and
`propose` work for a tenant only while it is `active` (#1214 Flow 4). `setup`, `scaffold`,
`new-id` and `migrate` are retired with the on-disk row.

`check` reports what acceptance does not refuse: the grant census against the RUNNING code (a verb
the adapters declare that the table leaves undecided, a row for a verb nobody declares), the
lead-zero agreement, and — for a git clone — that `agent/.tenant-id` is what the tenant's repo
commits (failing closed when git cannot answer). `check <id>` judges the tenant under
`$DEFENDER_DATA_ROOT` through acceptance; `check --folder <path>` judges a tenant repo's working
folder with no data root and no tenant record at all (tenant CI).

`update` publishes (#1108 P4 flow 1): it mints the tenant's forge credential through its live
generation, fetches the recorded origin, fast-forwards the clone, writes the export and points
`current` at it. `check <id>` also reports how far `current` trails the clone's `origin/main` and
the last publish refusal any trigger met (a run launch, a drain start, `update`), so a sealed
issuer or a refused merge is visible (O-SEE). `propose` hands a staged directory shaped like the
tenant's `agent/` root (connect's tenant half: a system skill, seed queries, tacit entries) to the
commit-maker as one PR on the tenant forge; files are added or replaced, nothing is deleted, and
only `agent/` is touched.

Exit status: 0 clean, 1 a finding or a refusal, 2 a usage error. A check that could not judge (the
grant census not taken, `.tenant-id` unverifiable) is one more finding, not a separate code, and
the checks that need no census still run. Every refusal is printed as `[tenant.py] <message>`.
"""
from __future__ import annotations

import argparse
import contextlib
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
from defender.tenancy import SETTINGS_HALF, TENANT_ID_FILE  # noqa: E402
from defender.systems import run_tenant  # noqa: E402
from defender.systems.verb_dispositions import DispositionError, dispositions_path  # noqa: E402
from defender.tenancy import case_ticket  # noqa: E402
from defender.records.formats import TenantRefused

#: How long one git call of `check`'s committed read may take: each is a local lookup of one
#: path, so a call still running is blocked (a FIFO where git expects a file), not slow.
_COMMITTED_READ_TIMEOUT = 15

#: The words `check` fails closed with when git cannot say whether `.tenant-id` is committed.
_CANNOT_VERIFY = "cannot verify .tenant-id is committed"


def _say(message: object) -> None:
    print(f"[tenant.py] {message}", file=sys.stderr)


def _settings_files_parse(settings: Path) -> None:
    """The folder rule run start does not apply before a run: the case-history mapping parses
    (the grant table and the lead-zero config are run start's own, in its readiness
    function)."""
    try:
        case_ticket.check_mapping(settings)
    except case_ticket.CaseTicketError as bad:
        raise TenantRefused(str(bad)) from bad



# ==========================================================================================
# admission (#1214 Flow 4)
# ==========================================================================================

def _admitted(tenant_id: str, directory: tenancy.TenantDirectory | None
              ) -> tuple[tenancy.TenantDirectory, tenancy.Tenant]:
    """The id's grammar and the data root (as run start judges them, before anything else), the
    tenant records (`directory`, else `DEFENDER_DATABASE_DSN`'s after the light version check),
    the tenant `active` in them with its forge wiring, and its folder accepted under
    `$DEFENDER_DATA_ROOT` — or `TenantRefused` at the first that fails, before any work."""
    tenancy.requested_tenant_id(tenant_id)
    data_root = tenancy.resolve_data_root()
    records = run_tenant.entry_directory(directory)
    tenancy.admit_tenant(records, tenant_id)
    tenant = tenancy.accept_tenant(data_root, tenant_id, defender_dir=_DEFENDER_DIR)
    return records, tenant


def _host_held(tenant_id: str) -> contextlib.AbstractContextManager[object]:
    """The tenant's host lock under `$DEFENDER_DATA_ROOT`, held shared for as long as the command
    works for the tenant (`tenancy.hold_tenant`, #1214 P3, Flow 4: lock, then state): the id's
    grammar and the data root first, `TenantRefused` before anything is held."""
    tenancy.requested_tenant_id(tenant_id)
    return tenancy.hold_tenant(tenancy.resolve_data_root(), tenant_id)


# ==========================================================================================
# check
# ==========================================================================================

def check_tenant(tenant_id: str, *, directory: tenancy.TenantDirectory | None = None) -> int:
    """`check <id>`: the tenant admitted and accepted (stopping at its first refusal), then every
    finding about its settings, its repo and its last publish, all reported."""
    try:
        held = _host_held(tenant_id)
    except TenantRefused as refused:
        _say(refused)
        return 1
    with held:
        try:
            records, tenant = _admitted(tenant_id, directory)
        except TenantRefused as refused:
            _say(refused)
            return 1
        return _report([*_findings(tenant.knowledge), *_publish_findings(tenant, records)])


def _publish_findings(tenant: tenancy.Tenant, records: tenancy.TenantDirectory) -> list[str]:
    """O-SEE: how far `current` trails the clone's `origin/main` (as the last fetch left it; no
    network), and the last publish refusal any trigger recorded in the tenant records, while no
    later publish has succeeded. Read locally only."""
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control.status import read_status

    findings: list[str] = []
    try:
        current: str | None = vc.current_export(tenant).commit
    except vc.DeliveryRefused:
        current = None  # never published: nothing trails yet (a refusal is reported below)
    trail = _trail(tenant, current)
    if trail is not None:
        findings.append(trail)
    status = read_status(records, tenant.id)
    if status is not None and status.get("refused"):
        findings.append(
            f"the last publish ({status.get('by', 'unknown trigger')}) was refused "
            f"({status.get('kind', 'operator')}): {status['refused']}")
    return findings


def _trail(tenant: tenancy.Tenant, current: str | None) -> str | None:
    """The finding that `current` trails `origin/main`, or None when it does not (or there is
    no clone with an `origin/main` to compare with)."""
    from defender.learning.author.version_control import DeliveryRefused
    from defender.learning.author.version_control.repository import LocalRepository

    if current is None or not os.path.lexists(tenant.knowledge / ".git"):
        return None
    try:
        repository = LocalRepository.open_local(tenant.knowledge)
        if not repository.holds_ref("refs/remotes/origin/main"):
            return None
        upstream = repository.revision("refs/remotes/origin/main")
        if current == upstream:
            return None
        behind = len(repository.commits_since(current, upstream))
    except (OSError, _git.GitError, ValueError, DeliveryRefused) as unreadable:
        return f"could not compare `current` with origin/main in {tenant.knowledge}: {unreadable}"
    if not behind:
        return None
    return (f"`current` ({current[:12]}) trails origin/main ({upstream[:12]}) by {behind} "
            f"{'commit' if behind == 1 else 'commits'}: the merged knowledge is not published "
            "yet (see the last publish refusal, or run tenant.py update)")


# ==========================================================================================
# update / propose (#1108 P4)
# ==========================================================================================

def _delivery(tenant: tenancy.Tenant, records: tenancy.TenantDirectory, *, client=None, identity=None,
              credential_config=None):
    """The tenant's opened `TenantDelivery` (a context manager): its recorded origin, its forge
    credential minted through its live generation (or the given stand-ins)."""
    from defender.learning.author import version_control as vc

    return vc.opened_delivery(tenant, defender_dir=_DEFENDER_DIR, directory=records, purpose="connect",
                              client=client, identity=identity, credential_config=credential_config)


def _publish(tenant: tenancy.Tenant, records: tenancy.TenantDirectory, *, by: str, client=None,
             identity=None, credential_config=None) -> int:
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control.status import recording

    try:
        with recording(records, tenant.id, by=by), _delivery(
                tenant, records, client=client, identity=identity,
                credential_config=credential_config) as delivery:
            export = delivery.publish()
    except (vc.DeliveryRefused, vc.ForgejoAuthError, TenantRefused) as refused:
        _say(f"publish refused: {refused}")
        return 1
    print(f"published {export.commit} as tenant {tenant.id}'s current knowledge")
    return 0


def update(tenant_id: str, *, directory: tenancy.TenantDirectory | None = None, client=None,
           identity=None, credential_config=None) -> int:
    """`update <id>`: publish the tenant's merged `main` (flow 1). The keywords are in-process
    stand-ins for the tenant records, the forge client, the credential and the host's issuer
    configuration. Refusals print `[tenant.py] ...`, exit 1, and are what `check` reports
    afterwards."""
    try:
        held = _host_held(tenant_id)
    except TenantRefused as refused:
        _say(refused)
        return 1
    with held:
        try:
            records, tenant = _admitted(tenant_id, directory)
        except TenantRefused as refused:
            _say(refused)
            return 1
        return _publish(tenant, records, by="tenant.py update", client=client, identity=identity,
                        credential_config=credential_config)


def propose(tenant_id: str, staged: Path, *, directory: tenancy.TenantDirectory | None = None,
            client=None, identity=None, credential_config=None) -> int:
    """`propose <id> <dir>` under the tenant's host lock (`_proposed`)."""
    try:
        held = _host_held(tenant_id)
    except TenantRefused as refused:
        _say(f"propose refused: {refused}")
        return 1
    with held:
        return _proposed(tenant_id, staged, directory=directory, client=client, identity=identity,
                         credential_config=credential_config)


def _proposed(tenant_id: str, staged: Path, *, directory: tenancy.TenantDirectory | None,
              client: Any, identity: Any, credential_config: Any) -> int:
    """`propose <id> <dir>`: the staged directory (shaped like `agent/`) as one commit-maker
    commit on a branch off the origin's `main`, pushed to the tenant origin with one PR. Files
    are added or replaced; nothing absent from the directory is deleted. A link, a special
    file, `.tenant-id` or a git control name anywhere in it refuses the whole proposal before
    anything is committed. Refusals print `[tenant.py] ...` and exit 1."""
    import secrets
    from dataclasses import replace

    from defender.learning.author import version_control as vc
    from defender.tenancy import regular_files as _regular_files

    try:
        records, tenant = _admitted(tenant_id, directory)
    except TenantRefused as refused:
        _say(f"propose refused: {refused}")
        return 1
    batch = None
    try:
        try:
            files = _regular_files(Path(staged))
        except OSError as unreadable:
            raise vc.DeliveryRefused(f"{staged} could not be read: {unreadable}") from None
        if not files:
            raise vc.DeliveryRefused(f"{staged} stages no file: there is nothing to propose")
        change_set = vc.ChangeSet(tuple(
            vc.AgentChange(f"agent/{rel}", data) for rel, data in sorted(files.items())))
        lanes = sorted({change.path.split("/")[1] for change in change_set
                        if change.path.count("/") >= 2})
        flat = [change.path for change in change_set if change.path.count("/") < 2]
        if flat:
            raise vc.DeliveryRefused(
                f"{', '.join(flat)}: propose stages files below a folder of agent/ only")
        with _delivery(tenant, records, client=client, identity=identity,
                       credential_config=credential_config) as opened:
            delivery = replace(opened, branch_prefix="propose/")
            batch = delivery.start_batch(f"propose-{secrets.token_hex(4)}", lanes=lanes)
            batch.commit(change_set, f"propose: {', '.join(sorted(files))[:200]}")
            delivered = delivery.finish(batch)
    except (vc.DeliveryRefused, vc.ForgejoAuthError, TenantRefused) as refused:
        _say(f"propose refused: {refused}")
        return 1
    finally:
        if batch is not None:
            batch.discard()
    print(f"proposed {len(files)} file(s): {delivered.status}"
          + (f" {delivered.url}" if delivered.url else ""))
    return 0


def check_folder(folder: Path) -> int:
    """`check --folder <path>`: a tenant repo's working folder judged by every rule that needs
    no data root. `agent/.tenant-id` is held to the id grammar only when present, and no
    containment is applied — that belongs to a process that mounts the folder."""
    try:
        tenancy.check_knowledge_folder(folder, tenant_id=None)
    except TenantRefused as refused:
        _say(refused)
        return 1
    return _report(_findings(folder))


def _findings(knowledge: Path) -> list[str]:
    """Everything `check` reports about a folder acceptance (or the folder rules) passed: the
    settings files load, the grant table loads, the lead-zero agreement against the running
    catalog, the grant census both ways against the running checkout, and the committed
    `.tenant-id`. A census that cannot be taken costs only the census: its finding says the
    table went unchecked and why, and every other rule still runs."""
    settings = knowledge / SETTINGS_HALF
    findings: list[str] = []
    try:
        _settings_files_parse(settings)
    except TenantRefused as bad:
        findings.append(str(bad))
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
    try:
        findings += (_tenant_census.table_findings(settings, census).lines(table)
                     if census is not None
                     else _tenant_census.folder_findings(settings).lines())
    except DispositionError as unloadable:
        findings.append(str(unloadable))
    committed = _tenant_id_committed(knowledge)
    if committed is not None:
        findings.append(committed)
    return findings


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

def main(argv: list[str], *, directory: tenancy.TenantDirectory | None = None) -> int:
    """The command line. `directory` is the tenant records a test or a launcher hands in; a
    production process passes none and reads them from `DEFENDER_DATABASE_DSN`."""
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    check_p = sub.add_parser("check", help="report the census and repo findings of a tenant")
    check_p.add_argument("tenant_id", nargs="?")
    check_p.add_argument("--folder", type=Path, default=None)
    update_p = sub.add_parser("update", help="publish the tenant's merged main as `current`")
    update_p.add_argument("tenant_id")
    propose_p = sub.add_parser(
        "propose", help="propose a staged agent/-shaped directory as one PR on the tenant forge")
    propose_p.add_argument("tenant_id")
    propose_p.add_argument("staged", type=Path)
    ns = p.parse_args(argv)
    if ns.command == "update":
        return update(ns.tenant_id, directory=directory)
    if ns.command == "propose":
        return propose(ns.tenant_id, ns.staged, directory=directory)
    if (ns.tenant_id is None) == (ns.folder is None):
        check_p.error("give exactly one of <tenant-id> and --folder")
    if ns.folder is not None:
        return check_folder(ns.folder)
    return check_tenant(ns.tenant_id, directory=directory)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    # Every git call this command makes acts on the folder it names — a tenant's clone, the
    # running checkout the census reads — never on a repository an operator's shell exported
    # (J-PO1), so the repo-locating variables go for the process.
    for _name in _git.REPO_LOCATING_ENV:
        os.environ.pop(_name, None)
    sys.exit(main(sys.argv[1:]))
