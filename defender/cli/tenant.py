#!/usr/bin/env python3
"""defender/cli/tenant.py — the connect skill's tenant command (#1214: what is left of the tenant
lifecycle's operator command once the lifecycle became a service).

    python3 defender/cli/tenant.py check <tenant-id> | --folder <path>
    python3 defender/cli/tenant.py update <tenant-id>
    python3 defender/cli/tenant.py propose <tenant-id> <staged dir>
    python3 defender/cli/tenant.py set-alert-mapping <tenant-id> <mapping file>
    python3 defender/cli/tenant.py catalog
    python3 defender/cli/tenant.py import <tenant-id> [--dry-run]
    python3 defender/cli/tenant.py set-system <tenant-id> <system> <folder> --replaces N [--disabled]
    python3 defender/cli/tenant.py delete-system <tenant-id> <system> --replaces N
    python3 defender/cli/tenant.py set-case <tenant-id> <case-record file> --replaces N
    python3 defender/cli/tenant.py delete-case <tenant-id> --replaces N
    python3 defender/cli/tenant.py systems <tenant-id> [--export <dir>] [--token-file <path>]
    python3 defender/cli/tenant.py set-credentials <tenant-id> <system> <file> --for-version N --token-file <path>

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

`set-alert-mapping` (#1345) replaces the tenant's alert mapping, which lives in the database: the file is
YAML naming each of the six entries (signature, event_time, summary, case_key, title, description) with a dotted path
into the raw alert; an entry left out, or `null`, is unmapped. It is validated by the rules the API's `PUT` applies and
stored by the same operation. It applies to alerts stored from then on; stored alerts keep their title and description. It is the production writer
until the API is wired to the real store, and the upgrade path from `settings/alert-mapping.yaml`. The entries:

    signature    the rule key lessons and the corpus are matched on: ASCII letters, digits and . _ : / @ + = - (no leading
                 dash, at most 128 characters), a JSON string or an integer. Anything else records no signature.
    event_time   when the activity happened; carried as it is, never parsed.
    summary      one line of what fired.
    case_key     the ticket a run started with --update-ticket comments on: a field the alerting system sets, never one
                 copied from the logged activity. At most 128 printable ASCII characters, no / \\ ; or whitespace, not
                 only dots; anything else records no key and the run leaves an error receipt.
    title        the alert's name in the alert list and on its runs, cut to 256 characters.
    description  the alert's longer text in the alert list, cut to 4096 characters.

The first four are read once, when a run starts, and recorded beside its alert. Title and description are text or an
integer's decimal text, and otherwise null.

A tenant's systems and its case record (#1366) are records in the database, versioned, and written only by this command
(`_tenant_records` describes each subcommand). `catalog` lists the adapters the product carries: what a system record
may name, with the settings keys each reads. `import` turns a tenant's retired `settings/systems/<s>/` folders and
`settings/case-record.yaml`, as its published export holds them, into first versions, once per tenant (a tenant created
after #1366 is imported at creation); `--dry-run` lists every fault, each naming the file to fix. `set-system` takes a
folder holding the system's `config.env` and `access.yaml` (what connect hands off and `systems --export` writes) and
stores it as the system's next version; `--replaces` names the version it replaces (0: none ever), and a write naming
a version that is no longer current is refused. `set-credentials` stores a system's credential set (a JSON file
`{"kind": ..., "fields": {...}}`) for the version it names, at that version's credential generation, which rises when
the system's address, CA or auth block changes: credentials are then set again. The import copies no credential.

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
from defender.systems import tacit_registry  # noqa: E402
from defender.systems.verbs import is_platform_served  # noqa: E402
from defender.systems import run_tenant  # noqa: E402
from defender.systems.verb_dispositions import (  # noqa: E402
    DispositionError,
    dispositions_path,
    run_grants,
)
from defender.records.formats import TenantRefused  # noqa: E402
from defender.cli import _tenant_records  # noqa: E402
from defender.kit.faults import AdapterFault  # noqa: E402

#: How long one git call of `check`'s committed read may take: each is a local lookup of one
#: path, so a call still running is blocked (a FIFO where git expects a file), not slow.
_COMMITTED_READ_TIMEOUT = 15

#: The words `check` fails closed with when git cannot say whether `.tenant-id` is committed.
_CANNOT_VERIFY = "cannot verify .tenant-id is committed"


_say = _tenant_records.say


# ==========================================================================================
# check
# ==========================================================================================

def check_tenant(admitted: run_tenant.Admitted, *, secrets: Any = None) -> int:
    """`check <id>`, for the tenant `main`'s host acceptance admitted: every finding about its
    settings, its repo and its last publish, all reported. `secrets` is the operator's OpenBao
    login, for the record findings that ask the secret store (#1366)."""
    from defender.cli import _tenant_records_check as records_check
    tenant, records = admitted.tenant, admitted.directory
    mine = records_check.records_check(tenant.id, records, knowledge=tenant.knowledge, secrets=secrets,
                                       defender_dir=_DEFENDER_DIR)
    # Not imported (R8): the import finding in place of every finding about its systems (nothing is judged from the
    # retired folders, which the import still reads); every other finding is reported all the same.
    findings = (_findings(tenant.knowledge, systems=mine.systems) if mine.records is not None
                else _tenant_findings(tenant.knowledge))
    return _report([*mine.lines, *findings, *_mapping_findings(tenant, records), *_publish_findings(tenant, records)])


def _mapping_findings(tenant: tenancy.Tenant, records: tenancy.TenantDirectory) -> list[str]:
    """Every run and new investigation of a tenant with no saved alert mapping is refused (#1345 O4), so it is not ready."""
    from defender.records.formats import ALERT_MAPPING_MISSING

    return [] if records.alert_mapping(tenant.id) is not None else [ALERT_MAPPING_MISSING]


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


def _stored_text(tenant_id: str, mapping: Any, created: bool) -> str:
    """What `set-alert-mapping` prints: the stored mapping, one line per entry."""
    from defender.records.formats import MAPPING_KEYS

    lines = [f"{'saved' if created else 'replaced'} the alert mapping of tenant {tenant_id}:"]
    lines += [f"  {entry}: {mapping.path_of(entry) or '(unmapped)'}" for entry in MAPPING_KEYS]
    return "\n".join(lines)


def set_alert_mapping(admitted: run_tenant.Admitted, mapping: Any) -> int:
    """`set-alert-mapping <id> <file>` for the admitted tenant: the validated `mapping` replaces the tenant's
    through the job store's replace, the one writer (same lock, outcome and job-store audit event as the
    API's `PUT`; no API audit event), over `DEFENDER_DATABASE_DSN`. Refusals print `[tenant.py] ...`, exit 1."""
    import asyncio
    import datetime as _dt

    from sqlalchemy.exc import SQLAlchemyError

    from defender.jobs import JobStore, UnknownReference
    from defender.records.formats import AlertMappingFault

    dsn = os.environ.get(tenancy.database_address_variable(), "")
    if not dsn:
        _say(f"{tenancy.database_address_variable()} is not set: the alert mapping is stored in the database")
        return 1
    tenant_id = admitted.tenant.id

    async def put() -> bool:
        store = JobStore(dsn, clock=lambda: _dt.datetime.now(_dt.UTC))
        try:
            return await store.put_alert_mapping(tenant_id, mapping, actor="tenant.py set-alert-mapping")
        finally:
            await store.close()

    try:
        created = asyncio.run(put())
    except (AlertMappingFault, UnknownReference) as refused:
        _say(refused)
        return 1
    except (OSError, SQLAlchemyError) as fault:
        _say(f"the alert mapping could not be stored: {type(fault).__name__}")
        return 1
    print(_stored_text(str(tenant_id), mapping, created))
    return 0


def _mapping_of_file(file: Path) -> Any:
    """The mapping in `file`, or a printed refusal and `None`."""
    from defender.records.formats import AlertMappingFault, parse_mapping

    try:
        raw = read_plain_bytes(file)
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as fault:
        _say(f"{file} cannot be read as UTF-8 text: {type(fault).__name__}")
        return None
    try:
        return parse_mapping(text)
    except AlertMappingFault as fault:
        _say(f"{file}: {fault}")
        return None


def update(admitted: run_tenant.Admitted, *, client=None, identity=None, credential_config=None) -> int:
    """`update <id>`: publish the admitted tenant's merged `main` (flow 1). The keywords are
    in-process stand-ins for the forge client, the credential and the host's issuer
    configuration. Refusals print `[tenant.py] ...`, exit 1, and are what `check` reports
    afterwards."""
    return _publish(admitted.tenant, admitted.directory, by="tenant.py update", client=client,
                    identity=identity, credential_config=credential_config)


def propose(admitted: run_tenant.Admitted, staged: Path, *, client=None, identity=None,
            credential_config=None) -> int:
    """`propose <id> <dir>` for the admitted tenant (`_proposed`)."""
    return _proposed(admitted, staged, client=client, identity=identity, credential_config=credential_config)


def _proposed(admitted: run_tenant.Admitted, staged: Path, *,
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

    records, tenant = admitted.directory, admitted.tenant
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
        # The registry file is judged apart from the folder's acceptance (#1390 A8).
        for finding in _registry_findings(folder):
            _say(finding)
        return 1
    return _report(_findings(folder))


def _findings(knowledge: Path, *, systems: Any = None) -> list[str]:
    """Everything `check` reports about a folder acceptance (or the folder rules) passed: the
    settings files load, the grant table loads, the lead-zero agreement against the running
    catalog, the grant census both ways against the running checkout, and the committed
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
        findings += (census_findings(_tenant_census.table_findings(settings, census), systems).lines(table)
                     if census is not None
                     else _tenant_census.folder_findings(settings).lines())
    except DispositionError as unloadable:
        findings.append(str(unloadable))
    return findings


def _tenant_findings(knowledge: Path) -> list[str]:
    """The findings that need nothing of the tenant's systems: the registry, the feedback setting, the registry's
    grants and the committed `.tenant-id`. A tenant not yet imported gets these too (R8)."""
    findings = [*_registry_findings(knowledge), *_feedback_findings(knowledge), *_registry_grant_findings(knowledge)]
    committed = _tenant_id_committed(knowledge)
    if committed is not None:
        findings.append(committed)
    return findings


def _feedback_findings(knowledge: Path) -> list[str]:
    """The feedback setting (#1414 O1): an unreadable file, or one naming an unknown outcome."""
    from defender.tenancy import feedback_setting

    try:
        feedback_setting.load_feedback_outcomes(knowledge / SETTINGS_HALF)
    except feedback_setting.FeedbackSettingError as bad:
        return [str(bad)]
    return []


def _registry_findings(knowledge: Path) -> list[str]:
    """The tacit-knowledge registry file judged by what `tacit_cli check` fails on (a whole-file
    refusal or a dropped entry, #1390 O7), whether or not the grant table reaches `lookup`
    (A10). Date-dependent notes stay advisory, so a tenant's CI does not go red by the calendar."""
    path = tacit_registry.registry_path(knowledge / AGENT_HALF)
    return [f"{tacit_registry.SYSTEM} registry: {why}"
            for why in tacit_registry.read_registry(path).problems]


def _registry_grant_findings(knowledge: Path) -> list[str]:
    """The registry file against the grant table, which only this check holds together: `lookup`
    granted with no file behind it fails. Entries with no `lookup` grant only earn a note, since
    a tenant may write them before it grants the verb. An unloadable table is reported where the
    table is judged, so it costs only this comparison."""
    try:
        gather = run_grants(knowledge / SETTINGS_HALF).gather
    except DispositionError:
        return []
    granted = any(system == tacit_registry.SYSTEM and verb == "lookup"
                  for system, verb, _ in gather.entries)
    read = tacit_registry.read_registry(tacit_registry.registry_path(knowledge / AGENT_HALF))
    if granted and read.absent:
        return [f"{tacit_registry.SYSTEM} registry: gather is granted `lookup`, but there is no "
                "registry file for it to read"]
    if read.entries and not granted:
        _say(f"note: {tacit_registry.SYSTEM} registry holds {len(read.entries)} entr(ies), but "
             "gather is not granted `lookup`, so none of them is consulted yet")
    return []


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

def main(  # noqa: PLR0913 — the command line plus its in-process stand-ins
    argv: list[str], *, directory: tenancy.TenantDirectory | None = None, client=None, identity=None,
    credential_config=None, secrets=None,
) -> int:
    """The command line. `directory` is the tenant records a test or a launcher hands in; a
    production process passes none and reads them from `DEFENDER_DATABASE_DSN`. `client`,
    `identity` and `credential_config` are in-process stand-ins for the forge client, the
    tenant's credential and the host's issuer configuration (`update`, `propose`); `secrets` is
    the operator's OpenBao login (`OpenBaoSecrets`) that `set-credentials`, `systems` and `check`
    use, else built from `--token-file`.

    `check <id>`, `update` and `propose` work for the tenant through the one host acceptance
    (r10 A1), held for the whole command: this process recorded under the tenant's host lock,
    the tenant `active` with its forge wiring, its folder accepted — or `[tenant.py] ...`, exit
    1, at the first refusal, before any work."""
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    check_p = sub.add_parser("check", help="report the census and repo findings of a tenant")
    check_p.add_argument("tenant_id", nargs="?")
    check_p.add_argument("--folder", type=Path, default=None)
    check_p.add_argument("--token-file", type=Path, default=None,
                         help="a file holding the operator's OpenBao token: also report systems with no credentials")
    check_p.add_argument("--kv-mount", default="kv", help="the KV mount credential sets are stored on (default kv)")
    update_p = sub.add_parser("update", help="publish the tenant's merged main as `current`")
    update_p.add_argument("tenant_id")
    propose_p = sub.add_parser(
        "propose", help="propose a staged agent/-shaped directory as one PR on the tenant forge")
    propose_p.add_argument("tenant_id")
    propose_p.add_argument("staged", type=Path)
    mapping_p = sub.add_parser(
        "set-alert-mapping", help="replace the tenant's alert mapping (stored in the database) from a YAML file")
    mapping_p.add_argument("tenant_id")
    mapping_p.add_argument("file", type=Path)
    _record_parsers(sub)
    ns = p.parse_args(argv)
    if ns.command == "catalog":
        return _tenant_records.catalog(_DEFENDER_DIR)
    mapping = None
    if ns.command == "set-alert-mapping":
        mapping = _mapping_of_file(ns.file)
        if mapping is None:
            return 1
    if ns.command == "check":
        if (ns.tenant_id is None) == (ns.folder is None):
            check_p.error("give exactly one of <tenant-id> and --folder")
        if ns.folder is not None:
            return check_folder(ns.folder)
    try:
        admitted = run_tenant.host_tenant(tenancy.resolve_data_root(), ns.tenant_id, directory=directory,
                                          defender_dir=_DEFENDER_DIR)
    except TenantRefused as refused:
        _say(f"propose refused: {refused}" if ns.command == "propose" else refused)
        return 1
    with admitted:
        try:
            return _admitted_dispatch(admitted, ns, mapping, client=client, identity=identity,
                                      credential_config=credential_config, secrets=secrets)
        except AdapterFault as fault:  # the secret store's every refusal (a bad mount, OpenBao down or refusing): one line
            _say(f"{type(fault).__name__}: {fault}")
            return 1


def _admitted_dispatch(  # noqa: PLR0913 — main's seams, passed through
        admitted: run_tenant.Admitted, ns: argparse.Namespace, mapping: Any, *, client: Any, identity: Any,
        credential_config: Any, secrets: Any) -> int:
    if ns.command in _RECORD_COMMANDS:
        return _record_command(admitted, ns, secrets=secrets)
    if ns.command == "set-alert-mapping":
        return set_alert_mapping(admitted, mapping)
    return _admitted_command(admitted, ns, client=client, identity=identity,
                             credential_config=credential_config, secrets=secrets)


def _admitted_command(admitted: run_tenant.Admitted, ns: argparse.Namespace, *, client: Any, identity: Any,
                      credential_config: Any, secrets: Any) -> int:
    """`update`, `propose` or `check <id>` for the admitted tenant."""
    if ns.command == "update":
        return update(admitted, client=client, identity=identity, credential_config=credential_config)
    if ns.command == "propose":
        return propose(admitted, ns.staged, client=client, identity=identity,
                       credential_config=credential_config)
    if secrets is None and ns.token_file is not None:
        secrets = _tenant_records.operator_secrets(ns.token_file, mount=ns.kv_mount)
        if secrets is None:
            return 1
    return check_tenant(admitted, secrets=secrets)


#: The record subcommands (#1366 DC8) that work for an admitted tenant (`catalog` needs none).
_RECORD_COMMANDS = frozenset({"import", "set-system", "delete-system", "set-case", "delete-case", "systems",
                              "set-credentials"})


def _record_parsers(sub: Any) -> None:
    """The record subcommands' arguments (#1366 DC8)."""
    sub.add_parser("catalog", help="list the adapters the product carries and the settings keys each reads")
    import_p = sub.add_parser("import", help="turn the tenant's retired settings folders into its first records, once")
    import_p.add_argument("tenant_id")
    import_p.add_argument("--dry-run", action="store_true", help="list every fault and write nothing")
    set_p = sub.add_parser("set-system", help="store a folder (config.env, access.yaml) as a system's next version")
    set_p.add_argument("tenant_id")
    set_p.add_argument("system")
    set_p.add_argument("folder", type=Path)
    set_p.add_argument("--replaces", type=int, required=True, help="the version it replaces (0: none ever)")
    set_p.add_argument("--disabled", action="store_true", help="store the system disabled")
    del_p = sub.add_parser("delete-system", help="delete a system's record (a new version)")
    del_p.add_argument("tenant_id")
    del_p.add_argument("system")
    del_p.add_argument("--replaces", type=int, required=True)
    case_p = sub.add_parser("set-case", help="store a case-record file as the tenant's next case record")
    case_p.add_argument("tenant_id")
    case_p.add_argument("file", type=Path)
    case_p.add_argument("--replaces", type=int, required=True)
    del_case_p = sub.add_parser("delete-case", help="delete the tenant's case record (a new version)")
    del_case_p.add_argument("tenant_id")
    del_case_p.add_argument("--replaces", type=int, required=True)
    systems_p = sub.add_parser("systems", help="list the tenant's current systems, or export each as a folder")
    systems_p.add_argument("tenant_id")
    systems_p.add_argument("--export", type=Path, default=None, metavar="DIR")
    cred_p = sub.add_parser("set-credentials", help="store a system's credentials for its current version")
    cred_p.add_argument("tenant_id")
    cred_p.add_argument("system")
    cred_p.add_argument("file", type=Path)
    cred_p.add_argument("--for-version", type=int, required=True)
    for parser in (systems_p, cred_p):
        parser.add_argument("--token-file", type=Path, default=None, help="a file holding the operator's OpenBao token")
        parser.add_argument("--kv-mount", default="kv", help="the KV mount credential sets are stored on (default kv)")


def _record_command(admitted: run_tenant.Admitted, ns: argparse.Namespace, *, secrets: Any) -> int:
    """One record subcommand for the admitted tenant."""
    if ns.command == "import":
        return _tenant_records.run_import(admitted, dry_run=ns.dry_run)
    if ns.command == "set-system":
        return _tenant_records.run_set_system(admitted, ns.system, ns.folder, replaces=ns.replaces,
                                              disabled=ns.disabled)
    if ns.command == "delete-system":
        return _tenant_records.run_delete_system(admitted, ns.system, replaces=ns.replaces)
    if ns.command == "set-case":
        return _tenant_records.run_set_case(admitted, ns.file, replaces=ns.replaces)
    if ns.command == "delete-case":
        return _tenant_records.run_delete_case(admitted, replaces=ns.replaces)
    if secrets is None and (ns.command == "set-credentials" or ns.token_file is not None):
        secrets = _tenant_records.operator_secrets(ns.token_file, mount=ns.kv_mount)
        if secrets is None:
            return 1
    if ns.command == "systems":
        return _tenant_records.run_systems(admitted, export=ns.export, secrets=secrets)
    return _tenant_records.run_set_credentials(admitted, ns.system, ns.file, for_version=ns.for_version,
                                               secrets=secrets)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    # Every git call this command makes acts on the folder it names — a tenant's clone, the
    # running checkout the census reads — never on a repository an operator's shell exported
    # (J-PO1), so the repo-locating variables go for the process.
    for _name in _git.REPO_LOCATING_ENV:
        os.environ.pop(_name, None)
    sys.exit(main(sys.argv[1:]))
