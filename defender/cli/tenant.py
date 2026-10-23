#!/usr/bin/env python3
"""defender/cli/tenant.py — the tenant lifecycle's operator command.

    python3 defender/cli/tenant.py new-id
    python3 defender/cli/tenant.py scaffold <tenant-id> <empty dir>
    python3 defender/cli/tenant.py setup <tenant-id>
    python3 defender/cli/tenant.py check <tenant-id> | --folder <path>
    python3 defender/cli/tenant.py update <tenant-id> [--issuer-config <path>]
    python3 defender/cli/tenant.py propose <tenant-id> <staged dir> [--issuer-config <path>]
    python3 defender/cli/tenant.py migrate <tenant-id> <new knowledge folder>   # one-off

A tenant's knowledge (its `settings/` and `agent/` halves) lives in the tenant's OWN repo, never
in the product repo. `scaffold` starts one: it copies `knowledge/tenant-template` into an empty
directory, writes `agent/.tenant-id`, and commits it on branch `main`; the operator pushes it to
a new private repo. To deploy it, the operator clones it ON THE HOST into the data root —

    git clone <tenant repo> "$DEFENDER_DATA_ROOT/<tenant-id>/knowledge"

(with a credential helper or an ssh agent, never a credential in the URL) — and, once the clone
has exited 0, runs `setup <tenant-id>`. Setup ADOPTS the placed folder; it never fetches,
copies or writes into it, and makes no git call. It runs the one-tenant guard, then the folder
rules (no link or special file in either half, `agent/.tenant-id` naming this tenant, nothing at
the folder's top level outside the allow-list, the settings files parse) and run start's own
readiness function (`run_tenant.resolve_run_tenant`: anything that would make a run refuse is
setup's refusal), and only then writes the tenant's row through `create_tenant`. It provisions that tenant's
real `learning/` directory, or adopts an explicitly selected legacy source with
`--learning-state-from PATH`. Adoption requires quiescence and never discovers an ambient
source. A re-run over a finished, provisioned tenant runs every rule again and writes nothing.

`check` reports what setup does not refuse: the grant census against the RUNNING code (a verb
the adapters declare that the table leaves undecided, a row for a verb nobody declares), the
lead-zero agreement, and — for a git clone — that `agent/.tenant-id` is what the tenant's repo
commits (failing closed when git cannot answer). `check <id>` judges the tenant under
`$DEFENDER_DATA_ROOT` through acceptance; `check --folder <path>` judges a tenant repo's working
folder with no data root at all (tenant CI).

`update` publishes (#1108 P4 flow 1): it logs in to the issuer from the issuer client config
file (`--issuer-config`; by default the dev issuer's client config under the repository),
fetches the tenant row's bound origin, fast-forwards the clone, writes the export and points
`current` at it.
`setup` does the same once the row carries a forge binding. `check <id>` also reports how far
`current` trails the clone's `origin/main` and the last publish refusal any trigger met (a run
launch, a drain start, `update`), so a sealed issuer or a refused merge is visible (O-SEE).
`propose` hands a staged directory shaped like the tenant's `agent/` root (connect's tenant
half: a system skill, seed queries, tacit entries) to the commit-maker as one PR on the tenant
forge; files are added or replaced, nothing is deleted, and only `agent/` is touched.

`migrate` is ONE-OFF, for a tenant set up before #1120 (a row and `runs/` under the data root,
its settings committed in the product repo until #1120 deleted them): it builds the knowledge
folder acceptance now requires from the last copy in the checkout's history, as a new repo
exactly like scaffold's, and the operator then runs `setup <tenant-id>`.

Exit status: 0 clean, 1 a finding or a refusal, 2 a usage error. A check that could not judge (the
grant census not taken, `.tenant-id` unverifiable) is one more finding, not a separate code, and
the checks that need no census still run. Every refusal is printed as `[tenant.py] <message>`.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

# Hand-rolled rather than `_venv.reexec_into_venv`, matching `run.py`: this must run
# BEFORE any `defender.*` import resolves, and reaching that helper is itself such an import.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _DEFENDER_DIR.parent
_VENV = _DEFENDER_DIR / ".venv"
_VENV_PY = _VENV / "bin" / "python3"
# Re-exec only from OUTSIDE the checkout's venv: an interpreter already running in it (by any
# of its names, `python` or `python3`) is the venv, and a setup that re-execs itself spawns a
# process DC2 says it never spawns. Either sign counts — the venv's prefix, or an interpreter
# started from the venv's own `bin/` — so a venv missing its `pyvenv.cfg` (whose prefix is
# the base install's) is exec'd at most once, never in a loop.
if (__name__ == "__main__" and _VENV_PY.is_file()
        and Path(sys.prefix).resolve() != _VENV.resolve()
        and Path(sys.executable).parent != _VENV / "bin"):
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if __name__ == "__main__":
    # An operator command writes nothing it does not name, the checkout it runs from included:
    # no bytecode cache lands beside the modules it imports (a refused `scaffold` leaves every
    # tree as it found it). Only when run: an importer's interpreter is not this command's.
    sys.dont_write_bytecode = True
    # This checkout first — first, not merely present: `defender` is a namespace tree, so each
    # module comes from the first path entry holding it. The command judges a tenant against
    # the code it runs, never against another checkout that a `PYTHONPATH` entry or an
    # editable install points at.
    _root = str(_REPO_ROOT)
    sys.path[:] = [_root, *(entry for entry in sys.path if entry != _root)]

from defender import _git
from defender.tenancy import _tenant  # noqa: E402
from defender._io import guarded_mkdir, read_plain_bytes, write_guarded  # noqa: E402
from defender.tenancy._tenants import SETTINGS_HALF, TENANT_ID_FILE, template_dir  # noqa: E402
from defender.runtime import run_tenant  # noqa: E402
from defender.runtime.verb_dispositions import DispositionError, dispositions_path  # noqa: E402
from defender.runtime import case_ticket  # noqa: E402

#: How long one git call of `check`'s committed read may take: each is a local lookup of one
#: path, so a call still running is blocked (a FIFO where git expects a file), not slow.
_COMMITTED_READ_TIMEOUT = 15

#: The words `check` fails closed with when git cannot say whether `.tenant-id` is committed.
_CANNOT_VERIFY = "cannot verify .tenant-id is committed"


def _say(message: object) -> None:
    print(f"[tenant.py] {message}", file=sys.stderr)


# ==========================================================================================
# setup
# ==========================================================================================

def setup(tenant_id: str, learning_state_from: Path | None = None, *,
          issuer_config: Path | None = None) -> int:
    """Validate the placed knowledge and learning adoption plan before writing the row, then
    provision or adopt tenant learning state. Refuse at the first rule it fails: the id grammar (before anything
    under the data root is looked at), the data root, the one-tenant guard (which admits the
    placed `knowledge/` beside a missing row), a present row that is not this tenant's, the
    folder rules, the settings files parse, and run start's readiness function. A finished
    tenant with provisioned learning that still passes is a silent success. Interrupted moves
    remain completable; recreated source records are preserved and reported. Refusals are
    printed visibly, exit 1."""
    try:
        tid = _tenant.TenantId(tenant_id)
        root = _tenant.resolve_data_root()
        _tenant.refuse_foreign_data_root(root, tid)
        settings, has_row = _tenant.accept_placed_knowledge(
            root, tid, defender_dir=_DEFENDER_DIR)
        _settings_files_parse(settings)
        run_tenant.resolve_run_tenant_or_refuse(
            settings, tenant_id=tid, defender_dir=_DEFENDER_DIR, dispatches_lead_zero=True)
        _tenant.provision_learning(root, tid, learning_state_from, repo_root=_REPO_ROOT,
                                   create_row=not has_row)
        if learning_state_from is not None:
            print(f"learning state adopted from {learning_state_from}")
        tenant = _tenant.accept_tenant(root, tid, defender_dir=_DEFENDER_DIR)
    except (OSError, _tenant.TenantRefused) as refused:
        _say(refused)
        return 1
    if _has_forge_binding(tenant):
        return _publish(tenant, by="tenant.py setup", issuer_config=issuer_config)
    return 0


def _has_forge_binding(tenant: _tenant.Tenant) -> bool:
    try:
        _tenant.read_forge_binding(tenant)
    except _tenant.TenantRefused:
        return False
    return True


def _settings_files_parse(settings: Path) -> None:
    """The folder rule run start does not apply before a run: the case-history mapping parses
    (the grant table and the lead-zero config are run start's own, in its readiness
    function)."""
    try:
        case_ticket.check_mapping(settings)
    except case_ticket.CaseTicketError as bad:
        raise _tenant.TenantRefused(str(bad)) from bad


# ==========================================================================================
# check
# ==========================================================================================

def check_tenant(tenant_id: str) -> int:
    """`check <id>`: the tenant under `$DEFENDER_DATA_ROOT` through acceptance (stopping at
    its first refusal), then every finding about its settings and its repo, all reported."""
    try:
        tenant = _tenant.accept_tenant(
            _tenant.resolve_data_root(), tenant_id, defender_dir=_DEFENDER_DIR)
    except _tenant.TenantRefused as refused:
        _say(refused)
        return 1
    return _report([*_findings(tenant.knowledge), *_publish_findings(tenant)])


def _publish_findings(tenant: _tenant.Tenant) -> list[str]:
    """O-SEE: how far `current` trails the clone's `origin/main` (as the last fetch left it; no
    network), and the last publish refusal any trigger recorded, while no later publish has
    succeeded. Read locally only."""
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
    status = read_status(tenant)
    if status is not None and status.get("refused"):
        findings.append(
            f"the last publish ({status.get('by', 'unknown trigger')}, {status.get('at', '?')}) "
            f"was refused ({status.get('kind', 'operator')}): {status['refused']}")
    return findings


def _trail(tenant: _tenant.Tenant, current: str | None) -> str | None:
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

def _delivery(tenant: _tenant.Tenant, *, client=None, identity=None,
              issuer_config: Path | None = None):
    """The tenant's `TenantDelivery`, opened against its row's bound origin with an identity
    from the issuer client config (or the given stand-ins)."""
    from defender.learning.author import version_control as vc

    binding = _tenant.read_forge_binding(tenant)
    if identity is None:
        identity = vc.issuer_login(
            tenant, issuer_config=issuer_config or vc.DEV_ISSUER_CONFIG)
    if client is None:
        import httpx

        client = httpx.Client()
    return vc.TenantDelivery.open(
        tenant, defender_dir=_DEFENDER_DIR, client=client, identity=identity,
        origin=binding.origin)


def _publish(tenant: _tenant.Tenant, *, by: str, client=None, identity=None,
             issuer_config: Path | None = None) -> int:
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control.status import recording

    try:
        with recording(tenant, by=by):
            export = _delivery(tenant, client=client, identity=identity,
                               issuer_config=issuer_config).publish()
    except (vc.DeliveryRefused, vc.ForgejoAuthError, _tenant.TenantRefused) as refused:
        _say(f"publish refused: {refused}")
        return 1
    print(f"published {export.commit} as tenant {tenant.id}'s current knowledge")
    return 0


def update(tenant_id: str, *, client=None, identity=None,
           issuer_config: Path | None = None) -> int:
    """`update <id>`: publish the tenant's merged `main` (flow 1). The keywords are in-process
    stand-ins for the forge client and the issuer login. Refusals print `[tenant.py] ...`,
    exit 1, and are what `check` reports afterwards."""
    try:
        tenant = _tenant.accept_tenant(
            _tenant.resolve_data_root(), tenant_id, defender_dir=_DEFENDER_DIR)
    except _tenant.TenantRefused as refused:
        _say(refused)
        return 1
    return _publish(tenant, by="tenant.py update", client=client, identity=identity,
                    issuer_config=issuer_config)


def propose(tenant_id: str, staged: Path, *, client=None, identity=None,
            issuer_config: Path | None = None) -> int:
    """`propose <id> <dir>`: the staged directory (shaped like `agent/`) as one commit-maker
    commit on a branch off the origin's `main`, pushed to the tenant origin with one PR. Files
    are added or replaced; nothing absent from the directory is deleted. A link, a special
    file, `.tenant-id` or a git control name anywhere in it refuses the whole proposal before
    anything is committed. Refusals print `[tenant.py] ...` and exit 1."""
    import secrets
    from dataclasses import replace

    from defender.learning.author import version_control as vc
    from defender.tenancy._exports import regular_files as _regular_files

    batch = None
    try:
        tenant = _tenant.accept_tenant(
            _tenant.resolve_data_root(), tenant_id, defender_dir=_DEFENDER_DIR)
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
        delivery = replace(_delivery(tenant, client=client, identity=identity,
                                     issuer_config=issuer_config), branch_prefix="propose/")
        batch = delivery.start_batch(f"propose-{secrets.token_hex(4)}", lanes=lanes)
        batch.commit(change_set, f"propose: {', '.join(sorted(files))[:200]}")
        delivered = delivery.finish(batch)
    except (vc.DeliveryRefused, vc.ForgejoAuthError, _tenant.TenantRefused) as refused:
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
        _tenant.check_knowledge_folder(folder, tenant_id=None)
    except _tenant.TenantRefused as refused:
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
    except _tenant.TenantRefused as bad:
        findings.append(str(bad))
    # Here, not at the top: the census reaches the lead-author's whole extraction stack, which
    # only `check` uses — `setup`, `scaffold` and `migrate` start without paying for it.
    from defender.tenancy import _tenant_census

    table = dispositions_path(settings)
    census: _tenant_census.Census | None = None
    try:
        census = _tenant_census.take_census(_DEFENDER_DIR, _REPO_ROOT)
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
# scaffold
# ==========================================================================================

def scaffold(tenant_id: str, target: Path) -> int:
    """Start a tenant repo in the empty directory `target`: the template's files as the
    running checkout's HEAD commits them (never its `examples/`, never an untracked or locally
    edited file), `agent/.tenant-id`, and one commit on branch `main` holding exactly those
    files, whatever the operator's ignore rules say. Needs no data root.
    Refused before any write for a bad id, a target that is not an empty directory outside
    the running checkout, or a git that is absent or has no commit identity; a failure after
    the first write leaves `target` empty again — or, when the undo itself fails, says so and
    names the folder to empty by hand."""
    try:
        tid = _tenant.TenantId(tenant_id)
    except _tenant.TenantRefused as refused:
        _say(refused)
        return 1
    target = Path(target).absolute()  # git runs with cwd=target: a relative GIT_DIR would nest
    refusal = _target_refusal(target) or _git_preflight(target)
    if refusal is not None:
        _say(refusal)
        return 1
    template = template_dir(_REPO_ROOT).relative_to(_REPO_ROOT).as_posix()
    try:
        files = [(rel, sha) for rel, sha in _committed_files(template)
                 if "examples" not in PurePosixPath(rel).parts]
        if not files:
            raise OSError(f"the checkout's HEAD commits no {template}/ to scaffold from")
        _commit_new_tenant_repo(target, tid, files, f"tenant {tid}: scaffolded from the template")
    except (OSError, _git.GitError) as failed:
        try:
            _empty(target)
        except OSError as stuck:
            _say(f"scaffolding {target} failed ({failed}), and undoing it failed too "
                 f"({stuck}) — empty {target} by hand before retrying")
            return 1
        _say(f"scaffolding {target} failed and was undone: {failed}")
        return 1
    return 0


def _target_refusal(target: Path) -> str | None:
    try:
        return _target_fault(target)
    except OSError as unusable:
        return f"{target} could not be checked as a scaffold target: {unusable}"


def _target_fault(target: Path) -> str | None:
    if not target.is_dir() or target.is_symlink():
        return f"{target} is not a directory — scaffold into an empty directory"
    if any(target.iterdir()):
        return f"{target} is not empty — scaffold into an empty directory"
    if target.resolve().is_relative_to(_REPO_ROOT.resolve()):
        return (f"{target} is inside the product checkout {_REPO_ROOT} — a tenant's repo lives "
                "outside it")
    return None


def _git_preflight(target: Path) -> str | None:
    """git is there and can commit as someone, asked before anything is written. The identity
    is asked as the repository about to be created in `target` will see it: `GIT_DIR` names its
    `.git` (not yet there, and not created by asking), so an `includeIf "gitdir:…"` rule
    matches as it will for the commit, and an enclosing repo's identity is not borrowed. Asked
    from `target`'s parent: migrate's target does not exist yet."""
    env = _git.env_for_cwd()
    future = {**env, "GIT_DIR": str(target / ".git")}
    cwd = target.parent
    try:
        _git.git(["--version"], cwd=cwd, env=env)
        for ident in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
            _git.git(["var", ident], cwd=cwd, env=future)
    except FileNotFoundError as absent:
        return f"scaffold needs git, and git is not available on PATH ({absent})"
    except OSError as unusable:
        return f"git could not be run in {target}: {unusable}"
    except _git.GitError as failed:
        return (f"git has no commit identity to commit the new tenant repo with — set "
                f"user.name and user.email: {failed.stderr}")
    return None


def _committed_files(source: str, rev: str = "HEAD") -> list[tuple[str, str]]:
    """The regular files the running checkout's commit `rev` holds under `source`
    (repo-relative), as `(path relative to source, blob sha)` — read from git, never from the
    disk, so an untracked file beside them (a `.DS_Store`, a stray `.env`) or a local edit is
    never carried into a tenant's repo. A link, a submodule or anything else that is not a
    plain file is left out."""
    listing = _git.git(["ls-tree", "-r", "-z", rev, "--", source], cwd=_REPO_ROOT,
                       env=_git.env_for_cwd())
    files = []
    for entry in sorted(filter(None, listing.split("\0"))):
        meta, path = entry.split("\t", 1)
        mode, kind, sha = meta.split()
        if kind == "blob" and mode in ("100644", "100755"):
            files.append((PurePosixPath(path).relative_to(source).as_posix(), sha))
    return files


def _commit_new_tenant_repo(target: Path, tid: _tenant.TenantId,
                            files: list[tuple[str, str]], message: str) -> None:
    """Write `files` (from `_committed_files`) and `agent/.tenant-id` into `target`, and commit
    exactly those on a new branch `main`, whatever the operator's ignore rules say."""
    env = _git.env_for_cwd()
    written = []
    for rel, sha in files:
        guarded_mkdir((target / rel).parent, base=target)
        write_guarded(target / rel, _git.git_blob_bytes(_REPO_ROOT, sha, env=env), mode="create")
        written.append(rel)
    write_guarded(target / TENANT_ID_FILE, _tenant.tenant_id_file_text(tid), mode="create")
    written.append(TENANT_ID_FILE.as_posix())
    _git.git(["init", "-q", "-b", "main"], cwd=target, env=env)
    _git.git(["add", "--force", "--", *written], cwd=target, env=env)
    staged = set(_git.git(["ls-files", "-z"], cwd=target, env=env).split("\0")) - {""}
    if staged != set(written):
        raise OSError(f"git staged {sorted(staged ^ set(written))} differently from what was "
                      "written")
    _git.git(["commit", "-q", "-m", message], cwd=target, env=env)


def _empty(target: Path) -> None:
    """Undo a scaffold that failed after it began: everything it put in `target` goes."""
    for entry in target.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


# ==========================================================================================
# migrate (one-off, #1120)
# ==========================================================================================

def migrate(tenant_id: str, target: Path) -> int:
    """ONE-OFF (#1120): build the knowledge folder a tenant set up before #1120 lacks. Such a
    tenant has a row and `runs/` under the data root, and its settings were committed in the
    product repo's `knowledge/tenants/<id>/`, which #1120 deleted; acceptance now refuses it for
    the missing `<root>/<id>/knowledge`, and there is no tenant repo to clone. `target`
    (normally `$DEFENDER_DATA_ROOT/<id>/knowledge`) becomes a new repo committing the LAST copy
    of that folder the running checkout's history holds (`_last_committed`) plus
    `agent/.tenant-id`, built as scaffold builds one from the template. It writes nothing else
    — no row — and judges nothing: the operator then runs `setup <id>`, which applies every
    rule to it and, finding the row there, writes nothing. Needs no data root. Refused before
    any write for a bad id, a target that exists already, whose parent is not a real
    directory, or that lies in the running checkout's `defender/` tree, a git with no commit
    identity, or a history with no copy for the id (a shallow clone is told to fetch its
    history); a failure after it creates `target` removes `target` again."""
    try:
        tid = _tenant.TenantId(tenant_id)
    except _tenant.TenantRefused as refused:
        _say(refused)
        return 1
    target = Path(target).absolute()
    source = f"knowledge/tenants/{tid}"
    refusal = _migrate_target_refusal(target) or _git_preflight(target)
    if refusal is not None:
        _say(refusal)
        return 1
    try:
        rev = _last_committed(source)
        # migrate writes the id file itself, for the id it is asked to migrate
        files = [] if rev is None else [(rel, sha) for rel, sha in _committed_files(source, rev)
                                        if rel != TENANT_ID_FILE.as_posix()]
        shallow = not files and _git.git(
            ["rev-parse", "--is-shallow-repository"], cwd=_REPO_ROOT,
            env=_git.env_for_cwd()).strip() == "true"
    except (OSError, _git.GitError) as failed:
        _say(f"could not read {source}/ from the checkout's history: {failed}")
        return 1
    if rev is None or not files:
        _say(f"the checkout's history holds no {source}/ — "
             + ("it is a shallow clone: fetch its whole history (git fetch --unshallow) and "
                "run migrate again" if shallow else
                f"there is nothing to migrate for tenant {tid!r}; clone the tenant repo into "
                f"{target} on the host, then run tenant.py setup {tid}"))
        return 1
    try:
        # An EXCLUSIVE create: an existing folder, or a link at the name, is refused, so the undo
        # below only ever removes what migrate made. guarded_mkdir is exist_ok.
        target.mkdir()  # lint-unguarded-tree-write: ok — exclusive create; parent judged above
    except OSError as blocked:
        _say(f"could not create {target}: {blocked}")
        return 1
    try:
        _commit_new_tenant_repo(
            target, tid, files,
            f"tenant {tid}: moved out of the product repo's {source} (#1120, from {rev[:12]})")
    except (OSError, _git.GitError) as failed:
        try:
            shutil.rmtree(target)
        except OSError as stuck:
            _say(f"migrating into {target} failed ({failed}), and removing it failed too "
                 f"({stuck}) — remove {target} by hand before retrying")
            return 1
        _say(f"migrating into {target} failed and was undone: {failed}")
        return 1
    print(f"{target}: built from {source}/ as commit {rev[:12]} last held it, and committed — "
          f"now run tenant.py setup {tid}")
    return 0


def _last_committed(source: str) -> str | None:
    """The newest commit in HEAD's history whose tree holds `source`, or None. The last commit
    to change `source` either holds it (an edit) or deleted it, and then its first parent holds
    the last copy. Through a merge, git follows the side the merge's tree agrees with, so a
    branch that deleted the folder is found whether it was merged or squashed."""
    env = _git.env_for_cwd()
    last = _git.git(["rev-list", "--max-count=1", "HEAD", "--", source], cwd=_REPO_ROOT,
                    env=env).strip()
    for rev in (last, f"{last}^") if last else ():
        try:
            if _git.git(["ls-tree", rev, "--", source], cwd=_REPO_ROOT, env=env).strip():
                return _git.git(["rev-parse", "--verify", f"{rev}^{{commit}}"], cwd=_REPO_ROOT,
                                env=env).strip()
        except _git.GitError:  # the root commit has no parent
            return None
    return None


def _migrate_target_refusal(target: Path) -> str | None:
    try:
        if os.path.lexists(target):
            return (f"{target} already exists — migrate only builds a knowledge folder that "
                    "is not there yet")
        parent = target.parent
        if not parent.is_dir() or parent.is_symlink():
            return (f"{parent} is not a real directory (a link is refused) — migrate builds the "
                    "knowledge folder inside it")
        if parent.resolve().is_relative_to(_DEFENDER_DIR.resolve()):
            return (f"{target} is inside the checkout's {_DEFENDER_DIR} tree — a tenant's "
                    "knowledge lives under the data root, outside it")
    except (OSError, RuntimeError) as unusable:
        return f"{target} could not be checked as a migrate target: {unusable}"
    return None


# ==========================================================================================
# the command line
# ==========================================================================================

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("new-id", help="mint an opaque tenant UUID; creates no tenant")
    scaffold_p = sub.add_parser("scaffold", help="start a tenant repo from the template")
    scaffold_p.add_argument("tenant_id")
    scaffold_p.add_argument("target", type=Path)
    setup_p = sub.add_parser(
        "setup", help="adopt placed knowledge, create the row, and provision tenant learning")
    setup_p.add_argument("tenant_id")
    setup_p.add_argument("--learning-state-from", type=Path, default=None,
                         help="explicit legacy learning directory to adopt offline")
    setup_p.add_argument("--issuer-config", type=Path, default=None,
                         help="the issuer client config file, for the publish of a tenant whose "
                              "row is bound to a forge (default: the dev path)")
    check_p = sub.add_parser("check", help="report the census and repo findings of a tenant")
    check_p.add_argument("tenant_id", nargs="?")
    check_p.add_argument("--folder", type=Path, default=None)
    update_p = sub.add_parser("update", help="publish the tenant's merged main as `current`")
    update_p.add_argument("tenant_id")
    update_p.add_argument("--issuer-config", type=Path, default=None,
                          help="the issuer client config file (default: the dev path)")
    propose_p = sub.add_parser(
        "propose", help="propose a staged agent/-shaped directory as one PR on the tenant forge")
    propose_p.add_argument("tenant_id")
    propose_p.add_argument("staged", type=Path)
    propose_p.add_argument("--issuer-config", type=Path, default=None,
                           help="the issuer client config file (default: the dev path)")
    migrate_p = sub.add_parser(
        "migrate", help="one-off (#1120): build a pre-#1120 tenant's knowledge folder from its "
                        "last copy in the checkout's history")
    migrate_p.add_argument("tenant_id")
    migrate_p.add_argument("target", type=Path)
    ns = p.parse_args(argv)
    if ns.command == "new-id":
        print(_tenant.TenantId.mint())
        return 0
    if ns.command == "scaffold":
        return scaffold(ns.tenant_id, ns.target)
    if ns.command == "setup":
        return setup(ns.tenant_id, ns.learning_state_from, issuer_config=ns.issuer_config)
    if ns.command == "migrate":
        return migrate(ns.tenant_id, ns.target)
    if ns.command == "update":
        return update(ns.tenant_id, issuer_config=ns.issuer_config)
    if ns.command == "propose":
        return propose(ns.tenant_id, ns.staged, issuer_config=ns.issuer_config)
    if (ns.tenant_id is None) == (ns.folder is None):
        check_p.error("give exactly one of <tenant-id> and --folder")
    if ns.folder is not None:
        return check_folder(ns.folder)
    return check_tenant(ns.tenant_id)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    # Every git call this command makes acts on the folder it names — a tenant's clone, the
    # scaffold target, the running checkout the census reads — never on a repository an
    # operator's shell exported (J-PO1), so the repo-locating variables go for the process.
    for _name in _git.REPO_LOCATING_ENV:
        os.environ.pop(_name, None)
    sys.exit(main(sys.argv[1:]))
