#!/usr/bin/env python3
"""defender/scripts/tenant.py — the tenant lifecycle's operator command.

    python3 defender/scripts/tenant.py scaffold <tenant-id> <empty dir>
    python3 defender/scripts/tenant.py setup <tenant-id>
    python3 defender/scripts/tenant.py check <tenant-id> | --folder <path>

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
setup's refusal), and only then writes the tenant's row through `create_tenant` — its one write.
A re-run over a finished tenant runs every rule again and writes nothing.

`check` reports what setup does not refuse: the grant census against the RUNNING code (a verb
the adapters declare that the table leaves undecided, a row for a verb nobody declares), the
lead-zero agreement, and — for a git clone — that `agent/.tenant-id` is what the tenant's repo
commits (failing closed when git cannot answer). `check <id>` judges the tenant under
`$DEFENDER_DATA_ROOT` through acceptance; `check --folder <path>` judges a tenant repo's working
folder with no data root at all (tenant CI). Exit status: 0 clean, 1 a finding or a refusal, 2 a
usage error. Every refusal is printed as `[tenant.py] <message>`.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path, PurePosixPath

# Hand-rolled rather than `scripts/_venv.reexec_into_venv`, matching `run.py`: this must run
# BEFORE any `defender.*` import resolves, and reaching that helper is itself such an import.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = _DEFENDER_DIR.parent
_VENV = _DEFENDER_DIR / ".venv"
_VENV_PY = _VENV / "bin" / "python3"
# Re-exec only from OUTSIDE the checkout's venv: an interpreter already running in it (by any
# of its names, `python` or `python3`) is the venv, and a setup that re-execs itself spawns a
# process DC2 says it never spawns.
if (__name__ == "__main__" and _VENV_PY.is_file()
        and Path(sys.prefix).resolve() != _VENV.resolve()):
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

from defender import _git, _tenant, _tenant_census  # noqa: E402
from defender._io import guarded_mkdir, read_plain_bytes, write_guarded  # noqa: E402
from defender._tenants import SETTINGS_HALF, TENANT_ID_FILE, template_dir  # noqa: E402
from defender.runtime import run_tenant  # noqa: E402
from defender.runtime.verb_dispositions import DispositionError, dispositions_path  # noqa: E402
from defender.scripts.case_history import case_ticket  # noqa: E402

#: The words `check` fails closed with when git cannot say whether `.tenant-id` is committed.
_CANNOT_VERIFY = "cannot verify .tenant-id is committed"


def _say(message: object) -> None:
    print(f"[tenant.py] {message}", file=sys.stderr)


# ==========================================================================================
# setup
# ==========================================================================================

def setup(tenant_id: str) -> int:
    """Adopt the operator-placed `<root>/<id>/knowledge` and write the tenant's row LAST, or
    refuse — writing nothing — at the first rule it fails: the id grammar (before anything
    under the data root is looked at), the data root, the one-tenant guard (which admits the
    placed `knowledge/` beside a missing row), a present row that is not this tenant's, the
    folder rules, the settings files parse, and run start's readiness function. A finished
    tenant that still passes is a silent success. Every refusal is the owner's
    `TenantRefused`, printed verbatim, exit 1."""
    try:
        tid = _tenant.TenantId(tenant_id)
        root = _tenant.resolve_data_root()
        _tenant.refuse_foreign_data_root(root, tid)
        settings, has_row = _tenant.accept_placed_knowledge(
            root, tid, defender_dir=_DEFENDER_DIR)
        _settings_files_parse(settings)
        run_tenant.resolve_run_tenant_or_refuse(
            settings, tenant_id=tid, defender_dir=_DEFENDER_DIR, dispatches_lead_zero=True)
        if not has_row:
            _tenant.create_tenant(root, tid)
    except _tenant.TenantRefused as refused:
        _say(refused)
        return 1
    return 0


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
    return _report(_findings(tenant.knowledge))


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
    settings files load, the grant census both ways and the lead-zero agreement against the
    running checkout, and the committed `.tenant-id`."""
    settings = knowledge / SETTINGS_HALF
    findings: list[str] = []
    try:
        _settings_files_parse(settings)
    except _tenant.TenantRefused as bad:
        findings.append(str(bad))
    try:
        census = _tenant_census.take_census(_DEFENDER_DIR, _REPO_ROOT)
    except _tenant_census.CensusUnavailable as blind:
        findings.append(f"the grant census could not be taken: {blind}")
    else:
        table = dispositions_path(settings)
        try:
            findings += _tenant_census.table_findings(settings, census).lines(table)
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


def _tenant_id_committed(folder: Path) -> str | None:
    """For a folder that is a git work tree: `None` when HEAD commits its `agent/.tenant-id`
    as it stands — byte for byte, except that a CRLF checkout of an LF commit (`core.autocrlf`,
    an `eol=crlf` attribute) matches — else the finding: the file untracked, staged only, or
    changed since the commit, or git unable to answer (absent, refusing the repo, any error),
    which fails closed. HEAD's blob is read raw, so git runs no filter or configured command
    over either side. A plain folder has no repo to ask and is exempt. The read ignores an
    exported `GIT_DIR`, and a `.git` that git does not read as a repository rooted at the
    folder (git would answer from an enclosing repo) fails closed too: the answer is the
    folder's own repository's or none."""
    rel = TENANT_ID_FILE.as_posix()
    if not os.path.lexists(folder / ".git") or not os.path.lexists(folder / rel):
        return None
    env = _git.env_for_cwd()
    try:
        top = _git.git(["rev-parse", "--show-toplevel"], cwd=folder, env=env)
        if Path(top).resolve() != folder.resolve():
            return (f"{_CANNOT_VERIFY}: {folder / '.git'} is not a repository of its own — "
                    f"git reads {top}'s instead")
        listed = _git.git(["ls-tree", "HEAD", "--", rel], cwd=folder, env=env)
        committed = _git.git_blob_bytes(folder, listed.split()[2], env=env) if listed else None
    except FileNotFoundError as absent:
        return f"{_CANNOT_VERIFY}: git is not available on PATH ({absent})"
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
    the first write leaves `target` empty again."""
    try:
        tid = _tenant.TenantId(tenant_id)
    except _tenant.TenantRefused as refused:
        _say(refused)
        return 1
    target = Path(target)
    refusal = _target_refusal(target) or _git_preflight(target)
    if refusal is not None:
        _say(refusal)
        return 1
    try:
        written = _copy_template(target)
        write_guarded(target / TENANT_ID_FILE, _tenant.tenant_id_file_text(tid), mode="create")
        written.append(TENANT_ID_FILE.as_posix())
        env = _git.env_for_cwd()
        _git.git(["init", "-q", "-b", "main"], cwd=target, env=env)
        _git.git(["add", "--force", "--", *written], cwd=target, env=env)
        staged = set(_git.git(["ls-files", "-z"], cwd=target, env=env).split("\0")) - {""}
        if staged != set(written):
            raise OSError(f"git staged {sorted(staged ^ set(written))} differently from what "
                          "scaffold wrote")
        _git.git(["commit", "-q", "-m", f"tenant {tid}: scaffolded from the template"],
                 cwd=target, env=env)
    except (OSError, _git.GitError) as failed:
        _empty(target)
        _say(f"scaffolding {target} failed and was undone: {failed}")
        return 1
    return 0


def _target_refusal(target: Path) -> str | None:
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
    is asked as the repository scaffold is about to create will see it: `GIT_DIR` names its
    `.git` (not yet there, and not created by asking), so an `includeIf "gitdir:…"` rule
    matches as it will for the commit, and an enclosing repo's identity is not borrowed."""
    env = _git.env_for_cwd()
    future = {**env, "GIT_DIR": str(target / ".git")}
    try:
        _git.git(["--version"], cwd=target, env=env)
        for ident in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
            _git.git(["var", ident], cwd=target, env=future)
    except FileNotFoundError as absent:
        return f"scaffold needs git, and git is not available on PATH ({absent})"
    except _git.GitError as failed:
        return (f"git has no commit identity to commit the new tenant repo with — set "
                f"user.name and user.email: {failed.stderr}")
    return None


def _copy_template(target: Path) -> list[str]:
    """Write the template's files into `target` as the running checkout's HEAD commits them —
    read from git, never from the disk, so an untracked file beside them (a `.DS_Store`, a
    stray `.env`) or a local edit is never carried into a tenant's repo. Returns the relative
    paths written."""
    template = template_dir(_REPO_ROOT).relative_to(_REPO_ROOT).as_posix()
    env = _git.env_for_cwd()
    listing = _git.git(["ls-tree", "-r", "-z", "HEAD", "--", template], cwd=_REPO_ROOT, env=env)
    if not listing:
        raise OSError(f"the checkout's HEAD commits no {template}/ to scaffold from")
    written: list[str] = []
    for entry in sorted(filter(None, listing.split("\0"))):
        meta, path = entry.split("\t", 1)
        mode, kind, sha = meta.split()
        rel = PurePosixPath(path).relative_to(template)
        if "examples" in rel.parts or kind != "blob" or mode not in ("100644", "100755"):
            continue
        guarded_mkdir((target / rel).parent, base=target)
        write_guarded(target / rel, _git.git_blob_bytes(_REPO_ROOT, sha, env=env), mode="create")
        written.append(rel.as_posix())
    return written


def _empty(target: Path) -> None:
    """Undo a scaffold that failed after it began: everything it put in `target` goes."""
    for entry in target.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


# ==========================================================================================
# the command line
# ==========================================================================================

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    scaffold_p = sub.add_parser("scaffold", help="start a tenant repo from the template")
    scaffold_p.add_argument("tenant_id")
    scaffold_p.add_argument("target", type=Path)
    setup_p = sub.add_parser(
        "setup", help="adopt the knowledge folder cloned into the data root; write the row")
    setup_p.add_argument("tenant_id")
    check_p = sub.add_parser("check", help="report the census and repo findings of a tenant")
    check_p.add_argument("tenant_id", nargs="?")
    check_p.add_argument("--folder", type=Path, default=None)
    ns = p.parse_args(argv)
    if ns.command == "scaffold":
        return scaffold(ns.tenant_id, ns.target)
    if ns.command == "setup":
        return setup(ns.tenant_id)
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
