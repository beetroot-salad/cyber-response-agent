"""Shared helpers for the #1120 tenant-frame tests (no test functions)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"
KNOWLEDGE_ROOT = REPO_ROOT / "knowledge"

#: The fixture tenant (the retired lab's frozen copy) and the template, both committed in the
#: product repo.
FIXTURE = KNOWLEDGE_ROOT / "tenant-fixture"
TEMPLATE = KNOWLEDGE_ROOT / "tenant-template"

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
LEARNING_STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"

#: The ids the design's own examples use.
TID = fixture_uuid("tenant:acme")
OTHER = fixture_uuid("tenant:beta")

#: `<root>/<T>/tenant.json` — the row.
ROW_NAME = "tenant.json"

#: The row file's path property on `Tenant`.
ROW_PATH_PROPERTY = "row_path"

#: `Tenant`'s nine path properties.
TENANT_PATH_PROPERTIES = (
    "tenant_root", "runs", "sessions", "episodes", "learning", "worktrees", "knowledge", "settings",
    "agent",
)

#: Files required under `settings/`, spelled as literals so a test can disagree with the
#: production constant.
REQUIRED_SETTINGS = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

#: The per-tenant id file, relative to `knowledge/`.
TENANT_ID_FILE = Path("agent") / ".tenant-id"

#: The fixture's lead-zero template.
FIXTURE_CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"

#: Run start's readiness function (grants load, gather holds a query verb, lead-zero agrees);
#: setup must reach this function, never a hand-copied rule list.
RUN_READINESS = "defender.systems.run_tenant.resolve_run_tenant"

#: `tenant.py`'s setup subcommand function.
SETUP_FUNCTION = "defender.cli.tenant.setup"

#: What `check` says, beside git's reason, when its committed-`.tenant-id` git read cannot
#: answer (git absent, dubious ownership, any git error).
CANNOT_VERIFY_TENANT_ID = "cannot verify .tenant-id is committed"

#: An adapter whose source the cold roster read cannot parse, so no census over the checkout
#: holding it can be taken — for `check` and the census lint alike.
BROKEN_SYSTEM = "broken"
BROKEN_ADAPTER = "VERBS = {\n    'verb': (\n"


# ======================================================================================
# The owner, imported lazily.
# ======================================================================================

def mod(dotted: str) -> Any:
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


#: Owner helpers take the owner module (`_tenant`) from the test file, so the test visibly
#: drives the target.

def accept(owner: Any, root: Path | str, tenant_id: str = TID, *,
           defender_dir: Path = DEFENDER, box_mounted: tuple[Path, ...] = ()) -> Any:
    """The real `accept_tenant(data_root, raw_id, *, defender_dir, box_mounted)`."""
    return owner.accept_tenant(
        fixture_data_root(Path(location_path(root))), tenant_id, defender_dir=Path(defender_dir), box_mounted=tuple(box_mounted))


def refusal(owner: Any, fn: Any, *args: Any, **kw: Any) -> BaseException:
    """Call `fn` and return its refusal, asserting it is `owner.TenantRefused`, never an
    escaping `OSError`/`KeyError`/`ValueError`."""
    with pytest.raises(owner.TenantRefused) as refused:
        fn(*args, **kw)
    return refused.value


def accept_refusal(owner: Any, root: Path | str, tenant_id: str = TID, **kw: Any) -> str:
    """`accept_tenant`'s refusal message for this tree."""
    return str(refusal(owner, accept, owner, root, tenant_id, **kw))


# ======================================================================================
# The data root, hand-spelled: expected paths are composed here, never read back from the
# owner (asking `Tenant` where the runs are, then finding them there, passes for any layout).
# ======================================================================================

def tenant_folder(root: Path, tenant_id: str = TID) -> Path:
    return Path(root) / tenant_id


def knowledge_dir(root: Path, tenant_id: str = TID) -> Path:
    return Path(root) / tenant_id / "knowledge"


def settings_dir(root: Path, tenant_id: str = TID) -> Path:
    return knowledge_dir(root, tenant_id) / "settings"


def agent_dir(root: Path, tenant_id: str = TID) -> Path:
    return knowledge_dir(root, tenant_id) / "agent"


#: Each run reads its own copy of its export, `<T>/run-knowledge/<run id>/{owner, settings/,
#: stage/{agent/, <token>}}`, never the tenant's clone (`<T>/knowledge/`) or the checkout.
RUN_COPIES = "run-knowledge"


def run_copy_part(path: Path | str, root: Path, tenant_id: str = TID) -> tuple[str, ...] | None:
    """The parts of `path` below ITS run copy (`<root>/<tenant_id>/run-knowledge/<run id>/`):
    `("settings",)` for a run copy's settings half, `("stage", "agent")` for its agent half —
    or `None` when `path` is not inside any of that tenant's run copies. Lexical: a copy is
    removed when its run ends, so the path may no longer exist."""
    p = Path(os.path.abspath(path))
    copies = Path(os.path.abspath(tenant_folder(root, tenant_id) / RUN_COPIES))
    if not p.is_relative_to(copies):
        return None
    rel = p.relative_to(copies).parts
    return rel[1:] if len(rel) >= 2 else None


def row_path(root: Path, tenant_id: str = TID) -> Path:
    return Path(root) / tenant_id / ROW_NAME


def plant_row(root: Path, tenant_id: str = TID, *, body: str | bytes | None = None,
              row_tenant_id: str | None = None, drop: str | None = None,
              extra: dict[str, Any] | None = None) -> Path:
    """Write `<root>/<tenant_id>/tenant.json` by hand — a valid row, or a real corruption.
    `body` writes raw bytes verbatim; `row_tenant_id` lets the row name another tenant; `drop`
    removes a field; `extra` adds keys a newer writer might add."""
    path = row_path(root, tenant_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if body is not None:
        path.write_bytes(body.encode("utf-8") if isinstance(body, str) else body)
        return path
    doc: dict[str, Any] = {
        "tenant_id": tenant_id if row_tenant_id is None else row_tenant_id,
        "created_at": "2026-09-28T00:00:00+00:00",
        **(extra or {}),
    }
    if drop is not None:
        doc.pop(drop)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def place_knowledge(root: Path, tenant_id: str = TID, *, source: Path = FIXTURE,
                    tenant_id_file: str | bytes | None = "id") -> Path:
    """What the operator does before `setup`: copy `source` to `<root>/<tenant_id>/knowledge`
    (new inodes, links kept as links). `tenant_id_file`: `"id"` writes `agent/.tenant-id` =
    `<tenant_id>\\n` (as `scaffold` does); `None` leaves it absent; anything else is written
    verbatim. Returns the `knowledge/` path."""
    dest = knowledge_dir(root, tenant_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, dest, symlinks=True)
    write_tenant_id_file(dest, tenant_id, tenant_id_file)
    return dest


def write_tenant_id_file(knowledge: Path, tenant_id: str, content: str | bytes | None) -> None:
    target = Path(knowledge) / TENANT_ID_FILE
    if content is None:
        if target.exists() or target.is_symlink():
            target.unlink()
        return
    data = f"{tenant_id}\n" if content == "id" else content
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)


def adopted(root: Path, tenant_id: str = TID, **kw: Any) -> Path:
    """A finished tenant built by hand — a placed `knowledge/` plus a valid row — so a test
    about acceptance does not depend on `setup`. Returns the tenant folder."""
    place_knowledge(root, tenant_id, **kw)
    plant_row(root, tenant_id)
    return tenant_folder(root, tenant_id)


# ======================================================================================
# Census: the before/after comparison every "writes nothing" and "byte- and mtime-identical"
# assertion makes.
# ======================================================================================

def tree_census(root: Path) -> dict[str, tuple[Any, ...]]:
    """Every entry under `root` (not following links): its kind, and for a file its bytes'
    digest, `st_mtime_ns` and mode; for a link its target. An absent root is `{}` — itself a
    value the comparison sees."""
    root = Path(root)
    if not root.is_dir():
        return {}
    out: dict[str, tuple[Any, ...]] = {}
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        for name in (*dirnames, *filenames):
            p = Path(current) / name
            rel = p.relative_to(root).as_posix()
            st = p.lstat()
            if p.is_symlink():
                out[rel] = ("link", os.readlink(p))
            elif p.is_dir():
                out[rel] = ("dir", st.st_mode)
            elif p.is_file():
                out[rel] = ("file", hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns,
                            st.st_mode)
            else:
                out[rel] = ("special", st.st_mode)
    return out


def census_diff(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """What changed between two censuses, named — the failure message's content."""
    diff = []
    for rel in sorted(set(before) | set(after)):
        if rel not in after:
            diff.append(f"removed: {rel}")
        elif rel not in before:
            diff.append(f"added: {rel}")
        elif before[rel] != after[rel]:
            diff.append(f"changed: {rel}")
    return diff


# ======================================================================================
# git for the tests' own throwaway repos (lint_raw_git_subprocess excludes test modules). The
# env drops every ambient GIT_* variable (an exported GIT_DIR overrides `cwd=`) and carries its
# own identity, so a developer's config never decides an outcome.
# ======================================================================================

GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "spec1120", "GIT_AUTHOR_EMAIL": "spec1120@example.invalid",
    "GIT_COMMITTER_NAME": "spec1120", "GIT_COMMITTER_EMAIL": "spec1120@example.invalid",
}


def git_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_IDENTITY)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env.update(extra)
    return env


def git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — fixed argv
        ["git", *args], cwd=str(cwd), env=git_env(), capture_output=True, text=True,
        check=check, timeout=120)


def repo_of(folder: Path, repo: Path) -> Path:
    """A git repository at `repo` committing a copy of `folder` (one commit on `main`) — the
    tenant's own repo, as `scaffold` makes one and the operator pushes it."""
    shutil.copytree(folder, repo, symlinks=True)
    git(repo, "init", "-q", "-b", "main")
    # Keep the source immutable while a plain local clone hardlinks its objects.
    # Git's detached auto-maintenance can otherwise repack them during the clone.
    git(repo, "config", "maintenance.auto", "false")
    git(repo, "config", "gc.auto", "0")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "tenant")
    return repo


def local_clone(repo: Path, dest: Path) -> Path:
    """A plain `git clone <local path>` (no `--no-hardlinks`), so `.git/objects` files are hard
    links to the source's."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    git(dest.parent, "clone", "-q", str(repo), str(dest))
    return dest


def hardlinked_git_objects(knowledge: Path) -> list[Path]:
    objects = Path(knowledge) / ".git" / "objects"
    return [p for p in objects.rglob("*") if p.is_file() and p.lstat().st_nlink > 1]


def git_status(repo: Path) -> str:
    return git(repo, "status", "--porcelain").stdout


def cloned_tenant(tmp: Path, root: Path, tenant_id: str = TID, *,
                  tenant_id_file: str | bytes | None = "id") -> Path:
    """The canonical placement: the tenant's repo (the fixture, committing
    `agent/.tenant-id` unless `tenant_id_file is None`) cloned by a plain local `git clone`
    into `<root>/<tenant_id>/knowledge`. Returns the `knowledge/` path."""
    src = tmp / f"{tenant_id}-repo-src"
    shutil.copytree(FIXTURE, src, symlinks=True)
    write_tenant_id_file(src, tenant_id, tenant_id_file)
    repo = repo_of(src, tmp / f"{tenant_id}-repo")
    return local_clone(repo, knowledge_dir(root, tenant_id))


#: Three ways a clone's `agent/.tenant-id` can hold the right id without its repo committing
#: it: never added, staged but not committed, and committed as another tenant's id (the wrong
#: repo cloned) then overwritten by hand.
UNCOMMITTED_TENANT_ID_WAYS = ("untracked", "staged", "overwritten")


def clone_with_uncommitted_tenant_id(tmp: Path, root: Path, how: str,
                                     tenant_id: str = TID) -> Path:
    """A plain local clone at `<root>/<tenant_id>/knowledge` whose `agent/.tenant-id` holds
    exactly `<tenant_id>\\n` while its repo's HEAD does not commit that content, `how` being
    one of `UNCOMMITTED_TENANT_ID_WAYS`. Real git states: the file's bytes are right and only
    the commit is missing. Returns the `knowledge/` path."""
    assert how in UNCOMMITTED_TENANT_ID_WAYS, how
    committed = f"{OTHER}\n" if how == "overwritten" else None
    knowledge = cloned_tenant(tmp, root, tenant_id, tenant_id_file=committed)
    write_tenant_id_file(knowledge, tenant_id, "id")
    if how == "staged":
        git(knowledge, "add", TENANT_ID_FILE.as_posix())
    return knowledge


# ======================================================================================
# tenant.py as a process. Drivers take the imported `tenant.py` module and run its file, so
# the test visibly drives the target while the command runs as the operator runs it.
# ======================================================================================

def tenant_env(root: Path | str | None, *, unset: tuple[str, ...] = (),
               **extra: str) -> dict[str, str]:
    """The environment an operator command runs in: this test's own, with the data root set
    (or removed, for `None`), the worktree's package first on the path (the shared venv's
    editable install points at the main checkout), and `unset` removed."""
    env = dict(os.environ)
    env.pop(DATA_ROOT_ENV, None)
    if root is not None:
        env[DATA_ROOT_ENV] = str(root)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    for key in unset:
        env.pop(key, None)
    env.update(extra)
    return env


def run_script(script: Path, *args: str, root: Path | str | None, cwd: Path | None = None,
               unset: tuple[str, ...] = (), **extra_env: str) -> subprocess.CompletedProcess:
    """`python3 <script> <args>` against data root `root`. Never raises on a non-zero exit:
    the exit status IS the observable."""
    return subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        [sys.executable, str(script), *args],
        env=tenant_env(root, unset=unset, **extra_env), cwd=str(cwd or REPO_ROOT),
        capture_output=True, text=True, timeout=180, check=False)


def script_of(module: Any) -> Path:
    """The file an entry-point module runs from (`tenant.py`, `policy_cli.py`, …), resolved —
    a module imported through pytest's `pythonpath = [".."]` reports `defender/../defender/…`."""
    return Path(module.__file__).resolve()


def tenant_py(module: Any, *args: str, root: Path | str | None, **kw: Any,
              ) -> subprocess.CompletedProcess:
    """`python3 defender/cli/tenant.py <args>` — `module` is the imported `tenant.py`."""
    return run_script(script_of(module), *args, root=root, **kw)


def output(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def assert_ran(proc: subprocess.CompletedProcess) -> None:
    """The program ran and answered: neither a missing script ("can't open file", exit 2)
    nor a traceback may be read as the command's verdict."""
    text = output(proc)
    assert "can't open file" not in text, f"the script does not exist:\n{text}"
    assert "Traceback (most recent call last)" not in text, (
        f"the command crashed instead of answering:\n{text}")


def assert_refused(proc: subprocess.CompletedProcess, *names: str, rc: int = 1) -> str:
    """The command refused: exit `rc`, no traceback, and the output names every one of
    `names`. Returns the output."""
    assert_ran(proc)
    text = output(proc)
    assert proc.returncode == rc, f"exited {proc.returncode}, not {rc}:\n{text}"
    for name in names:
        assert name in text, f"the refusal does not name {name!r}:\n{text}"
    return text


def assert_clean(proc: subprocess.CompletedProcess) -> str:
    """The command exited 0 with no traceback. Returns the output."""
    assert_ran(proc)
    text = output(proc)
    assert proc.returncode == 0, f"exited {proc.returncode}, not 0:\n{text}"
    return text


def setup(module: Any, root: Path, tenant_id: str = TID, **kw: Any) -> subprocess.CompletedProcess:
    """`tenant.py setup <tenant_id>` against `root`."""
    return tenant_py(module, "setup", tenant_id, root=root, **kw)


def check(module: Any, root: Path | None, *args: str, **kw: Any) -> subprocess.CompletedProcess:
    """`tenant.py check <args>` against `root` (`None`: `DEFENDER_DATA_ROOT` unset)."""
    return tenant_py(module, "check", *args, root=root, **kw)


def adopt_fixture(module: Any, root: Path, tenant_id: str = TID) -> Path:
    """A tenant in a tmp data root the operator's way: place the fixture (writing
    `agent/.tenant-id`, which the fixture does not commit) and run `tenant.py setup <id>`,
    which must exit 0. Returns the tenant folder."""
    place_knowledge(root, tenant_id)
    assert_clean(setup(module, root, tenant_id))
    return tenant_folder(root, tenant_id)


# ======================================================================================
# `run.main`, through its injection seams.
# ======================================================================================

class RunRecorder:
    """One recording fake per `run.main` seam; it classifies and refuses nothing.
    `materialize` makes the run dir where told so the tail has a tree to list; `lifecycle`
    keeps every keyword (`tenant=` is the `RunTenant`)."""

    def __init__(self, run_dir_at: Path) -> None:
        # A run id is a canonical UUID: a readable last segment becomes fixture_uuid(<label>)
        # (a UUID passes as is). Read the folder back off `run_dir_at`, never off the label.
        from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape

        run_dir_at = Path(run_dir_at)
        if not is_fixture_uuid_shape(run_dir_at.name):
            run_dir_at = run_dir_at.parent / fixture_uuid(run_dir_at.name)
        self.run_dir_at = run_dir_at
        self.order: list[str] = []
        self.materialize_calls: list[dict[str, Any]] = []
        self.lifecycle_calls: list[dict[str, Any]] = []

    def preflight(self, _model: str | None = None, *, branching: bool = False) -> int:
        self.order.append("preflight")
        return 0

    def materialize(self, alert: Path, **kw: Any) -> Any:
        self.order.append("materialize")
        self.materialize_calls.append({"alert": alert, **kw})
        self.run_dir_at.mkdir(parents=True, exist_ok=True)
        # Run start settles the alert once (#1222): the folder holds it with its record, which
        # the box mount needs.
        from defender.tests.support.storage._alert_plant import plant_alert as plant_with_record

        plant_with_record(self.run_dir_at, Path(alert).read_bytes())
        from defender.tests.support.shared.contracts._spec1077 import fixture_run

        return fixture_run(self.run_dir_at)

    def lifecycle(self, **kw: Any) -> dict[str, Any]:
        self.order.append("lifecycle")
        self.lifecycle_calls.append({**kw, "run_dir": kw["run"].run_dir})
        return {"output": "spec1120", "requests": 0, "truncated_by": None}

    def visualize(self, _run: Any, **_kw: Any) -> None:
        self.order.append("visualize")

    def enqueue(self, *_a: Any, **_kw: Any) -> bool:
        self.order.append("enqueue")
        return False

    def seams(self) -> dict[str, Any]:
        return {"preflight": self.preflight, "materialize": self.materialize,
                "lifecycle": self.lifecycle, "visualize": self.visualize,
                "enqueue": self.enqueue}

    @property
    def spent(self) -> bool:
        return any(s in self.order for s in ("preflight", "materialize", "lifecycle"))


def plant_alert(where: Path) -> Path:
    where.mkdir(parents=True, exist_ok=True)
    alert = where / "alert.json"
    alert.write_text(json.dumps({"rule": {"id": "5710", "key": "spec.rule"}}), encoding="utf-8")
    return alert


def drive_run(run_module: Any, argv: list[str], rec: RunRecorder,
              ) -> tuple[int | None, BaseException | None]:
    """The REAL `run.main(argv)` (`run_module` is the imported `defender/run.py`) with every
    seam recorded: `(exit status, None)`, or `(None, the SystemExit it refused with)`."""
    try:
        # Plus the in-process launch-time publish.
        from defender.tests.support.tenancy._launch_publish_p4 import with_publish

        return run_module.main(list(argv), **with_publish(dict(rec.seams()))), None
    except SystemExit as refused:
        return None, refused


def exit_text(exc: BaseException | None) -> str:
    """What an entry's refusal says: `SystemExit`'s code when it is a string, else the text."""
    if isinstance(exc, SystemExit) and isinstance(exc.code, str):
        return exc.code
    return str(exc)


def assert_verbatim(entry_text: str, owner_text: str, *, entry: str) -> None:
    """The entry passed the owner's refusal through verbatim."""
    assert owner_text, "the owner's refusal carries no message"
    assert owner_text in entry_text, (
        f"{entry} did not pass accept_tenant's refusal through verbatim.\n"
        f"  accept_tenant said: {owner_text!r}\n  {entry} said: {entry_text!r}")


# ======================================================================================
# A tmp checkout — a git-initialised copy of `defender/` (tests, docs, caches and fixtures left
# out) plus `knowledge/` — for tests about which tree `check` takes its census from and for
# "inside the running checkout's defender/" cases, so the real worktree is never written into.
# Run its scripts with `run_script` on the copy's own file
# (`checkout / script_of(module).relative_to(REPO_ROOT)`).
# ======================================================================================

_CHECKOUT_IGNORE = shutil.ignore_patterns(
    "tests", "__pycache__", ".venv", "fixtures-e2e", "docs", "*.pyc", "runs", "cases")


def tmp_checkout(dest: Path) -> Path:
    """A runnable copy of this checkout at `dest` (its `defender/cli/tenant.py` imports its
    OWN `defender` package — the script puts its checkout first on `sys.path`). Returns the
    checkout root."""
    shutil.copytree(DEFENDER, dest / "defender", ignore=_CHECKOUT_IGNORE, symlinks=True)
    shutil.copytree(KNOWLEDGE_ROOT, dest / "knowledge", symlinks=True)
    git(dest, "init", "-q", "-b", "main")
    # No background maintenance: auto-maintenance after the commit repacks loose objects in a
    # detached process, racing every before/after census of this tree.
    git(dest, "config", "maintenance.auto", "false")
    git(dest, "config", "gc.auto", "0")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "checkout")
    return dest


def add_adapter(checkout: Path, system: str, source: str) -> Path:
    """Drop `<system>_adapter.py` holding `source` into a tmp checkout's adapters — one more
    system the running code declares (the census reads adapters COLD, never importing them)."""
    path = checkout / "defender" / "integrations" / f"{system.replace('-', '_')}_adapter.py"
    path.write_text(source, encoding="utf-8")
    return path


def edit_table(settings: Path, *, drop: tuple[str, ...] = (), append: str = "") -> Path:
    """Edit a tenant's `verb-grants.yaml` as TEXT: remove every line containing one of `drop`,
    then append `append` verbatim. Returns the table's path."""
    table = Path(settings) / "verb-grants.yaml"
    lines = table.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [ln for ln in lines if not any(d in ln for d in drop)]
    table.write_text("".join(kept) + append, encoding="utf-8")
    return table
