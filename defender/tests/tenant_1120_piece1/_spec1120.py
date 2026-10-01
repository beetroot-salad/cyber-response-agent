"""Shared machinery for #1120 piece 1's spec — "the tenant frame". NO test functions.

The change (`spec-flow/specs/spec_graph_1120-piece1.yaml`; `.spec-flow/doc-1120.md` read
through `.spec-flow/frontiers/15-design-corrections.md`, `70-resolutions.md` and
`71-resolutions-addendum.md`): a tenant's settings and agent halves leave the checkout for
`<data root>/<T>/knowledge/`, a folder the OPERATOR places there (a `git clone` of the tenant's
repo, or a plain folder — DC2), and ONE function accepts a tenant:

    accept_tenant(data_root, raw_id, *, defender_dir, box_mounted) -> Tenant

It checks, in order: the id grammar, the row (`require_tenant`), `knowledge/` a real unlinked
directory at `<T>/knowledge` whose top level holds only the allow-listed names (V12 as widened
by V15: `settings/`, `agent/`, `.github/`, `.git`, `archive/`, `README.md`, `.gitignore`,
`.gitattributes`), the `settings/` and `agent/` halves plus `REQUIRED_SETTINGS`, the link walk
over the two halves only (`knowledge/.git` is skipped: a local clone's objects are hard links),
`agent/.tenant-id` (the id plus at most one LF or CRLF, read bounded — M8; presence and match
only, no git call — V11), and `settings` outside `defender_dir` and every `box_mounted` path.
`Tenant` is a frozen `(id, data_root, row)` whose other members are path properties; it is
constructed nowhere else. `tenant.py` gains `scaffold <id> <dir>`, `check <id> | --folder
<path>`, and `setup <id>`, which ADOPTS the placed folder: the one-tenant guard (MF1: a rowless
`<id>/` may hold exactly the name `knowledge`), then setup's rule as V18 (human) states it: the
FOLDER RULES (links and special files, `agent/.tenant-id` presence + match, the top-level
allow-list, the settings files parse — `systems/case-history/mapping.yaml` included, which run
start never reads before a run) + RUN START'S OWN READINESS FUNCTION (`RUN_READINESS` — V14,
human, superseding V1's and V10's rule lists: the grant table loads, gather holds a query verb,
the lead-zero agreement; whatever would make a run refuse), then the row LAST — a refused setup
writes nothing. The grant census (a gap does not
stop runs, A1) and "agent/.tenant-id is committed" (V11; failing closed when git cannot answer,
V16) are `check`'s, never setup's. (Was, before 73's V1: "acceptance plus the settings tables
load (DC1/NF1) … the lead-zero agreement is check's, never setup's" — overturned by V1, V10 and
V14.)

NONE OF THE NEW NAMES EXISTS AT BASE a1c65801. Every import goes through `mod()` PER CALL, so a
missing name is ONE failure per test (an `ImportError`/`AttributeError` at the seam the test
needs), never a collection error hiding every other test in the file.

COINED NAMES LIVE HERE AND NOWHERE ELSE. The design names `accept_tenant`, `Tenant` and its nine
path properties, `TenantRefused`, `RunTenant.tenant`, `template_dir` and the three `tenant.py`
subcommands. It does NOT name the row FILE's path property on `Tenant` (N6 reading (a):
`tenant.row` is the `TenantRow`, the file's path "a separate property named by the
implementer") — this suite spells it `row_path` (`ROW_PATH_PROPERTY`). If write-code-from-spec
names anything differently it renames it HERE, never through a `conceptAliases` entry.

THE REFUSAL SHAPE (demand #0, N16): every refusal is a `TenantRefused` whose message names the
refused value (escaped, repr-style, and bounded), and every entry point passes that message
through VERBATIM. `tenant.py` prints it as `[tenant.py] <message>` and exits 1 (N17: 0 clean, 1
a finding or a refusal, 2 a usage error).

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE: the symlinks, hard links, FIFOs,
torn rows, stray entries, local clones with hard-linked objects and the tmp checkouts carrying
an extra adapter are made on disk in the test itself. The only fakes are the entry points' own
injection seams (`run.main`'s `preflight=`/`materialize=`/`lifecycle=`), which RECORD what they
are handed and decide nothing — never `monkeypatch.setattr` (`scripts/lint/lint_monkeypatch.py`).

THE FIXTURE TENANT is `knowledge/tenant-fixture/` (A4: a frozen copy of the lab's settings,
`agent/` holding only `.gitkeep`, NO committed `.tenant-id` — M8). It is resolved from this
file's own location (N11) and COPIED into a tmp data root, never used in place.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFENDER = REPO_ROOT / "defender"
KNOWLEDGE_ROOT = REPO_ROOT / "knowledge"

#: A4's fixture tenant and D9's template, both committed in the product repo.
FIXTURE = KNOWLEDGE_ROOT / "tenant-fixture"
TEMPLATE = KNOWLEDGE_ROOT / "tenant-template"

#: The checkout's lab. It stays committed in piece 1 (H2: the path-only readers keep it until
#: D9 step 7); the suite reads it only to make a checkout whose settings DIFFER from the data
#: root's, never as an oracle.
LAB = KNOWLEDGE_ROOT / "tenants" / "playground"

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
LEARNING_STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"

#: The ids the design's own examples use.
TID = "acme"
OTHER = "beta"

#: `<root>/<T>/tenant.json` — the row (unchanged from #1078).
ROW_NAME = "tenant.json"

#: The row FILE's path property on `Tenant` — a COINED name (N6, see the module docstring).
ROW_PATH_PROPERTY = "row_path"

#: `Tenant`'s nine path properties (D1's table), in the design's order.
TENANT_PATH_PROPERTIES = (
    "dir", "runs", "sessions", "episodes", "learning", "worktrees", "knowledge", "settings",
    "agent",
)

#: D1's step 4: files required under `settings/`. Spelled as literals: after piece 1 the
#: constant's home is the implementer's choice, and the test must be able to disagree with it.
REQUIRED_SETTINGS = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

#: D4's per-tenant probe file, relative to `knowledge/`.
TENANT_ID_FILE = Path("agent") / ".tenant-id"

#: The fixture's lead-zero template (A4).
FIXTURE_CORRELATION_TEMPLATE = "elastic.correlate-alerts-by-entity"

#: Run start's own readiness function (V14, human): what `run.py` reaches to decide a tenant can
#: run — its grants load, gather holds a query verb (`require_gather_query`), and the lead-zero
#: agreement. doc-1120 "Key flows / Run" step 3 names it; setup must reach THIS function, never
#: a hand-copied rule list. A COINED address: renamed HERE if the implementer moves it.
RUN_READINESS = "defender.runtime.run_tenant.resolve_run_tenant"

#: `tenant.py`'s setup subcommand's function (today's `setup(tenant_id)`) — the census's start.
SETUP_FUNCTION = "defender.scripts.tenant.setup"

#: V16 (human): what `check` says when its committed-`.tenant-id` git read cannot answer (git
#: absent, git refusing the clone as dubious ownership, any git error) — beside git's reason.
CANNOT_VERIFY_TENANT_ID = "cannot verify .tenant-id is committed"


# ======================================================================================
# The owner, lazily. ONE place, so a rename is one edit.
# ======================================================================================

def mod(dotted: str) -> Any:
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


#: Every owner helper below takes the owner MODULE (`from defender import _tenant` in the test
#: file — it exists at base; only its new attributes do not), so the test visibly drives the
#: target and a missing attribute is that one test's `AttributeError`.

def accept(owner: Any, root: Path | str, tenant_id: str = TID, *,
           defender_dir: Path = DEFENDER, box_mounted: tuple[Path, ...] = ()) -> Any:
    """The REAL `accept_tenant(data_root, raw_id, *, defender_dir, box_mounted)` (D1)."""
    return owner.accept_tenant(
        Path(root), tenant_id, defender_dir=Path(defender_dir), box_mounted=tuple(box_mounted))


def refusal(owner: Any, fn: Any, *args: Any, **kw: Any) -> BaseException:
    """Call `fn` and hand back its refusal — asserting it IS the one tenant refusal class
    (`owner.TenantRefused`, #0), never an `OSError`/`KeyError`/`ValueError` escaping."""
    with pytest.raises(owner.TenantRefused) as refused:
        fn(*args, **kw)
    return refused.value


def accept_refusal(owner: Any, root: Path | str, tenant_id: str = TID, **kw: Any) -> str:
    """`accept_tenant`'s refusal message for this tree."""
    return str(refusal(owner, accept, owner, root, tenant_id, **kw))


# ======================================================================================
# The data root, hand-spelled. EXPECTED paths are composed here, never read back from the
# owner: a test that asked `Tenant` where the runs are and then asserted they are there would
# be green for any layout at all.
# ======================================================================================

def tenant_folder(root: Path, tenant_id: str = TID) -> Path:
    return Path(root) / tenant_id


def knowledge_dir(root: Path, tenant_id: str = TID) -> Path:
    return Path(root) / tenant_id / "knowledge"


def settings_dir(root: Path, tenant_id: str = TID) -> Path:
    return knowledge_dir(root, tenant_id) / "settings"


def agent_dir(root: Path, tenant_id: str = TID) -> Path:
    return knowledge_dir(root, tenant_id) / "agent"


def row_path(root: Path, tenant_id: str = TID) -> Path:
    return Path(root) / tenant_id / ROW_NAME


def plant_row(root: Path, tenant_id: str = TID, *, body: str | bytes | None = None,
              row_tenant_id: str | None = None, drop: str | None = None,
              extra: dict[str, Any] | None = None) -> Path:
    """Write `<root>/<tenant_id>/tenant.json` BY HAND — a valid row, or a real corruption.
    `body` writes raw bytes verbatim; `row_tenant_id` lets the row name another tenant; `drop`
    removes a field; `extra` adds keys a newer writer might add (N18)."""
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
    """What the OPERATOR does before `setup` (DC2): a plain folder copied to
    `<root>/<tenant_id>/knowledge`. The copy is independent of `source` (new inodes, links
    kept as links). `tenant_id_file`: `"id"` writes `agent/.tenant-id` = `<tenant_id>\\n` (what
    `scaffold` writes and a tenant repo commits — M8); `None` leaves it absent; any other value
    is written verbatim (the byte-rule cells). Returns the `knowledge/` path."""
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
    """A FINISHED tenant built by hand — a placed `knowledge/` plus a valid row — so a test
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
# git, for the tests' own throwaway repos (tests may build them raw — lint_raw_git_subprocess
# excludes test modules). The environment is scrubbed of every ambient GIT_* variable (J-PO1:
# an exported GIT_DIR decides the repository whatever `cwd=` says) and carries its own
# identity, so a developer's config never decides an outcome.
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
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "tenant")
    return repo


def local_clone(repo: Path, dest: Path) -> Path:
    """A PLAIN `git clone <local path>` — no `--no-hardlinks`, so `.git/objects` files are hard
    links to the source's (claims C3, C4, P-DC2-1 leg D: 7 and 24 files with `st_nlink > 1`)."""
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
    """DC2's canonical placement: the tenant's repo (the fixture, committing
    `agent/.tenant-id` unless `tenant_id_file is None`) cloned by a plain local `git clone`
    into `<root>/<tenant_id>/knowledge`. Returns the `knowledge/` path."""
    src = tmp / f"{tenant_id}-repo-src"
    shutil.copytree(FIXTURE, src, symlinks=True)
    write_tenant_id_file(src, tenant_id, tenant_id_file)
    repo = repo_of(src, tmp / f"{tenant_id}-repo")
    return local_clone(repo, knowledge_dir(root, tenant_id))


#: The three ways a clone's `agent/.tenant-id` can hold the right id WITHOUT its repo committing
#: it (V2, human: "for a git clone, acceptance refuses an agent/.tenant-id that is not
#: committed"): never added, added but never committed, and committed as ANOTHER tenant's id
#: (the wrong tenant's repo cloned) then overwritten by hand — 47 P6's cross-tenant case.
UNCOMMITTED_TENANT_ID_WAYS = ("untracked", "staged", "overwritten")


def clone_with_uncommitted_tenant_id(tmp: Path, root: Path, how: str,
                                     tenant_id: str = TID) -> Path:
    """A plain local clone at `<root>/<tenant_id>/knowledge` whose `agent/.tenant-id` holds
    exactly `<tenant_id>\\n` while its repo's HEAD does not commit that content, `how` being
    one of `UNCOMMITTED_TENANT_ID_WAYS`. Real git states, built with real git: the file's bytes
    are right and only the commit is missing. Returns the `knowledge/` path."""
    assert how in UNCOMMITTED_TENANT_ID_WAYS, how
    committed = f"{OTHER}\n" if how == "overwritten" else None
    knowledge = cloned_tenant(tmp, root, tenant_id, tenant_id_file=committed)
    write_tenant_id_file(knowledge, tenant_id, "id")
    if how == "staged":
        git(knowledge, "add", TENANT_ID_FILE.as_posix())
    return knowledge


# ======================================================================================
# tenant.py, as a process. Every driver takes the tenant.py MODULE (`from defender.scripts
# import tenant as tenant_py` in the test file) and runs its own file, so the test visibly
# drives the target (`spec-graph calls`) while the command still runs as the operator runs it.
# ======================================================================================

def tenant_env(root: Path | str | None, *, unset: tuple[str, ...] = (),
               **extra: str) -> dict[str, str]:
    """The environment an operator command runs in: this test's own, with the data root set
    (or removed, for `None`), the WORKTREE's package first on the path (the shared venv's
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
    """`python3 defender/scripts/tenant.py <args>` — `module` is the imported `tenant.py`."""
    return run_script(script_of(module), *args, root=root, **kw)


def output(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def assert_ran(proc: subprocess.CompletedProcess) -> None:
    """The PROGRAM ran and answered on its own terms: a missing script exits 2 with the
    interpreter's "can't open file", and a crash prints a traceback — neither may be read as
    the command's verdict (a refusal is `[tenant.py] …`, never a traceback)."""
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
    """THE ONE HELPER a test uses to get a tenant in a tmp data root (D9, H2; it also serves
    the pass-A re-plumb): copy `knowledge/tenant-fixture` into `<root>/<id>/knowledge`, write
    `agent/.tenant-id` = `<id>\n` into the COPY (the fixture commits none — M8), and run the
    operator's `tenant.py setup <id>` (`module`), which must exit 0. Returns the tenant
    folder."""
    place_knowledge(root, tenant_id)
    assert_clean(setup(module, root, tenant_id))
    return tenant_folder(root, tenant_id)


# ======================================================================================
# `run.main`, through its injection seams.
# ======================================================================================

class RunRecorder:
    """ONE fake per seam `run.main` takes, each RECORDING what it was handed — it classifies
    nothing and refuses nothing. `materialize` makes the run dir where it is told so the tail
    has a tree to list; `lifecycle` keeps every keyword (`tenant=` is the `RunTenant`)."""

    def __init__(self, run_dir_at: Path) -> None:
        self.run_dir_at = Path(run_dir_at)
        self.order: list[str] = []
        self.materialize_calls: list[dict[str, Any]] = []
        self.lifecycle_calls: list[dict[str, Any]] = []

    def preflight(self, _model: str | None = None) -> int:
        self.order.append("preflight")
        return 0

    def materialize(self, alert: Path, run_id: str | None, **kw: Any) -> Any:
        self.order.append("materialize")
        self.materialize_calls.append({"alert": alert, "run_id": run_id, **kw})
        self.run_dir_at.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(run_dir=self.run_dir_at)

    def lifecycle(self, **kw: Any) -> dict[str, Any]:
        self.order.append("lifecycle")
        self.lifecycle_calls.append(kw)
        return {"output": "spec1120", "requests": 0, "truncated_by": None}

    def visualize(self, _run: Any) -> None:
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
        return run_module.main(list(argv), **rec.seams()), None
    except SystemExit as refused:
        return None, refused


def exit_text(exc: BaseException | None) -> str:
    """What an entry's refusal says: `SystemExit`'s code when it is a string, else the text."""
    if isinstance(exc, SystemExit) and isinstance(exc.code, str):
        return exc.code
    return str(exc)


def assert_verbatim(entry_text: str, owner_text: str, *, entry: str) -> None:
    """The entry passed the owner's refusal through VERBATIM (#0)."""
    assert owner_text, "the owner's refusal carries no message"
    assert owner_text in entry_text, (
        f"{entry} did not pass accept_tenant's refusal through verbatim.\n"
        f"  accept_tenant said: {owner_text!r}\n  {entry} said: {entry_text!r}")


# ======================================================================================
# A tmp CHECKOUT — the running code, copied — for the tests about which tree `check` takes its
# census from (A3, s070), and for every "inside the RUNNING checkout's defender/" cell (O11a is
# keyed to the running checkout, so a data root placed inside the COPY's tree is the cell, and
# the real worktree is never written into). It is a real copy of this worktree's `defender/`
# (tests, docs, caches, replay fixtures and the golden eval cases left out) plus `knowledge/`,
# git-initialised because the census's marker half is a committed-tree read
# (`declared_systems._marker_names` reads HEAD). Run its scripts with `run_script`, pointing
# at the copy's own file (`checkout / script_of(module).relative_to(REPO_ROOT)`).
# ======================================================================================

_CHECKOUT_IGNORE = shutil.ignore_patterns(
    "tests", "__pycache__", ".venv", "fixtures-e2e", "docs", "*.pyc", "runs", "cases")


def tmp_checkout(dest: Path) -> Path:
    """A runnable copy of this checkout at `dest` (its `defender/scripts/tenant.py` imports its
    OWN `defender` package — the script puts its checkout first on `sys.path`). Returns the
    checkout root."""
    shutil.copytree(DEFENDER, dest / "defender", ignore=_CHECKOUT_IGNORE, symlinks=True)
    shutil.copytree(KNOWLEDGE_ROOT, dest / "knowledge", symlinks=True)
    git(dest, "init", "-q", "-b", "main")
    # No background maintenance: a newer git's auto-maintenance after the commit repacks the
    # loose objects in a detached process, racing every before/after census of this tree
    # (phase E, PR #1157: CI's git packed them under a refused scaffold's census).
    git(dest, "config", "maintenance.auto", "false")
    git(dest, "config", "gc.auto", "0")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "checkout")
    return dest


def add_adapter(checkout: Path, system: str, source: str) -> Path:
    """Drop `<system>_adapter.py` holding `source` into a tmp checkout's adapters — one more
    system the running code declares (the census reads adapters COLD, never importing them)."""
    path = checkout / "defender" / "scripts" / "adapters" / f"{system.replace('-', '_')}_adapter.py"
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
