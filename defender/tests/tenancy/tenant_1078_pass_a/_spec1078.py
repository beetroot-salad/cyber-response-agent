"""Shared machinery for #1078 pass (A)'s spec — "tenant 1 on the request". NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.storage._alert_plant import plant_alert as plant_alert_input
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.contracts._data_root_1078 import D9_TENANT_ID, DATA_ROOT_ENV

mod = T.mod
sym = T.sym

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"

#: `defender/cli/tenant.py` — D10's setup command, the ONLY production caller of
#: `create_tenant`. Driven as a process: its Python entry is not named by the design.
TENANT_PY = DEFENDER / "cli" / "tenant.py"
RUN_PY = DEFENDER / "run.py"

# ======================================================================================
# The vocabulary the tests assert against (the design's own words, spelled once).
# ======================================================================================

#: The tenant row's name inside `<root>/<T>/` (D1, the data model). Kind `tenant_row` in the
#: run-records registry; NOT exported from the owner (the design keeps it out of
#: `_OWNER_NON_RECORD_EXPORTS`), so the tests spell it.
ROW_NAME = "tenant.json"

#: #1077's runs-base record `{tenant_id, base_world_id, created_at}` — RETIRED by #1187 (R1, R1b):
#: nothing writes or accepts it. The name stays so a test can plant one as the OLD entry it is
#: and show nothing writes one.
RECORD_NAME = S.TENANT_RECORD_NAME

#: Canonical lowercase UUID text: no legacy tenant names or alternate spellings.
GRAMMAR = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

#: O3's seven refused ids (C19), with the gate's address tokens as pytest ids so a failure
#: names the domain member it is about.
REFUSED_IDS = [
    pytest.param("../x", id="../x"),
    pytest.param("A", id="A"),
    pytest.param("a/b", id="a/b"),
    pytest.param("", id="empty"),
    pytest.param("a" * 64, id="64-chars"),
    pytest.param("1abc", id="1abc"),
    pytest.param("acme\n", id="trailing-newline"),
]
REFUSED_ID_VALUES = ["../x", "A", "a/b", "", "a" * 64, "1abc", "acme\n"]

#: The ids that carry control or separator content — the untrusted refused values g_r6 is
#: about (a refusal must render them confined, never let them forge a line).
HOSTILE_IDS = ["acme\n", "../x", "a/b", "acme\n[run.py] ok: tenant accepted"]

VALID_ID = D9_TENANT_ID


# ======================================================================================
# The owner, lazily. ONE place, so a rename is one edit.
# ======================================================================================

def tenant() -> Any:
    """`defender/tenancy/_tenant.py` — the tenant owner (D1; J06 places every new name here)."""
    return mod("tenancy._tenant")


def TenantPaths(root: Path | str, tenant_id: str) -> Any:  # noqa: N802 — it is the class's own name
    """The private layout class #1120 made of the public one (M4): the same constructor, with
    the O11a/J03 guards, now reached by no production caller outside the owner. The pass-A
    tests that built it are re-plumbed onto it (spec_graph_1120-piece1 block (5))."""
    return tenant()._TenantPaths(fixture_data_root(root), tenant_id)


def create_tenant(root: Path, tenant_id: str) -> Any:
    return tenant().create_tenant(fixture_data_root(root), tenant_id)


def require_tenant(root: Path, tenant_id: str) -> Any:
    return tenant().require_tenant(fixture_data_root(root), tenant_id)


def resolve_data_root() -> Path:
    return location_path(tenant().resolve_data_root())


def runs_base_for(tenant_id: str) -> Path:
    """#1120 D1: the owner takes an accepted `Tenant`. The tenant is set up from the committed
    fixture under the process's data root first (`_data_root_1078.set_up_tenant`)."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    return location_path(set_up_tenant(resolve_data_root(), tenant_id).runs)


def run_common() -> Any:
    return mod("run_common")


def run_py() -> Any:
    return mod("run")


def branch_cli() -> Any:
    return mod("learning.branch.cli")


# ======================================================================================
# The data root and the tenant layout, hand-spelled.
#
# The EXPECTED paths below are composed by the test, never read back from `TenantPaths`: a
# test that asked the owner where the runs base is and then asserted the run landed there
# would be green for any layout at all.
# ======================================================================================

def set_data_root(monkeypatch, root: Path | str | None) -> None:
    """Point this test's process at `root` (`None` unsets the variable) — `setenv`, the
    sanctioned environment seam, never `setattr`."""
    if root is None:
        monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    else:
        monkeypatch.setenv(DATA_ROOT_ENV, str(root))


def tenant_dir(root: Path, tenant_id: str) -> Path:
    return Path(root) / tenant_id


def row_path(root: Path, tenant_id: str) -> Path:
    return Path(root) / tenant_id / ROW_NAME


def runs_dir(root: Path, tenant_id: str) -> Path:
    return Path(root) / tenant_id / "runs"


def sessions_dir(root: Path, tenant_id: str) -> Path:
    return Path(root) / tenant_id / "sessions"


def place_knowledge(root: Path, tenant_id: str = VALID_ID) -> Path:
    """#1120 DC2: the knowledge folder the operator clones to `<root>/<T>/knowledge` BEFORE
    setup — a copy of the committed fixture, with `agent/.tenant-id` naming T. Returns it."""
    knowledge = Path(root) / tenant_id / "knowledge"
    shutil.copytree(T1106.FIXTURE, knowledge, symlinks=True)
    (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    return knowledge


def make_tenant(root: Path, tenant_id: str = VALID_ID) -> Any:
    """`tenant_id` created in `root` through the REAL `create_tenant` (D10: fixtures call it
    directly, against a fresh tmp root), over the knowledge folder the operator placed first
    (#1120 DC2: `place_knowledge`, the one entry O10 sanctions in a rowless own folder).
    Returns the `TenantRow` it wrote."""
    place_knowledge(Path(root), tenant_id)
    return create_tenant(fixture_data_root(Path(root)), tenant_id)


def accept(root: Path, tenant_id: str = VALID_ID) -> Any:
    """#1120 D1: the accepted `Tenant` an entry point hands inward — the REAL `accept_tenant`
    over `root`, keyed to this checkout's `defender/`, refusing as it would."""
    return tenant().accept_tenant(fixture_data_root(Path(root)), tenant_id, defender_dir=DEFENDER)


def plant_row(root: Path, tenant_id: str, body: str | bytes | None = None, *,
              row_tenant_id: str | None = None, created_at: Any = "2026-09-26T00:00:00+00:00",
              drop: str | None = None) -> Path:
    """Write `<root>/<tenant_id>/tenant.json` BY HAND — the malformed rows, and the hand-made
    second row N13 says nothing refuses. `body` writes raw bytes verbatim; `row_tenant_id`
    lets the row disagree with its folder; `drop` removes a field."""
    path = row_path(root, tenant_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if body is not None:
        path.write_bytes(body.encode("utf-8") if isinstance(body, str) else body)
        return path
    doc: dict[str, Any] = {
        "tenant_id": tenant_id if row_tenant_id is None else row_tenant_id,
        "created_at": created_at,
    }
    if drop is not None:
        doc.pop(drop)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def plant_record(runs_base: Path, tenant_id: str, **kw: Any) -> Path:
    """`<runs_base>/_tenant.json` naming `tenant_id` (or a real corruption, via `body=`) — a
    pre-#1187 container record, planted as the OLD entry it now is (R1)."""
    runs_base.mkdir(parents=True, exist_ok=True)
    return S.plant_tenant_record(runs_base, tenant_id=tenant_id, **kw)


def source_run(base: Path, run_id: str = T.SOURCE_RUN_ID) -> Path:
    """A finished, BRANCHABLE run dir under `base`, with its session store beside the base
    (`<base>/../sessions/`) — `_triplet_947.runs_base`'s source, at a base the test chooses.

    Stamped with the tenant it was made FOR — what materialize stamps every run with (#1077),
    and what the launcher compares with the requested tenant (`_source_stamp_agrees`, kept by
    #1187 N14): when `base` is a tenant's own runs folder `<root>/<T>/runs` (T's row beside it),
    T — the run's tenant follows from where it sits (#1187 P-loc, no container record is read);
    anywhere else, no tenant (a legacy stamp)."""
    base = Path(base)
    src = base / run_id
    (src / "gather_raw").mkdir(parents=True, exist_ok=True)
    plant_alert_input(src, {"rule": {"id": "v2-cross-tier-ssh-pivot"}})
    (src / "investigation.md").write_text(T.branchable_investigation(), encoding="utf-8")
    (src / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    T.capture_call(src)
    at_tenant = base.name == "runs" and (base.parent / ROW_NAME).is_file()
    stamped = base.parent.name if at_tenant else None
    (src / "provenance.json").write_text(json.dumps(T.provenance_record(tenant_id=stamped)),
                                         encoding="utf-8")
    T.seed_source_session(base, src)
    return src


def tenant_source(root: Path, tenant_id: str = VALID_ID, *, row: bool = True,
                  run_id: str = T.SOURCE_RUN_ID, published: bool = False) -> tuple[Path, Path]:
    """A source run AT A TENANT LOCATION: `<root>/<T>/runs/<run_id>`, returns (base, src) —
    stamped with T (`source_run`). #1187 (R1): the runs folder holds no `_tenant.json`. `row`
    creates T through the real `create_tenant` first (the data root must be empty for that, so
    it runs before anything else is written under `root`). `published=True` (#1108 P4, for
    scenes that launch a branch over the source): T is instead set up as a REAL published
    tenant (`set_up_tenant(published=True)`), so the source's knowledge stamp names a commit
    its clone holds — what flow 7 materialises and pins."""
    root = Path(root)
    if row and published:
        from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

        location_path(set_up_tenant(root, tenant_id, published=True).learning).mkdir(
            exist_ok=True)
    elif row:
        make_tenant(root, tenant_id)
        location_path(accept(root, tenant_id).learning).mkdir(exist_ok=True)
    base = runs_dir(root, tenant_id)
    base.mkdir(parents=True, exist_ok=True)
    return base, source_run(base, run_id)


def plant_alert(where: Path, name: str = "alert.json") -> Path:
    """The operator's own alert file — what a fresh run is handed on argv."""
    where.mkdir(parents=True, exist_ok=True)
    alert = where / name
    alert.write_text(json.dumps({"rule": {"id": "5710", "key": "spec.rule"}}), encoding="utf-8")
    return alert


def census(root: Path) -> dict[str, tuple[str, str | None]]:
    """Every entry under `root` and every regular file's bytes — the before/after census a
    "writes nothing" assertion compares (`_spec1077.mutation_census`). An absent root is the
    empty census, which is itself a value the comparison sees."""
    root = Path(root)
    return S.mutation_census(root) if root.is_dir() else {}


def entries(root: Path) -> list[str]:
    """`root`'s direct entries by name, sorted; `[]` for an absent root."""
    root = Path(root)
    return sorted(os.listdir(root)) if root.is_dir() else []


# ======================================================================================
# The refusal shape (#0, F0/J29): one refusal class, passed through verbatim.
# ======================================================================================

def owner_refusal(fn: Callable[..., Any], *args: Any, **kw: Any) -> Exception:
    """Call an OWNER function and hand back its refusal — asserting it IS one: the one tenant
    refusal class, `TenantRefused` (#0), never a bare `OSError`/`KeyError` escaping."""
    with pytest.raises(tenant().TenantRefused) as refused:
        fn(*args, **kw)
    return refused.value


def refusal_text(exc: BaseException) -> str:
    """What an entry's refusal says: `SystemExit`'s code when it is a string (`sys.exit(msg)`,
    `LauncherRefused(msg)`), else the exception's own text."""
    if isinstance(exc, SystemExit) and isinstance(exc.code, str):
        return exc.code
    return str(exc)


def assert_verbatim(entry_text: str, owner: BaseException, *, entry: str) -> None:
    """The entry passed the owner's refusal message through VERBATIM (F0/J29's added rule)."""
    owner_text = str(owner)
    assert owner_text, f"the owner's refusal {type(owner).__name__} carries no message"
    assert owner_text in entry_text, (
        f"{entry} did not pass the owner's refusal through verbatim.\n"
        f"  owner said: {owner_text!r}\n  {entry} said: {entry_text!r}")


# ======================================================================================
# The setup command, as a process.
# ======================================================================================

def setup_env(root: Path | str | None, **extra: str) -> dict[str, str]:
    """The environment a setup process runs in: this test's own, with the data root set (or
    removed, for `None`) and the WORKTREE's package on the path (the shared venv's editable
    install points at the main checkout — see defender/tests/CLAUDE.md)."""
    env = dict(os.environ)
    env.pop(DATA_ROOT_ENV, None)
    if root is not None:
        env[DATA_ROOT_ENV] = str(root)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    env.update(extra)
    return env


def run_setup(root: Path | str | None, tenant_id: str, *, cwd: Path | None = None,
              **extra_env: str) -> subprocess.CompletedProcess:
    """`python3 defender/cli/tenant.py setup <tenant_id>` — the operator's own command —
    against `root`. Never raises on a non-zero exit: the exit status IS the observable."""
    return subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        [sys.executable, str(TENANT_PY), "setup", tenant_id],
        env=setup_env(root, **extra_env), cwd=str(cwd or REPO_ROOT),
        capture_output=True, text=True, timeout=120, check=False)


def setup_output(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def assert_setup_ran(proc: subprocess.CompletedProcess) -> None:
    """The setup PROGRAM ran: a missing `tenant.py` exits 2 with the interpreter's own
    "can't open file", which a refusal assertion must never read as setup refusing."""
    assert "can't open file" not in (proc.stderr or ""), (
        f"{TENANT_PY} does not exist — D10's setup command is missing:\n{proc.stderr}")


# ======================================================================================
# `run.py main`, through its injection seams.
# ======================================================================================

class Recorder:
    """ONE fake per seam `run.main` takes, each RECORDING what it was handed and in which order
    relative to the others — it classifies nothing and refuses nothing.

    `materialize` builds a plain directory where it is told (`run_dir_at`) so the tail after it
    has a tree to list, and returns it; everything `main` handed it is kept in `calls`."""

    def __init__(self, run_dir_at: Path) -> None:
        self.run_dir_at = Path(run_dir_at)
        self.order: list[str] = []
        self.materialize_calls: list[dict[str, Any]] = []
        self.preflight_calls: list[Any] = []
        self.preflight_branching: list[bool] = []

    def preflight(self, model: str | None = None, *, branching: bool = False) -> int:
        self.order.append("preflight")
        self.preflight_calls.append(model)
        self.preflight_branching.append(branching)
        return 0

    def materialize(self, alert: Path, **kw: Any) -> Any:
        """Records the call and answers what `main` reads off the builder's handle (#1110:
        the builder answers the run's `Run`): its `run_dir`."""
        self.order.append("materialize")
        self.materialize_calls.append({"alert": alert, **kw})
        self.run_dir_at.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(run_dir=self.run_dir_at)

    def lifecycle(self, *, run: Any, **_kw: Any) -> dict[str, Any]:
        self.order.append("lifecycle")
        return {"output": "spec1078", "requests": 0, "truncated_by": None}

    def visualize(self, run_dir: Path, **_kw: Any) -> None:
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
        """Did `main` spend anything — the preflight (model keys), a run dir, a box?"""
        return any(s in self.order for s in ("preflight", "materialize", "lifecycle"))


def place_knowledge_for_rows() -> None:
    """#1120 DC2: give every tenant whose row this test's data root holds the knowledge folder
    an operator would have cloned beside it — a copy of the committed fixture, with its
    `agent/.tenant-id` — where it has none. A run accepts its tenant only over a placed
    knowledge folder, so a scenario about the row, the record or the request reaches the same
    frame it did before #1120 moved the settings under the data root."""
    raw = os.environ.get(DATA_ROOT_ENV)
    root = Path(raw) if raw else None
    if root is None or not root.is_absolute() or not root.is_dir():
        return
    for row in sorted(root.glob("*/tenant.json")):
        knowledge = row.parent / "knowledge"
        if not os.path.lexists(knowledge):
            place_knowledge(root, row.parent.name)


def drive_main(argv: list[str], rec: Recorder) -> tuple[int | None, BaseException | None]:
    """Drive the REAL `run.main` over `argv` with every seam recorded. Returns
    `(exit status, None)` or `(None, the SystemExit it refused with)`.

    #1108 P4 (OD14, O11): plus the in-process launch-time publish (`_launch_publish_p4`), which
    publishes the requested tenant's folder for real when `run.main` launches it."""
    from defender.tests.support.tenancy._launch_publish_p4 import with_publish

    try:
        place_knowledge_for_rows()
        return run_py().main(list(argv), **with_publish(dict(rec.seams()))), None
    except SystemExit as refused:
        return None, refused


def sibling_argv(manifest: Path, world: str = "b", *extra: str) -> list[str]:
    """A sibling's command line for the episode whose manifest is `manifest` (#1105 PR 2,
    declared change 6: `run.py --episode <episode_id> --world L`, the tenant among `extra`).
    #1187: the episode is opened by id under the requested tenant's `<T>/episodes/`
    (`family_for` puts it there); no environment names it."""
    return ["--episode", Path(manifest).parent.name, "--world", world, *extra]


def family_for(source: Path, *, episode_id: str = T.EPISODE_ID, roster: bool = True) -> Path:
    """An episode holding a family manifest whose source is `source` (by its run id) — what the
    launcher leaves before it spawns a sibling — at `<root>/<T>/episodes/<episode_id>`, T the
    tenant whose `<root>/<T>/runs/` holds `source` (#1187 Layout A: an episode lives under its
    tenant). Returns the manifest path.

    `roster=True` is the episode as RUNS leaves it (#1187 R2): `runs/` made, then the arm roster
    `arms.json` naming every manifest world at a fresh uuid4 — a sibling starts only in an
    episode that reached RUNS (O4b). `roster=False` leaves both absent (a pre-RUNS episode)."""
    import uuid

    source = Path(source)
    episodes = source.parent.parent / "episodes"
    doc = T.family_doc(source_run_dir=str(source), source_run_id=source.name,
                       episode_id=episode_id)
    ep = T.episode(episodes.parent, doc=doc, episode_id=episode_id, root=episodes)
    if roster:
        (ep / "runs").mkdir(exist_ok=True)
        T.write_roster(ep, {w["world_id"]: str(uuid.uuid4()) for w in doc["worlds"]})
    return ep / "family.yaml"


# ======================================================================================
# The branch launcher.
# ======================================================================================

CONTINUATION = "Continue from here."


def launch_argv(source: Path, message_id: int = T.BRANCH_MESSAGE_ID, *,
                tenant_id: str | None = None) -> list[str]:
    """The launcher's command line for the source run at `source` (#1105 PR 2, declared
    change 1: `--tenant T <source_run_id> <message>`): the tenant is `tenant_id`, or the one
    whose tenant location `<root>/<T>/runs/<run id>` the source sits at; the run by its id."""
    place_knowledge_for_rows()
    source = Path(source)
    requested = source.parent.parent.name if tenant_id is None else tenant_id
    return ["--tenant", requested, source.name, str(message_id),
            *T.retired_continuation_argv()]


def no_preflight(_model: str | None = None, *, branching: bool = False) -> int:
    """The role-model preflight, neutralised (`_triplet_947.no_preflight`), taking the
    launcher's `branching=` (#1224: a branching process also preflights its oracle roles)."""
    return 0


#: The answer `source_run`'s one captured call carries (`_triplet_947.capture_call`'s default).
SOURCE_ANSWER = {"hits": [{"_id": "d1"}]}


def serving_oracle() -> dict[str, Any]:
    """Pre-flight's model seams (#1224) for a launch that must start its siblings: an oracle
    serving `source_run`'s one captured call unchanged and a verifier passing it, so every
    fact world calibrates and the family is accepted."""
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S

    return {"oracle": S.oracle(then=S.submit(SOURCE_ANSWER, S.EMPTY_CLAIM)).model,
            "verifier": S.passing_verifier().model}


def drive_launch(source: Path, *, spawn: Any = None, tenant_id: str | None = None,
                 **seams: Any) -> BaseException | int:
    """Drive the REAL `learning/branch/cli.main` over one source (`launch_argv`), the role
    preflight neutralised (`no_preflight`) so a refusal is never the host's credentials.
    Returns the exit status, or the refusal it raised."""
    seams.setdefault("preflight", no_preflight)
    try:
        return branch_cli().main(launch_argv(source, tenant_id=tenant_id), spawn=spawn, **seams)
    except SystemExit as refused:
        return refused
