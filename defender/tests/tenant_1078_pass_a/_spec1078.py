"""Shared machinery for #1078 pass (A)'s spec — "tenant 1 on the request". NO test scripts.

The change (`spec-flow/specs/spec_graph_1078-pass-a.yaml`, `.spec-flow/frontiers/70-resolutions.md`):
every request names its tenant, the tenant must exist (its ROW, `<data root>/<T>/tenant.json`,
written only by `create_tenant`), and the runs base follows from it
(`runs_base_for(T) == TenantPaths(resolve_data_root(), T).runs == <root>/<T>/runs`). A fork
learns its tenant from its source's HOST-ONLY runs-base record (`tenant_of_run_dir`), never
from the stamp a box can write.

NONE of the new names exists at base ed5386bc. Every import goes through `mod()` PER CALL (the
`_triplet_947` / `_spec1077` idiom) so a missing name is ONE failure per test rather than a
collection error that hides every other assertion in the file.

COINED NAMES LIVE HERE AND NOWHERE ELSE. The design names every new owner function
(`is_valid_tenant_id`, `refuse_bad_tenant_id`, `TenantPaths`, `create_tenant`, `require_tenant`,
`tenant_of_run_dir`, `ensure_runs_base_record`, `resolve_data_root`, `runs_base_for`), and §7
J06 places them all in `defender/_tenant.py`. What it does NOT name is the setup command's
Python entry; the tests therefore drive it as the operator does, as a PROCESS
(`python3 defender/scripts/tenant.py setup <id>`), and read its exit status and output. If
write-code-from-spec renames anything, it renames it HERE, never through a `conceptAliases`
entry (which silently disables `check_binds`' prose-not-in-binds scan for the concept).

THE REFUSAL SHAPE (demand #0, §7 F0/J29, human): every owner function refuses by raising ONE
`ValueError` subclass whose message names the refused value, and every entry passes the
owner's message through VERBATIM. So "refused by X" is observed here as: the entry's refusal
text CONTAINS `str(X's own refusal)`, which this suite obtains by calling X directly on the
same input (`owner_refusal`). That makes "which guard fired" an observation, not a guess at a
message.

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE: the off-grammar ids, the torn and
disagreeing records, the rowless folders, the stray entries, the symlinked roots and the
racing creators are written to (or run against) the real filesystem in the test itself, and
re-probed on every run. The one fake family is the entry points' own injection seams
(`run.main`'s `preflight=`/`materialize=`/`lifecycle=`, the launcher's `spawn=`/`preflight=`),
which RECORD what they are handed and inject nothing — never `monkeypatch.setattr`
(`scripts/lint/lint_monkeypatch.py`).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _spec1077 as S
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import D9_TENANT_ID, DATA_ROOT_ENV

mod = T.mod
sym = T.sym

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFENDER = REPO_ROOT / "defender"

#: `defender/scripts/tenant.py` — D10's setup command, the ONLY production caller of
#: `create_tenant`. Driven as a process: its Python entry is not named by the design.
TENANT_PY = DEFENDER / "scripts" / "tenant.py"
RUN_PY = DEFENDER / "run.py"

# ======================================================================================
# The vocabulary the tests assert against (the design's own words, spelled once).
# ======================================================================================

#: The tenant row's name inside `<root>/<T>/` (D1, the data model). Kind `tenant_row` in the
#: run-records registry; NOT exported from the owner (the design keeps it out of
#: `_OWNER_NON_RECORD_EXPORTS`), so the tests spell it.
ROW_NAME = "tenant.json"

#: #1077's runs-base record, unchanged in name and fields: `{tenant_id, base_world_id, created_at}`.
RECORD_NAME = S.TENANT_RECORD_NAME

#: The grammar, verbatim from "Settled by the user": `^[a-z][a-z0-9-]{0,62}$`, matched with
#: `re.fullmatch`.
GRAMMAR = r"^[a-z][a-z0-9-]{0,62}$"

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
    """`defender/_tenant.py` — the tenant owner (D1; J06 places every new name here)."""
    return mod("_tenant")


def TenantPaths(root: Path | str, tenant_id: str) -> Any:  # noqa: N802 — it is the class's own name
    return tenant().TenantPaths(root, tenant_id)


def create_tenant(root: Path, tenant_id: str) -> Any:
    return tenant().create_tenant(root, tenant_id)


def require_tenant(root: Path, tenant_id: str) -> Any:
    return tenant().require_tenant(root, tenant_id)


def tenant_of_run_dir(run_dir: Path) -> str:
    return tenant().tenant_of_run_dir(run_dir)


def ensure_runs_base_record(runs_base: Path, tenant_id: str) -> Any:
    return tenant().ensure_runs_base_record(runs_base, tenant_id)


def resolve_data_root() -> Path:
    return tenant().resolve_data_root()


def runs_base_for(tenant_id: str) -> Path:
    return tenant().runs_base_for(tenant_id)


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


def make_tenant(root: Path, tenant_id: str = VALID_ID) -> Any:
    """`tenant_id` created in `root` through the REAL `create_tenant` (D10: fixtures call it
    directly, against a fresh tmp root). Returns the `TenantRow` it wrote."""
    return create_tenant(Path(root), tenant_id)


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
    """`<runs_base>/_tenant.json` naming `tenant_id` (or a real corruption, via `body=`)."""
    runs_base.mkdir(parents=True, exist_ok=True)
    return S.plant_tenant_record(runs_base, tenant_id=tenant_id, **kw)


def source_run(base: Path, run_id: str = T.SOURCE_RUN_ID) -> Path:
    """A finished, BRANCHABLE run dir under `base`, with its session store beside the base
    (`<base>/../sessions/`) — `_triplet_947.runs_base`'s source, at a base the test chooses."""
    src = base / run_id
    (src / "gather_raw").mkdir(parents=True, exist_ok=True)
    (src / "alert.json").write_text(json.dumps({"rule": {"id": "v2-cross-tier-ssh-pivot"}}),
                                    encoding="utf-8")
    (src / "investigation.md").write_text(T.branchable_investigation(), encoding="utf-8")
    (src / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    T.capture_call(src)
    (src / "provenance.json").write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    T.seed_source_session(base, src)
    return src


def tenant_source(root: Path, tenant_id: str = VALID_ID, *, record: str | None = "same",
                  row: bool = True, run_id: str = T.SOURCE_RUN_ID) -> tuple[Path, Path]:
    """A source run AT A TENANT LOCATION: `<root>/<T>/runs/<run_id>`, returns (base, src).

    `record="same"` plants the runs-base record naming T (what a pass-A materialize leaves);
    another string plants one naming that tenant; `None` plants none. `row` creates T through
    the real `create_tenant` first (the data root must be empty for that, so it runs before
    anything else is written under `root`)."""
    root = Path(root)
    if row:
        make_tenant(root, tenant_id)
    base = runs_dir(root, tenant_id)
    base.mkdir(parents=True, exist_ok=True)
    if record is not None:
        plant_record(base, tenant_id if record == "same" else record)
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
# The refusal shape (#0, F0/J29): one ValueError subclass, passed through verbatim.
# ======================================================================================

def owner_refusal(fn: Callable[..., Any], *args: Any, **kw: Any) -> ValueError:
    """Call an OWNER function and hand back its refusal — asserting it IS one: a `ValueError`
    (the design's "one ValueError subclass"), never a bare `OSError`/`KeyError` escaping."""
    # Deliberately the base class: #0 fixes "one ValueError subclass" without naming it, and
    # which subclass it is, is asserted where it matters (test_d0_return_contract).
    with pytest.raises(ValueError) as refused:  # noqa: PT011 — the design names no subclass
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
    install points at the main checkout — the project profile's note)."""
    env = dict(os.environ)
    env.pop(DATA_ROOT_ENV, None)
    if root is not None:
        env[DATA_ROOT_ENV] = str(root)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    env.update(extra)
    return env


def run_setup(root: Path | str | None, tenant_id: str, *, cwd: Path | None = None,
              **extra_env: str) -> subprocess.CompletedProcess:
    """`python3 defender/scripts/tenant.py setup <tenant_id>` — the operator's own command —
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

    def preflight(self, model: str | None = None) -> int:
        self.order.append("preflight")
        self.preflight_calls.append(model)
        return 0

    def materialize(self, alert: Path, run_id: str | None, **kw: Any) -> Path:
        self.order.append("materialize")
        self.materialize_calls.append({"alert": alert, "run_id": run_id, **kw})
        self.run_dir_at.mkdir(parents=True, exist_ok=True)
        return self.run_dir_at

    def lifecycle(self, *, run_dir: Path, **_kw: Any) -> dict[str, Any]:
        self.order.append("lifecycle")
        return {"output": "spec1078", "requests": 0, "truncated_by": None}

    def visualize(self, run_dir: Path) -> None:
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


def drive_main(argv: list[str], rec: Recorder) -> tuple[int | None, BaseException | None]:
    """Drive the REAL `run.main` over `argv` with every seam recorded. Returns
    `(exit status, None)` or `(None, the SystemExit it refused with)`."""
    try:
        return run_py().main(argv, **rec.seams()), None
    except SystemExit as refused:
        return None, refused


def resume_argv(manifest: Path, world: str = "b", *extra: str) -> list[str]:
    return ["--resume", str(manifest), "--world", world, *extra]


def family_for(source: Path, episode_dir: Path) -> Path:
    """An episode dir holding a family manifest whose source is `source` — what the launcher
    leaves before it spawns a sibling. Returns the manifest path."""
    ep = T.episode(episode_dir.parent, doc=T.family_doc(source_run_dir=str(source)),
                   episode_id=episode_dir.name, root=episode_dir.parent)
    return ep / "family.yaml"


# ======================================================================================
# The branch launcher.
# ======================================================================================

CONTINUATION = "Continue from here."


def launch_argv(source: Path, message_id: int = T.BRANCH_MESSAGE_ID) -> list[str]:
    return [str(source), str(message_id), "--continuation-prompt", CONTINUATION]


def drive_launch(source: Path, *, spawn: Any = None, **seams: Any) -> BaseException | int:
    """Drive the REAL `learning/branch/cli.main` over one source, the role preflight
    neutralised (`_triplet_947.no_preflight`) so a refusal is never the host's credentials.
    Returns the exit status, or the refusal it raised."""
    seams.setdefault("preflight", T.no_preflight)
    try:
        return branch_cli().main(launch_argv(source), spawn=spawn, **seams)
    except SystemExit as refused:
        return refused
