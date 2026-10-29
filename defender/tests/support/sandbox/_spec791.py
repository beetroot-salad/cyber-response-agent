"""Shared helpers for the #791 suite: run dirs the learning cycle accepts, and fakes for the
investigation entrypoint's tail."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]

# The investigation tail's undrivable dependencies; everything else in the tail runs for real.
TAIL_SEAM = ("lifecycle", "visualize", "ticket_writer")


@pytest.fixture(scope="session", autouse=True)
def worktree_package_guard():
    """Fail the whole module loudly, naming the ENVIRONMENT cause, when the suite has
    imported a different checkout's copy of the package than the one holding these tests."""
    import defender.agents as agents_mod

    loaded = Path(agents_mod.__file__).resolve()
    assert REPO_ROOT in loaded.parents, (
        f"ENVIRONMENT: this suite lives under {REPO_ROOT} but imported the package from "
        f"{loaded}; run from a neutral directory with PYTHONPATH={REPO_ROOT}"
    )


def noop_start_box(request, **_kw):
    """A box lifecycle that starts nothing: these demands are about the learning cycle's
    wiring, not the (separately spec'd) box lifecycle."""
    return SimpleNamespace(name=getattr(request, "name", "spec791"), sandboxed=False)


def noop_stop_box(_box, **_kw) -> None:
    pass


class SpecBranch:
    """The drain's git-worktree lifecycle, recorded rather than performed: these demands are
    about which lane RAN, not about the (separately spec'd) supply-chain step."""

    #: What the real `AuthorBranch` cuts a batch from (its default); a box-start fault names it.
    branch_base = "origin/main"

    branch_prefix = "lead-author/"

    def __init__(self, base: Path) -> None:
        self._base = base
        self.events: list[str] = []

    def branch_name(self, batch_id: str) -> str:
        # The real `AuthorBranch.branch_name`, verbatim: #952's failure log names the local
        # branch the commit was retained on, so the fake has to answer for it.
        return f"{self.branch_prefix}{batch_id}"

    def open_pr_exists(self) -> bool:
        self.events.append("lease-check")
        return False

    def start_batch(self, batch_id: str) -> Path:
        self.events.append("start")
        wt = self._base / f"wt-{batch_id}"
        wt.mkdir(parents=True, exist_ok=True)
        return wt

    def finish_batch(self, batch_id: str, wt: Path):
        self.events.append("finish")
        return f"PR/{batch_id}"

    def cleanup(self, wt: Path) -> None:
        self.events.append("cleanup")


def loop_paths(tmp_path: Path):
    """A `LoopPaths` whose queues and runs live under `tmp_path`, with the fake repo tree
    kept apart from the mutable state root."""
    from defender.learning.core.config import LoopPaths

    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def satisfy_entrypoint_keys(monkeypatch, tmp_path: Path) -> None:
    """Give the ENTRYPOINT's startup preflight a key per provider and a runs base under tmp,
    so a scenario about the tail does not fail in the credential step ahead of it.

    Setting every var first means a key the preflight sources from the repo's `.env` is
    restored at teardown instead of leaking into the rest of the session."""
    from defender import providers

    for var in providers.api_key_vars():
        monkeypatch.setenv(var, "spec791-not-used")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "runs"))


LEAD_PAYLOAD = (
    "### Summary\n2 events\n\n### Raw Sample Events\n\n"
    '```json\n[{"user": "dev.dana", "outcome": "success"}]\n```\n'
)


def make_run_dir(
    tmp_path: Path,
    *,
    name: str = "case-791",
    disposition: str = "inconclusive",
    alert_bytes: bytes | None = None,
) -> Path:
    """A finished investigation run dir the learning cycle accepts: the alert, the report
    whose disposition selects the legs, the invlang work log, and the two append-only
    tables (lead `l-001`'s sidecar, its executed-query row and its raw payload)."""
    run_dir = tmp_path / name
    run_dir.mkdir(parents=True, exist_ok=True)
    plant_alert_in_run(run_dir, alert_bytes if alert_bytes is not None
                       else json.dumps({"rule": {"id": "5710", "key": "spec.rule"}}).encode("utf-8"))
    populate_run_dir(run_dir, disposition=disposition)
    return run_dir


def plant_alert_in_run(run_dir: Path, raw: bytes) -> None:
    """The run's alert and its record (#1222), where a materialized run holds them."""
    from defender.tests.support.storage._alert_plant import plant_alert as plant_in_run
    plant_in_run(run_dir, raw)


def populate_run_dir(run_dir: Path, *, disposition: str = "inconclusive") -> Path:
    """The same artifacts, written into a run dir that ALREADY EXISTS: in the tail scenarios
    that is the run dir `main` materializes, not one the test chose."""
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    run_dir.joinpath("report.md").write_text(
        f"---\ndisposition: {disposition}\nconfidence: high\n---\n\nspec791 run\n",
        encoding="utf-8",
    )
    run_dir.joinpath("investigation.md").write_text("+ spec791 investigation\n", encoding="utf-8")

    (run_dir / "gather_raw" / "l-001").mkdir(parents=True, exist_ok=True)
    (run_dir / "gather_raw" / "l-001.lead.json").write_text(
        json.dumps({"goal": "check l-001", "what_to_summarize": ["accepted vs failed"]}),
        encoding="utf-8",
    )
    (run_dir / "gather_raw" / "l-001" / "0.json").write_text(LEAD_PAYLOAD, encoding="utf-8")
    run_dir.joinpath("executed_queries.jsonl").write_text(json.dumps({
        "lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "search",
        "query_id": "elastic.auth", "params": {"host": "h0"}, "raw_command": "x",
        "exit_code": 0, "payload_status": "ok", "payload_digest": "d0",
        "payload_path": "gather_raw/l-001/0.json",
    }) + "\n", encoding="utf-8")
    return run_dir


@dataclass(frozen=True)
class TailStep:
    """One step of the investigation tail, with what it could see when it ran: the curation
    requests already on the queue, and whether the tree it reads had been certified."""

    name: str
    curation_requests: tuple[str, ...]
    tree_certified: bool


class SpecTail:
    """The investigation tail's three injected dependencies, each recording what it saw."""

    def __init__(
        self,
        paths,
        *,
        truncated_by: str | None = None,
        closed_before_cut: bool = False,
        certify: bool = True,
    ) -> None:
        self._paths = paths
        self._truncated_by = truncated_by
        self._closed_before_cut = closed_before_cut
        self._certify = certify
        self.run_dirs: list[Path] = []
        self.steps: list[TailStep] = []
        #: What `record_case_ticket` was called with, in order: the one place that shows whether
        #: `run.py`'s tail threads the exit class (`truncated_by`) through to the ticket lane.
        self.record_calls: list[dict[str, Any]] = []
        #: Every `Run` handle the render step was handed, in order (#1110).
        self.visualized: list[Any] = []
        #: The tenant record each ticket leg was handed by `run.py`; kept apart from
        #: `record_calls`, which stays the exit-class record.
        self.ticket_tenants: list[Any] = []

    # the seam's three dependencies
    def lifecycle(self, *, run: Any, **_kw: Any) -> dict:
        from defender.box import _scrub as scrub_mod

        run_dir = run.run_dir
        self.run_dirs.append(run_dir)
        populate_run_dir(run_dir, disposition="benign")
        if self._certify:
            scrub_mod.scrub(run_dir)
        self._note("lifecycle", run_dir)
        return {"output": "spec791 verdict", "requests": 1, "truncated_by": self._truncated_by,
                "closed_before_cut": self._closed_before_cut}

    def visualize(self, run: Any, *, tenant: Any = None, update_ticket: bool = False) -> None:
        # The run's tenant-bound `Run` handle (the step saves the page through it), kept whole
        # so a test can ask which handle the tail gave (#1110).
        self.visualized.append(run)
        self._note("visualize", run.run_dir)

    def open_case_ticket(self, run: Any, *, tenant: Any, defender_dir: Path,
                         env: Any) -> None:
        self.ticket_tenants.append(tenant)
        self._note("open_case_ticket", run.run_dir)

    def record_case_ticket(self, run: Any, *, tenant: Any, defender_dir: Path, env: Any,
                           **kw: Any) -> None:
        self.ticket_tenants.append(tenant)
        # `**kw` takes #1047's `truncated_by=`/`closed_before_cut=`: this fakes the ticket SEAM,
        # not the lane's per-class branching, but records the call to show they are passed on.
        self.record_calls.append(kw)
        self._note("record_case_ticket", run.run_dir)

    # what the steps saw
    def _note(self, name: str, run_dir: Path) -> None:
        from defender.box import _scrub as scrub_mod

        self.steps.append(TailStep(
            name=name,
            curation_requests=tuple(author_markers(self._paths)),
            tree_certified=bool(scrub_mod.tree_verified(run_dir)),
        ))

    @property
    def names(self) -> list[str]:
        return [s.name for s in self.steps]

    def step(self, name: str) -> TailStep:
        for s in self.steps:
            if s.name == name:
                return s
        raise AssertionError(f"the tail never ran {name} (ran {self.names}) — re-site this demand")


def require_tail_seam(main) -> None:
    """The entrypoint's tail seam, checked up front so a missing seam fails by name rather than
    as an unexpected-keyword `TypeError` inside an unrelated scenario."""
    missing = [p for p in TAIL_SEAM if p not in inspect.signature(main).parameters]
    assert not missing, f"the investigation entrypoint takes no {missing}: its tail has no injection seam"


def drive_tail(main, alert: Path, tail: SpecTail, *args: str) -> int:
    """Drive the REAL entrypoint over one alert with the tail's dependencies injected.

    `main` is passed in so each scenario names the entry point it drives. The argv carries
    `--tenant` with D9's tenant, created first in this test's data root: `main` refuses a run
    whose tenant does not exist (#1078)."""
    from defender.tests.support.shared.contracts._data_root_1078 import ensure_d9_tenant, current_data_root
    from defender.tenancy._tenant import requested_tenant

    require_tail_seam(main)
    tenant_id = ensure_d9_tenant()
    location_path(requested_tenant(fixture_data_root(current_data_root()), tenant_id).learning).mkdir(exist_ok=True)
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv, in_process_publish

    # The in-process launch-time publish (it publishes the tenant for real), when `main` takes one.
    argv = [str(alert), "--tenant", tenant_id, *args]
    publish = ({"publish": in_process_publish(), "directory": directory_for_argv(argv)}
               if "publish" in inspect.signature(main).parameters else {})
    return main(argv, lifecycle=tail.lifecycle,
                visualize=tail.visualize, ticket_writer=tail, **publish)


def plant_alert(tmp_path: Path, *, alert_bytes: bytes | None = None) -> Path:
    """The operator's own alert file — the argv the entrypoint is handed."""
    alert = tmp_path / "alert.json"
    alert.parent.mkdir(parents=True, exist_ok=True)
    alert.write_bytes(
        alert_bytes if alert_bytes is not None
        else json.dumps({"rule": {"id": "5710", "key": "spec.rule"}}).encode("utf-8")
    )
    return alert


def author_markers(paths) -> list[str]:
    q = location_path(paths.state_root) / "author-queue"
    return sorted(p.name for p in q.glob("*.json")) if q.is_dir() else []


def marker_body(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


