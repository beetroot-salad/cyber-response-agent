"""Shared machinery for the #791 spec suite — NO test scripts (the leading underscore
keeps pytest from collecting it).

#791 retires the OFFLINE oracle from the learning cycle. Every test in the four
`test_791_*.py` modules is one demand of `spec-flow/specs/spec_graph_791-retire-offline-oracle.yaml`,
named by that demand's `discharged_by`; this module holds only what more than one of them
needs.

RED AGAINST HEAD IS THE EXPECTED STATE. No implementation exists. The fakes below declare
the DEMANDED shapes, not today's: `SpecSubagents.judge` takes no projected-telemetry path,
because that parameter leaving the subagents protocol IS the seam demand
(`judge_call_carries_no_projection`), and every hermetic fake in the tree implements that
protocol (E7). A fake written to today's signature would let the change ship with the
protocol unchanged and nothing red.

Two seams are DEMANDED rather than described, because the design gives the dependency none
and a demand with no executable witness discharges nothing:

* `run.py`'s tail is DRIVEN, not read (R22). `main` takes its three undrivable
  dependencies — the credentialed investigation lifecycle, the HTML render and the case
  ticket endpoint — through an injection seam, exactly as `_run_investigation_lifecycle`
  already takes its own (#741's argument, applied one layer out). Everything else in the
  tail runs for real, so "the tail writes no learn marker", "the trigger is handed the
  operator's flag", "curation is sited above the render step" and both ordering cells are
  observations of a run rather than readings of a statement sequence. A source read cannot
  fail when behaviour changes, which is the failure this flow exists to prevent.
* the golden replay hardcodes its stage function; `oracle_fn=` is pinned as its seam.

`call_order` survives for the one claim that is genuinely about source shape — which
consumer names the shipped ordering property lists, an inline tuple inside another test —
and for the composition claim over the learning CLI's own dispatch.

The three fakes are declarative fault-injectors and nothing else: they carry canned
content and record what they were handed. They classify nothing and decide no policy.
Fault content that cites a real dependency's behaviour cites the ledger claim that
observed it — see each fake's own comment.
"""
from __future__ import annotations

import ast
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from defender.tests._docker import satisfy_engine_keys  # noqa: F401 — re-exported: the four #791 suites reach it through their own harness

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
RUN_PY = DEFENDER / "run.py"
RUN_COMMON_PY = DEFENDER / "run_common.py"
CLI_PY = DEFENDER / "learning" / "core" / "cli.py"
SCRUB_PROPERTY_TEST = DEFENDER / "tests" / "e2e" / "test_540_scrub_lifecycle.py"
VULTURE_BASELINE = REPO_ROOT / "scripts" / "lint" / "lint_vulture_baseline.json"
PROJECT_PROFILE = REPO_ROOT / ".claude" / "spec-flow.json"

# `OLDER_SPEC_GRAPH` (spec_graph_774.yaml) and `LIVE_STAGE_WORD` ("projection") left with
# #797: the graph is deleted and the live projection stage is retired, so the two demands
# that read them — `rekey_live_projection_graph_id` and
# `live_projection_stage_sheds_the_retired_name` — have no subject left to assert about.
# `RETIRED_STAGE_WORD` went with them; the offline oracle's own vocabulary lives on in
# `PROJECTION_WORDS` below, which the judge-prompt demands still read.

RETIRED_PACKAGE = "defender.learning.pipeline.oracle"
# What the retirement actually orphans. NOT the retired package: `pipeline/oracle/` keeps
# every symbol live, because the secondary eval still projects (its own measurement, kept
# deliberately) and the golden replay binds the per-lead seam. The design demand — this
# change's deliberate dead code is ON RECORD — is about the corpses, wherever they fall.
RETIRED_DEAD_SYMBOLS = (
    "enqueue_learning",       # the learning-queue write the curation request replaced
    "enqueue_for_authoring",  # its authoring-queue sibling
    "parse_judge_verdict",    # the A/B harness's verdict parser, orphaned when it stopped judging
)
# The projected-telemetry writer bullet 3 deletes, as the project profile's shared-root
# census spells it. A census row naming a symbol that resolves to nothing reads exactly
# like a row nobody wrote, and this file seeds the next change's grounding pass.
RETIRED_TELEMETRY_WRITER = "_write_oracle_telemetry"

# The investigation tail's undrivable dependencies (R22). Everything else in the tail — the
# table cross-check, the refusal predicate, the curation write, the queue itself — is driven
# for real, so what these scenarios observe is production, not a double.
TAIL_SEAM = ("lifecycle", "visualize", "ticket_writer")

# The leg's own terminal status (R15). `unrecorded` is the value a run dir written BEFORE
# the field existed reads as — R15's accepted cost, and the third member the gate credits.
LEG_COMPLETED = "completed"
LEG_NEVER_SELECTED = "never-selected"
LEG_STARTED_AND_DIED = "started-and-died"
LEG_UNRECORDED = "unrecorded"

# Every spelling the retired stage's column reached the judge under. A negative binds every
# surface the content could reach, so the same vocabulary is asserted against the prompts,
# the rendered comparison files and the assembled judge turn.
PROJECTION_WORDS = (
    "oracle projection",
    "projected telemetry",
    "projected_telemetry",
    "the oracle's projection",
    "oracle's projected",
    "projection",
)


@pytest.fixture(scope="session", autouse=True)
def worktree_package_guard():
    """Fail the whole module loudly, naming the ENVIRONMENT cause, when the suite has
    imported a different checkout's copy of the package than the one holding these tests.

    The main checkout carries its own installed copy, so any invocation whose working
    directory is the main checkout silently loads THAT copy instead — probed, and it
    answered a registry query with eight roles where this tree has eleven. Every "every role"
    claim in this suite is then made against the wrong tree and passes or fails for a reason
    that has nothing to do with the change.

    The guard is keyed on the MODULE PATH, never on a role count — which is why it still
    guards after the resolutions that took the count to eleven, and after #797 took it back
    down; a guard written on the count would have needed editing to keep passing and would
    have stopped meaning anything.

    It moved here from `_gate774` when #797 deleted that module: this suite is its one
    surviving consumer, and a session-scoped autouse fixture only guards the modules that
    import it."""
    import defender.agents as agents_mod

    here = Path(__file__).resolve().parents[2]
    loaded = Path(agents_mod.__file__).resolve()
    assert here in loaded.parents, (
        f"ENVIRONMENT: this suite lives under {here} but imported the package from "
        f"{loaded} — a different checkout's installed copy. Run from a neutral directory "
        f"with PYTHONPATH={here}; every all-roles claim below is meaningless otherwise."
    )


def noop_start_box(request, **_kw):
    """A box lifecycle that starts nothing: these demands are about the learning cycle's
    wiring, not the (separately spec'd) box lifecycle."""
    return SimpleNamespace(name=getattr(request, "name", "spec791"))


def noop_stop_box(_box, **_kw) -> None:
    pass


def noop_scrub(_path, **_kw) -> None:
    pass


class SubagentRecorder:
    """The observation channel for the injected subagents: what each stage was HANDED.

    A fake that only returns canned answers leaves the outbound channel unpinned, so every
    scenario asserts against these records as well as against the run dir."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.judge_kwargs: list[dict] = []

    def record(self, stage: str, **kwargs: Any) -> None:
        self.calls.append(stage)
        if stage.startswith("judge"):
            self.judge_kwargs.append(dict(kwargs))

    def count(self, stage: str) -> int:
        return sum(1 for c in self.calls if c == stage)


class SpecSubagents:
    """The injected `Subagents` double, in the DEMANDED shape.

    `judge` takes no projected-telemetry path (the seam demand). `oracle` is still declared
    — the retired stage survives in the tree for the surviving eval entry points (C10) — but
    a learning run must never reach it, so it RECORDS rather than raises: a fake that raised
    would make "the leg died early" and "the leg correctly declined to call the stage"
    the same observation, which is exactly the vacuity R12 exists to close.

    `judge_raw` is the canned judge reply. The malformed shapes it can carry cite the
    ledger: an unparseable YAML body is the response class R5(c) promotes, and
    `RunUnprocessable` is the loud failure the run cycle already raises for it.
    """

    def __init__(
        self,
        *,
        story: str = "story body\n",
        story_benign: str = "story body\n",
        judge_raw: str = "outcome: caught\ndefender_findings: []\n",
        judge_benign_raw: str = "outcome: survived\ndefender_findings: []\n",
        actor_fault: BaseException | None = None,
        judge_fault: BaseException | None = None,
        recorder: SubagentRecorder | None = None,
    ) -> None:
        self._story = story
        self._story_benign = story_benign
        self._judge_raw = judge_raw
        self._judge_benign_raw = judge_benign_raw
        self._actor_fault = actor_fault
        self._judge_fault = judge_fault
        self.rec = recorder if recorder is not None else SubagentRecorder()

    @property
    def calls(self) -> list[str]:
        return self.rec.calls

    def actor(self, run_dir, learning_run_dir, *, box=None) -> str:
        self.rec.record("actor", run_dir=run_dir, learning_run_dir=learning_run_dir)
        if self._actor_fault is not None:
            raise self._actor_fault
        return self._story

    def actor_benign(self, run_dir, learning_run_dir, alert_rule_key, *, box=None) -> str:
        self.rec.record("actor_benign", run_dir=run_dir, learning_run_dir=learning_run_dir)
        return self._story_benign

    def oracle(self, run_dir, actor_story_path, learning_run_dir) -> str:
        self.rec.record("oracle", run_dir=run_dir)
        return "projections: []\n"

    def judge(self, wiring, run_dir, actor_story_path, learning_run_dir, *, box=None) -> str:
        from defender.learning.core import directions as _directions

        benign = wiring is _directions.BENIGN_WIRING
        self.rec.record(
            "judge_benign" if benign else "judge",
            wiring=wiring, run_dir=run_dir, actor_story_path=actor_story_path,
            learning_run_dir=learning_run_dir,
        )
        if self._judge_fault is not None:
            raise self._judge_fault
        return self._judge_benign_raw if benign else self._judge_raw


class GroundedJudgeSubagents(SpecSubagents):
    """`SpecSubagents` whose judge drives the REAL `invoke_judge` with a faked model.

    The model is the one dependency a hermetic run cannot drive (cost, nondeterminism);
    everything below it — the comparison builder, the per-lead render, the manifest, the
    prompt frames — is real, so a scenario that wants to assert on what the judge was SENT
    gets the production payload rather than a second implementation of it."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.judge_user_texts: list[str] = []
        self.judge_scopes: list[Any] = []

    def judge(self, wiring, run_dir, actor_story_path, learning_run_dir, *, box=None) -> str:
        from defender.learning.core import directions as _directions
        from defender.learning.pipeline.judge.run import invoke_judge

        benign = wiring is _directions.BENIGN_WIRING
        self.rec.record(
            "judge_benign" if benign else "judge",
            wiring=wiring, run_dir=run_dir, actor_story_path=actor_story_path,
            learning_run_dir=learning_run_dir,
        )
        raw = self._judge_benign_raw if benign else self._judge_raw

        def judge_fn(_wiring, *, user, scope, **_kw):
            self.judge_user_texts.append(user)
            self.judge_scopes.append(scope)
            return raw

        return invoke_judge(
            wiring, run_dir, actor_story_path, learning_run_dir,
            judge_fn=judge_fn, box=None,
        )


class SpecBranch:
    """The drain's git-worktree lifecycle, recorded rather than performed: these demands are
    about which lane RAN, not about the (separately spec'd) supply-chain step."""

    branch_prefix = "lead-author/"

    def __init__(self, base: Path) -> None:
        self._base = base
        self.events: list[str] = []

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
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")




def satisfy_entrypoint_keys(monkeypatch, tmp_path: Path) -> None:
    """Give the ENTRYPOINT's startup preflight a key per provider and a runs base under tmp,
    so a scenario about the tail does not fail in the credential step ahead of it.

    Every provider's var is set before the preflight runs, so the key the preflight sources
    out of the repo's `.env` into `os.environ` is restored at teardown rather than leaking
    into the rest of the session (setenv, the sanctioned env seam — never setattr)."""
    from defender.runtime import providers

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
    leads: tuple[str, ...] = ("l-001",),
    payload: bool = True,
    alert_bytes: bytes | None = None,
) -> Path:
    """A finished investigation run dir the learning cycle accepts: the alert, the report
    whose disposition selects the legs, the invlang work log, and the two append-only
    tables (one lead sidecar + one executed-query row + its raw payload per lead)."""
    run_dir = tmp_path / name
    run_dir.mkdir(parents=True, exist_ok=True)
    run_dir.joinpath("alert.json").write_bytes(
        alert_bytes if alert_bytes is not None
        else json.dumps({"rule": {"id": "5710", "key": "spec.rule"}}).encode("utf-8")
    )
    populate_run_dir(run_dir, disposition=disposition, leads=leads, payload=payload)
    return run_dir


def populate_run_dir(
    run_dir: Path,
    *,
    disposition: str = "inconclusive",
    leads: tuple[str, ...] = ("l-001",),
    payload: bool = True,
) -> Path:
    """The same artifacts, written into a run dir that ALREADY EXISTS.

    The tail scenarios cannot use `make_run_dir`: `main` materializes its own run dir under
    the runs base and copies the operator's alert into it, and that dir — not one the test
    chose — is what every tail step reads."""
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    run_dir.joinpath("report.md").write_text(
        f"---\ndisposition: {disposition}\nconfidence: high\n---\n\nspec791 run\n",
        encoding="utf-8",
    )
    run_dir.joinpath("investigation.md").write_text("+ spec791 investigation\n", encoding="utf-8")

    rows = []
    for i, lead_id in enumerate(leads):
        (run_dir / "gather_raw" / lead_id).mkdir(parents=True, exist_ok=True)
        (run_dir / "gather_raw" / f"{lead_id}.lead.json").write_text(
            json.dumps({"goal": f"check {lead_id}", "what_to_summarize": ["accepted vs failed"]}),
            encoding="utf-8",
        )
        rows.append(json.dumps({
            "lead_id": lead_id, "seq": 0, "system": "elastic", "verb": "search",
            "query_id": "elastic.auth", "params": {"host": f"h{i}"}, "raw_command": "x",
            "exit_code": 0, "payload_status": "ok", "payload_digest": f"d{i}",
            "payload_path": f"gather_raw/{lead_id}/0.json",
        }))
        if payload:
            (run_dir / "gather_raw" / lead_id / "0.json").write_text(
                LEAD_PAYLOAD, encoding="utf-8"
            )
    run_dir.joinpath("executed_queries.jsonl").write_text(
        "".join(r + "\n" for r in rows), encoding="utf-8"
    )
    return run_dir


@dataclass(frozen=True)
class TailStep:
    """One step of the investigation tail, with what it could see when it ran: the curation
    requests already on the queue, and whether the tree it reads had been certified."""

    name: str
    curation_requests: tuple[str, ...]
    tree_certified: bool


class SpecTail:
    """The investigation tail's three injected dependencies, each recording what it saw.

    One fake per dependency, driven by data (`disposition`, `truncated_by`, `certify`); it
    injects and records, and classifies nothing. The lifecycle fake does what a real
    investigation does to the run dir — leaves the report, the work log and the two tables,
    and lets the real scrub certify the tree — because every tail step below it reads that
    tree for real.

    `certify=False` is the one fault it injects, and it is a real one through the real
    primitive: a tree with no scan verdict is what the shared refusal predicate refuses.
    """

    def __init__(
        self,
        paths,
        *,
        disposition: str = "benign",
        leads: tuple[str, ...] = ("l-001",),
        truncated_by: str | None = None,
        certify: bool = True,
    ) -> None:
        self._paths = paths
        self._disposition = disposition
        self._leads = leads
        self._truncated_by = truncated_by
        self._certify = certify
        self.run_dirs: list[Path] = []
        self.steps: list[TailStep] = []

    # -- the seam's three dependencies -------------------------------------------------
    def lifecycle(self, *, run_dir: Path, **_kw: Any) -> dict:
        from defender.runtime import scrub as scrub_mod

        self.run_dirs.append(run_dir)
        populate_run_dir(run_dir, disposition=self._disposition, leads=self._leads)
        if self._certify:
            scrub_mod.scrub(run_dir)
        self._note("lifecycle", run_dir)
        return {"output": "spec791 verdict", "requests": 1, "truncated_by": self._truncated_by}

    def visualize(self, run_dir: Path) -> None:
        self._note("visualize", run_dir)

    def open_case_ticket(self, run_dir: Path) -> None:
        self._note("open_case_ticket", run_dir)

    def close_case_ticket(self, run_dir: Path) -> None:
        self._note("close_case_ticket", run_dir)

    # -- what the steps saw --------------------------------------------------------------
    def _note(self, name: str, run_dir: Path) -> None:
        from defender.runtime import scrub as scrub_mod

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
    """The entrypoint's tail seam, checked before it is used.

    Checked here rather than at each call site so the failure names the DEMAND — the tail has
    no injection point — instead of surfacing as an unexpected-keyword TypeError inside a
    scenario about something else."""
    missing = [p for p in TAIL_SEAM if p not in inspect.signature(main).parameters]
    assert not missing, (
        f"the investigation entrypoint takes no {missing}: its tail has no injection seam, so "
        "every demand about what the tail DOES can only be read off its source — and a test "
        "that reads source cannot fail when the behaviour changes"
    )


def drive_tail(main, alert: Path, tail: SpecTail, *args: str) -> int:
    """Drive the REAL entrypoint over one alert with the tail's dependencies injected.

    `main` is passed in rather than imported here so each scenario's own body names the
    entry point it drives."""
    require_tail_seam(main)
    return main([str(alert), *args], lifecycle=tail.lifecycle, visualize=tail.visualize,
                ticket_writer=tail)


def plant_alert(tmp_path: Path, *, name: str = "alert.json",
                alert_bytes: bytes | None = None) -> Path:
    """The operator's own alert file — the argv the entrypoint is handed."""
    alert = tmp_path / name
    alert.parent.mkdir(parents=True, exist_ok=True)
    alert.write_bytes(
        alert_bytes if alert_bytes is not None
        else json.dumps({"rule": {"id": "5710", "key": "spec.rule"}}).encode("utf-8")
    )
    return alert


def learn_markers(paths) -> list[str]:
    q = paths.learn_queue_dir
    return sorted(p.name for p in q.glob("*.json")) if q.is_dir() else []


def author_markers(paths) -> list[str]:
    q = paths.author_queue_dir
    return sorted(p.name for p in q.glob("*.json")) if q.is_dir() else []


def marker_body(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fn_node(path: Path, name: str) -> ast.AST:
    """The named function's node in `path` (a composition claim's instrument)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{path.name} defines no `{name}` — re-site this demand")


def call_order(path: Path, name: str) -> list[str]:
    """The names called inside `path::name`, in source-position order; attribute calls
    collapse to the attribute (`_run.visualize(...)` reads as `visualize`)."""
    hits: list[tuple[tuple[int, int], str]] = []
    for node in ast.walk(fn_node(path, name)):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
        if called:
            hits.append(((node.lineno, node.col_offset), called))
    return [n for _, n in sorted(hits)]
