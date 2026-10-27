"""Shared machinery for #1047's cut-short-record spec — NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape
from defender.tests.support.learning.branch import _triplet_947 as T

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.learning.judge._judge_921 import (  # noqa: F401 — re-exported vocabulary
    ALERT_ID,
    EPISODE_ID,
    EPISODES_BASE_ENV,
    FAMILY_AGENT_PREFIX,
    RUNS_BASE_ENV,
    STATE_DIR_ENV,
    accepted_episode,
    archived_judge_world,
    archived_world,
    base_capture,
    captured_row,
    episode,
    grade,
    ledger_row,
    mod,
    provenance_record,
    report_text,
    rows,
    runs_base,
    scripted_judge,
    sibling_run_dir,
    staged_row,
    sym,
    word_of,
    world_doc,
    world_id,
    write_ledger,
)
from defender.tests.support.learning.core._state1135 import state_over
from defender.tests.support.learning.branch._triplet_947 import (  # noqa: F401 — re-exported vocabulary
    DEFENDER,
    WORLDS,
    refusals,
)

#: The five exit classes a MAIN session can end on, plus the sixth, lead-only member. Read off
#: `session_store.TRUNCATED_BY_VALUES` at call time rather than re-spelled here, because a
#: suite that hard-coded the vocabulary would keep passing the day a member is renamed — the
#: exact drift `normalized_truncated_by` exists to make impossible.
def vocabulary() -> tuple[str, ...]:
    """`TRUNCATED_BY_VALUES`, from the module that owns it."""
    return tuple(sym("records.session_store", "TRUNCATED_BY_VALUES"))


#: The two exits on which the model was stopped before it could close and the host still owes
#: the run a `report.md` (`driver._CUT_SHORT_WITH_A_MODEL_STILL_OWED_A_CLOSE`, claim h1,
#: narrowed by ddd41b88 after #1047 was filed). `aborted`/`budget`/`store` write no report.
FORCED_CLOSE_SET = ("request-limit", "retry-exhausted")

#: The three exits that write no `report.md` at all today (claim h1). F5's ordering resolution
#: is exactly about these: without it `cut_short` would only ever be observable for the two
#: classes above, undercutting O1's own words ("the reason names the exit").
NO_REPORT_EXITS = ("aborted", "budget", "store")


# --------------------------------------------------------------------------------------
# The record — the sidecar the host writes and the archived copy the judge reads.
# --------------------------------------------------------------------------------------


def run_end_name() -> str:
    """The archived run-end record's leaf name, ASKED OF THE OWNER (#1077 D7).

    F6 resolved the spelling to the design doc's own (`run_end.json`). It used to be read off
    `archive.RUN_END_NAME`, on the reasoning that the judge reads back every name the archive
    writes and the two must not re-spell it. True, and the re-export was still a second home:
    archive.py now holds no record name, and both the writer and this helper reach the same
    accessor on `_episode_paths`.
    """
    return str(sym("records._episode_paths", "WORLD_LEAVES").run_end)


def sidecar_path(run_dir: Path) -> Path:
    """`run_end.sidecar_path(run_dir)` — the HOST-SIDE record, beside the run dir.

    Resolved through the production function, never composed here: the whole of O3's security
    argument is that this path is a pure function of a path the host already holds, and a
    fixture that spelled its own would be a second opinion about where the record lives."""
    return sym("records.run_end", "sidecar_path")(Path(run_dir))


def plant_sidecar(run_dir: Path, *, truncated_by: str | None = None,
                  closed_before_cut: bool = False, raw: str | bytes | None = None) -> Path:
    """Land the host-side run-end sidecar beside `run_dir`, as the driver leaves it.

    `raw=` writes the bytes verbatim, for the states F-G's skip-and-report resolution is about
    (zero bytes, truncated JSON, a JSON list) and for premise 22's undecodable bytes — a real
    input through the real reader, not a stubbed return value."""
    path = sidecar_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    if raw is None:
        path.write_text(json.dumps(record_doc(truncated_by, closed_before_cut)), encoding="utf-8")
    elif isinstance(raw, bytes):
        path.write_bytes(raw)
    else:
        path.write_text(raw, encoding="utf-8")
    return path


def record_doc(truncated_by: str | None, closed_before_cut: bool = False) -> dict[str, Any]:
    """The run-end record's document — BOTH fields.

    `closed_before_cut` is F-A reading B's second field: the host's own answer to "had the
    model already decided when the exit class was stamped", read from
    `challenge_gate.ReviewState.of(deps).closed` at the moment of the cut. Without it the third
    row shape's own reason string ("the host's report is not a verdict") is literally false for
    a world that produced a real, confident, model-authored verdict."""
    return {"truncated_by": truncated_by, "closed_before_cut": closed_before_cut}


def plant_archived_record(episode_dir: Path, label: str, *, truncated_by: str | None = None,
                          closed_before_cut: bool = False,
                          raw: str | bytes | None = None) -> Path:
    """Land `worlds/<world-uuid>/run_end.json` directly, for the scenarios about what the JUDGE does
    with a record rather than about how the archive produced one."""
    world = Path(episode_dir) / "worlds" / T.world_id(episode_dir, label)
    world.mkdir(parents=True, exist_ok=True)
    path = world / run_end_name()
    if raw is None:
        path.write_text(json.dumps(record_doc(truncated_by, closed_before_cut)), encoding="utf-8")
    elif isinstance(raw, bytes):
        path.write_bytes(raw)
    else:
        path.write_text(raw, encoding="utf-8")
    return path


def cut_short_episode(tmp_path: Path, *, cut: dict[str, str] | None = None,
                      closed: tuple[str, ...] = (), **kw: Any) -> Path:
    """An accepted #947-layout episode, with a run-end record on the worlds named in `cut`.

    `cut` maps world label -> exit class; `closed` names the labels whose model had already
    closed before the cut (F-A's second field). Worlds not named in `cut` get NO record at all
    — which is `missing_run_end_grades_as_today`'s own state, and the control every negative
    in this suite compares against."""
    ledgers = kw.pop("ledgers", None) or {"b": [staged_row("b")], "c": []}
    ep = accepted_episode(tmp_path, ledgers=ledgers, **kw)
    for label, exit_class in (cut or {}).items():
        plant_archived_record(ep, label, truncated_by=exit_class,
                              closed_before_cut=label in closed)
    return ep


def graded(episode_dir: Path, *, judge: Any = None) -> dict[str, dict]:
    """`graded_record`'s per-world rows, keyed by label."""
    return rows(graded_record(episode_dir, judge=judge))


def graded_record(episode_dir: Path, *, judge: Any = None) -> Any:
    """The family record (`EpisodeGrade`) — the real judge pass
    (`learning.judge.grade_episode`, which reads each world through `family.read_world`) over
    a real episode dir, which is the entry point every O1 demand is stated at."""
    ep = Path(episode_dir)
    (ep / "judge.yaml").unlink(missing_ok=True)
    side = ep.parent / f".{ep.name}-judge"
    return grade(ep, judge=judge,
                 state=state_over(side / "learning-state"))


def graded_with_view(episode_dir: Path) -> tuple[dict[str, dict], dict[str, str]]:
    """One pass: the per-world rows, and what the family-scope call was shown of each world,
    keyed by label."""
    judge = scripted_judge()
    record = graded_record(episode_dir, judge=judge)
    family = [p for p, a in zip(judge.prompts, judge.agent_ids, strict=True)
              if str(a).startswith(FAMILY_AGENT_PREFIX)]
    assert family, "the pass never made its family-scope call"
    return rows(record), _family_view_of(family[-1])


def _family_view_of(prompt: str) -> dict[str, str]:
    """`graded_with_view`'s per-world view, read off one family prompt's text."""
    header = prompt.split("## CONTRAST TABLE", 1)[0]
    noise = prompt.split("## NOISE CONTEXT", 1)[-1]
    view: dict[str, str] = {}
    for label, block in re.findall(r"(?ms)^### run (\S+)\n(.*?)(?=^### run |\Z)", header):
        reached = re.search(r"reached verdict \(its archived report\.md\): <(run-[0-9a-f]+)-"
                            r"untrusted>\n(.*?)\n</\1-untrusted>", block, re.S)
        view[label] = f"verdict={reached.group(2)!r}" if reached else block.strip()
    for label in re.findall(r"(?m)^- world (\S+): ", noise):
        assert label not in view, f"world {label} is both a usable run and excluded: {prompt}"
        view[label] = "NOT JUDGED"
    return view


def family_view(episode_dir: Path) -> dict[str, str]:
    """`graded_with_view`'s family view alone."""
    return graded_with_view(episode_dir)[1]


def judge_calls_for(judge: Any, label: str, *, episode_dir: Path) -> list[str]:
    """The judge calls bound to the selected world's persisted UUID."""
    prefix = f"judge:{world_id(episode_dir, label)}:"
    return [a for a in judge.agent_ids if str(a).startswith(prefix)]


def world_facts(episode_dir: Path, label: str) -> Any:
    """`read_world_facts` over one archived world — the judge's own reader, driven directly for
    the premises that are about what a record READS AS rather than about the row it produces."""
    from defender._io import bind

    with bind(Path(episode_dir)) as bound:
        return mod("learning.judge.family").read_world_facts(
            bound, label, world_id=world_id(episode_dir, label), absent_ledger_ok=True)


# --------------------------------------------------------------------------------------
# The ticket lane.
# --------------------------------------------------------------------------------------

#: The words the two comment kinds are told apart by on the wire. `ESCALATION_MARK` is a
#: phrase of the host's fixed escalation sentence; `UNREADABLE_MARK` is the fixed sentence the
#: record carries when the report yields no disposition (#767 §7 R10) — a record with no
#: proposal in it, which is still a record and not a note.
ESCALATION_MARK = "Escalate for manual review"
UNREADABLE_MARK = "No disposition could be recorded"


@dataclass
class TicketCall:
    """One outbound call the ticket lane made, as the transport saw it."""

    method: str
    path: str
    body: dict | None = None

    @property
    def is_transition(self) -> bool:
        """A lifecycle move. The host's client has none (#767 O1: closing is a person's act),
        so this is the census every scenario expects EMPTY — the one property here whose
        positive case is a defect."""
        return self.path.endswith("/transitions")

    @property
    def is_comment(self) -> bool:
        return self.path.endswith("/comments")

    @property
    def is_note(self) -> bool:
        """The cut-short escalation note (#1047 O2): the fixed host sentence asking a person
        to escalate, with no verdict in it. Told apart from a record by its body — both are
        comments on the wire, since a comment is the only write the host can make."""
        return self.is_comment and ESCALATION_MARK in self.text()

    @property
    def is_record(self) -> bool:
        """The investigation record (#767 D2): the host's PROPOSED disposition off the report,
        for a person to review and close on."""
        return self.is_comment and not self.is_note

    @property
    def key(self) -> str:
        """The ticket key this call addressed — the path segment between `/tickets/` and the
        verb. `open_case_ticket` writes its key in the BODY and the record addresses it in the
        PATH, so a scenario proving the two lanes share one namespace has to read both."""
        parts = self.path.strip("/").split("/")
        return parts[1] if len(parts) > 1 else ""

    def text(self) -> str:
        """Every string value in the body, joined — what a person reading this call sees."""
        return json.dumps(self.body or {})


@dataclass
class FakeTicketSystem:
    """The ticket system's HTTP endpoint, injected through `TicketWriterDeps`."""

    status: str | None = "200"
    configured: bool = True
    calls: list[TicketCall] = field(default_factory=list)

    def request(self, _config: dict[str, str], method: str, path: str,
                body: dict | None = None, *, ctx: Any) -> tuple[str | None, str]:
        self.calls.append(TicketCall(method, path, body))
        if method == "GET":
            # The writer's courtesy read-back before it comments (#767): an open, unreleased
            # case. The scripted fault below is about the WRITE — a note call that fails —
            # so the read always answers.
            return "200", json.dumps({"key": path.rsplit("/", 1)[-1], "status": "open",
                                      "labels": [], "comments": []})
        if self.status is None:
            return None, "transport error: docker exec failed"
        return self.status, ""

    def deps(self) -> Any:
        return sym("investigation.ticket_writer", "TicketWriterDeps")(
            request=self.request)

    @property
    def writes(self) -> list[TicketCall]:
        """Every call that could change the estate — the read-back is not one."""
        return [c for c in self.calls if c.method != "GET"]

    @property
    def transitions(self) -> list[TicketCall]:
        return [c for c in self.calls if c.is_transition]

    @property
    def records(self) -> list[TicketCall]:
        return [c for c in self.calls if c.is_record]

    @property
    def notes(self) -> list[TicketCall]:
        return [c for c in self.calls if c.is_note]


def record_ticket(run_dir: Path, *, ticket: FakeTicketSystem | None = None,
                  **kw: Any) -> FakeTicketSystem:
    """Drive the REAL `record_case_ticket` over `run_dir` and return the fake it talked to.

    `**kw` is the lane's new input under F3 reading A — `truncated_by=` and
    `closed_before_cut=`, passed in-process by `run.py` from the driver's own summary. Nothing
    here reads a store, a pointer file or anything else inside the run dir to get them."""
    fake = ticket or FakeTicketSystem()
    mod("investigation.ticket_writer").record_case_ticket(
        _run_handle_1165(Path(run_dir)), fake.deps(), **_handed(run_dir, fake), **kw)
    return fake


def open_ticket(run_dir: Path, *, ticket: FakeTicketSystem | None = None) -> FakeTicketSystem:
    """Drive the REAL `open_case_ticket` — the leg that establishes the ticket key's namespace,
    with no `report.md` anywhere on disk (round-2 probe #30, EXECUTED)."""
    fake = ticket or FakeTicketSystem()
    mod("investigation.ticket_writer").open_case_ticket(
        _run_handle_1165(Path(run_dir)), fake.deps(), **_handed(run_dir, fake))
    return fake


def _handed(run_dir: Path, fake: FakeTicketSystem) -> dict[str, Any]:
    """What `run.py` hands both legs (#1107): the run's record, the code tree and the run's env.

    The record is the committed fixture tenant's (set up under the test's data root), as this
    lane read the checkout's own mapping before the move; an unconfigured fake gets a tenant
    planted beside the run with no case-history `config.env`."""
    from defender.tests.support.tenancy import _tenants1106
    from defender.tests.tenancy.tenant_1107_settings import _spec1107

    if fake.configured:
        record = _tenants1106.fixture_run_tenant()
    else:
        root = Path(run_dir).parent / "unconfigured-tenants"
        _spec1107.plant(root, "t1047", configs={})
        record = _spec1107.resolve(root, "t1047")
    return {"tenant": record, "defender_dir": _tenants1106.DEFENDER,
            "env": mod("box").run_env(_tenants1106.DEFENDER, Path(run_dir))}


def receipt_path(run_dir: Path) -> Path:
    """The ticket receipt's location: a sidecar beside the run dir, keyed by the run's name
    (#1107 moved it out of the box-writable run dir; it was `run_dir/ticket_write.json`)."""
    return Path(run_dir).parent / f"{Path(run_dir).name}.ticket-write.json"


def receipt(run_dir: Path) -> dict | None:
    """The ticket receipt, the lane's own record of what it did — or `None` when the lane
    wrote none. Demand #0b's stated observable, and F-L's resolution puts the note call's
    outcome here too."""
    path = receipt_path(run_dir)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def closed_run_dir(tmp_path: Path, *, disposition: str = "malicious", report: bool = True,
                   name: str = "2026-09-16t12-00-00z_case-1047-lotl-web1") -> Path:
    """A finished run dir as `run.py`'s tail meets it: an alert, and a committed `report.md`
    unless `report=False`.

    `report=False` is the shape the three no-report exit classes leave (claim h1) and the shape
    F-K's unreachable sub-case has: a forced-close-set exit whose own forced close failed.

    `name` is a LABEL for the run, or its id: a canonical UUID names the folder as it is, any
    other text names it `fixture_uuid(name)`, so a test reads the run's id as `run_dir.name`."""
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    run_dir = Path(tmp_path) / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    run_dir.mkdir(parents=True, exist_ok=True)
    from defender.tests.support.storage._alert_plant import plant_alert

    plant_alert(run_dir, {"rule": {"id": ALERT_ID, "description": "lateral movement from web1"},
                          "timestamp": "2026-09-16T11:00:00Z"})
    if report:
        (run_dir / "report.md").write_text(report_text(disposition), encoding="utf-8")
    return run_dir


# --------------------------------------------------------------------------------------
# The driver — the frame that writes the sidecar, under F-B's resolution.
# --------------------------------------------------------------------------------------


def drive(deps: Any, model: Any, *, bounds: Any = None, store: Any = None) -> tuple[Any, Any, Any]:
    """Drive the REAL `_drive_agent` over MAIN's REAL agent with `model` as the model function.

    The one seam every exit class in this suite is reached through, and it is the production
    frame: `run_investigation` calls exactly this, and F-B sited the run-end write inside it,
    before the forced close at `driver/__init__.py:303`. Returns
    `(run, end, exit_reason)` — `end` is the driver's own `RunEnd` record, the same value
    `run_investigation` flattens onto its summary."""
    import asyncio

    from defender.investigation import challenge_gate, driver
    from defender.tests.support.runtime.engine import _spec923
    from defender.tests.support.invlang.validation._invlang_warn_836 import build_main_agent

    agent = build_main_agent(model)
    return asyncio.run(driver._drive_agent(
        agent, "go", deps, store if store is not None else _spec923.NullStore(), "sid",
        bounds if bounds is not None else challenge_gate.default_bounds(),
    ))


def killing_model(exc: BaseException) -> Any:
    """A model function that raises `exc` from the model call — the seam the real kills reach
    the loop through (a tool hook and a gather agent both propagate them past `agent.iter`).

    REAL EXCEPTION CLASSES ONLY, and only the ones the driver's own handlers name:
    `BudgetKill` (`hooks/budget_enforcer.py`) and `RunAborted`
    (`systems/circuit_breaker.py`). What is under test is the driver's classification, not
    where the kill originated — the same construction `test_992_close_contract.py` already
    uses for these two arms."""

    class _Killed:
        __name__ = "Killed"

        def __call__(self, _messages: Any, _info: Any) -> Any:
            raise exc

    return _Killed()


def clean_model(text: str = "done") -> Any:
    """A model function that answers once and stops — a run that ends CLEANLY, with no exit
    class at all. The control for every cut-short arm, and `s33`'s own subject: the sidecar
    write is unconditional, so a clean run writes `{"truncated_by": null}`."""
    from pydantic_ai.messages import ModelResponse, TextPart

    class _Clean:
        __name__ = "Clean"

        def __call__(self, _messages: Any, _info: Any) -> Any:
            return ModelResponse(parts=[TextPart(content=text)])

    return _Clean()


def sidecar_doc(run_dir: Path) -> dict | None:
    """The sidecar's parsed document, or `None` when nothing is at the path."""
    path = sidecar_path(run_dir)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# Forgery surfaces — everything a box can write inside its own rw bind.
# --------------------------------------------------------------------------------------

#: Every name in a run dir (or an archived world dir) a box could plausibly plant a
#: `truncated_by`-looking value at. `no_box_writable_input_to_cut_short` binds EVERY surface
#: the content could reach, and an unbound surface is exactly where the leak ships; this is
#: that list, held in one place so a negative that walks it cannot be quietly narrowed.
FORGEABLE_NAMES = (
    "run_end.json",
    # Not written inside the run dir since #1235 F2 (the case pointer is a host-only sidecar
    # beside it now), but the box can still plant a file at the old name; kept, like the two
    # state names below.
    "session_store_pointer.json",
    "ticket_write.json",
    "provenance.json",
    "lessons_loaded.jsonl",
    # No host writer since #1235 (the counters and the breaker are in-memory state), but the
    # box can still plant a file at either name inside its own rw bind, and dropping them
    # would only narrow every negative that walks this list. Kept deliberately.
    "circuit_breaker.json",
    "budget.json",
    "tool_trace.jsonl",
)


def salt_run_dir(run_dir: Path, value: str = "request-limit") -> list[Path]:
    """Plant a `truncated_by`-looking value at every box-writable name in `run_dir`, and
    return what was planted.

    THE BOX IS ROOT ON THIS MOUNT (flagged fact F4): the run dir is the box's rw bind, so
    every one of these is content an adversary chooses. A real file through the real readers —
    tier 1 — not a fake that pretends a reader saw one."""
    planted: list[Path] = []
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    for name in FORGEABLE_NAMES:
        path = run_dir / name
        path.write_text(json.dumps(record_doc(value)), encoding="utf-8")
        planted.append(path)
    # And the one surface that is not JSON: the report's frontmatter, which `validate_report`
    # admits an unknown key into (claim h3) — the exact hazard that killed the first design.
    report = run_dir / "report.md"
    if report.is_file():
        report.write_text(report_text("malicious", extra=f"truncated_by: {value}\n"),
                          encoding="utf-8")
        planted.append(report)
    return planted


def plant_frontmatter(world_dir: Path, extra: str, *, disposition: str = "malicious",
                      raw: str | bytes | None = None) -> Path:
    """Rewrite an archived world's `report.md` with `extra` spliced into its frontmatter.

    `validate_report` accepts an unknown frontmatter key (claim h3, EXECUTED: the spliced
    document returned `None` from the validator, i.e. accepted), and the judge reads the
    archived copy of a file the box had an rw bind on (claim h4) — so this is the forgery the
    revised design exists to make inert, driven as a real document through the real reader."""
    path = Path(world_dir) / "report.md"
    if raw is None:
        path.write_text(report_text(disposition, extra=extra), encoding="utf-8")
    elif isinstance(raw, bytes):
        path.write_bytes(raw)
    else:
        path.write_text(raw, encoding="utf-8")
    return path


def row_without_volatiles(row: dict) -> dict:
    """One graded row with nothing volatile in it — for the negatives, which assert a planted
    forgery left the grade BYTE-IDENTICAL to the control's rather than merely "still
    ungradable". A bare `assert "request-limit" not in row` is also green on an empty row."""
    return {k: v for k, v in sorted(row.items())}
