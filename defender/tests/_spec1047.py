"""Shared machinery for #1047's cut-short-record spec — NO test scripts.

THE CHANGE. The exit class a run ended on (`truncated_by`) moves onto a path no box can
write, and three consumers key on it: the family judge files a cut-short world as a third row
shape instead of grading the host's forced report as a verdict (O1); the ticket lane decides
per exit class instead of on "is there a readable report.md" (O2); the archive writes each
world a host-owned record of how its run ended (O3). The design's FIRST draft put the exit
class in `report.md`'s frontmatter and was refuted by its own cold review — `validate_report`
admits unknown keys (claim h3) and the judge reads a copy of a file the box had an rw bind on
(claim h4), so a planted `truncated_by:` line would have let a graded subject exclude its own
world from grading. Everything in this module exists to keep the value off that path.

**None of the mechanism exists at base `59bdea44`.** `session_store.normalized_truncated_by`,
`runtime/run_end.py`, `archive.RUN_END_NAME`, `_grade_world`'s cut-short early return and
the ticket lane's exit-class parameter are all absent. That is the expected state of a
spec — RED against HEAD. Every import goes through `mod()`/`sym()` PER TEST (the
`_triplet_947` / `_judge_921` idiom) so a missing target is one failure per test rather than
one collection error that hides the other ninety-odd assertions.

THE RESOLVED MECHANISM, as §7 settled it — a test written against the doc's own sentences
would be written against two refuted readings:

* **F2 reading A (human).** The archive does NOT read a session store. The sibling's own
  host-side process writes a SIDECAR beside its run dir — `verdict_path`'s shape
  (`tree.parent / f"{tree.name}<suffix>"`, `runtime/scrub.py:124-129`) — and
  `archive_episode` copies it in as `worlds/<label>/run_end.json`. Reading B (pre-minted
  session ids threaded through argv) was rejected.
* **F-A/F-B reading B (human, §7 round 2).** The record carries a SECOND field,
  `closed_before_cut`, saying whether the model had already closed
  (`challenge_gate.ReviewState.of(deps).closed`) when the exit class was stamped. Probe p21
  (EXECUTED) found the forced close's `closed`-skip branch reachable on all five exit classes
  with zero test coverage, so a world can carry a real model verdict AND a stamped exit class.
  The record must distinguish the two; a cut-short world that had already decided keeps its
  verdict. The write therefore sits in the DRIVER, before the forced report write
  (`driver/__init__.py:303`), not in `run.py`'s tail — probe p25 (EXECUTED) drove three arms
  of that tail that raise and skip everything after them, one of which loses the summary
  itself, so a tail-sited write has no value to write even in principle.
* **F3 reading A (human).** The ticket lane takes the exit class as an IN-PROCESS PARAMETER
  from `run.py`, exactly as `enqueue_curation` already does twelve lines later. It reads no
  store and nothing inside the run dir — reading B (recover the case id from
  `session_store_pointer.json`) is precisely the box-writable input O1's security dive
  forbids as a decider of "was this run cut short".
* **F5 reading A (human).** The cut-short check runs BEFORE `_missing_required_input`, so all
  five exit classes name their exit rather than only the two that also produce a forced report.
* **F-D (auto, confirmed EXECUTED by round-2 probe #30).** The leave-open arm's ticket identity
  is `run_dir.name` — the same namespace `open_case_ticket` already writes under, reachable
  with no report.md on disk at all.
* **F-F (auto, confirmed EXECUTED by round-2 probe #11), resolved at the LANE rather than the
  leaf.** The archive's `copy2` lane wrote THROUGH a pre-existing hard link at a destination
  leaf. Rather than fork one file out of that lane, the record is the seventh single file —
  beside the scrub verdict, the other host-side sidecar — and the lane's pre-copy destination
  screen now refuses a hard link at ANY of the seven (`_run_paths.plain_file`, the rule
  `write_guarded` already applied). The archive interprets nothing: it copies the sidecar's
  bytes, and the judge alone decides what they mean (`run_end.parse_record`).
* **F-M (auto).** The vocabulary owner is STRICT — no whitespace strip, no case fold, no
  confusable fold. Under the resolved mechanism the value's only producer is the driver's own
  stamp, so leniency buys nothing and costs a coercion path.

FAULT INJECTION, down the charge's hierarchy and never off it. Tier 1 wherever the primitive
is cheap: the undecodable bytes are written, the symlink is planted, the run dir is emptied,
`ReviewState.of(deps).closed` is really set, and the driver's five exit classes are reached by
raising the REAL exception classes through the REAL `agent.iter` loop (`_spec923.StuckModel`
exhausts pydantic-ai's own tool-retry budget; `BudgetKill`/`RunAborted` are raised from the
model call, the seam the real kills reach the loop through). Tier 2 for the two dependencies
that are neither cheap nor deterministic — the model and the ticket system's HTTP endpoint —
and each fake's fault content cites the ledger claim that observed it:

* `FakeTicketSystem(status=...)` — the transport's own answer shape, `(status, body)`, from
  `ticket_writer._request`; the "no/malformed response" arm is `status=None`, the shape a
  `TransportFault` already produces there (claim n4's namespace probe, round-2 item 2,
  EXECUTED, drove exactly this stand-in against the real writer and the real mapping.yaml).
* `FakeTicketSystem(configured=False)` — `_load_config` returning `None`, the unconfigured
  lane F-R resolved to today's silence.

Fakes enter through the entry point's INJECTION SEAMS — `deps=` on `record_case_ticket`,
`run_dirs=` on `archive_episode`, the `agent`/`store` arguments on `_drive_agent` — never by
`monkeypatch.setattr`, which CI ratchets (`scripts/lint/lint_monkeypatch.py`).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests._judge_921 import (  # noqa: F401 — re-exported vocabulary
    ALERT_ID,
    EPISODE_ID,
    EPISODE_TOKEN,
    EPISODES_BASE_ENV,
    RUNS_BASE_ENV,
    STATE_DIR_ENV,
    accepted_episode,
    archived_judge_world,
    archived_world,
    base_capture,
    captured_row,
    episode,
    ledger_row,
    mod,
    provenance_record,
    report_text,
    rows,
    runs_base,
    sibling_run_dir,
    staged_row,
    sym,
    word_of,
    world_doc,
    write_ledger,
)
from defender.tests._triplet_947 import (  # noqa: F401 — re-exported vocabulary
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
    return tuple(sym("runtime.session_store", "TRUNCATED_BY_VALUES"))


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
    """`archive.RUN_END_NAME` — the archived record's leaf name, from the archive module.

    F6 resolved the spelling to the design doc's own (`run_end.json`), and the constant lives
    beside the other archive names because the judge reads back every name this module writes:
    a name spelled in the writer and re-spelled in the reader is a rename that leaves the two
    looking at different files with no error anywhere."""
    return sym("learning.branch.archive", "RUN_END_NAME")


def sidecar_path(run_dir: Path) -> Path:
    """`run_end.sidecar_path(run_dir)` — the HOST-SIDE record, beside the run dir.

    Resolved through the production function, never composed here: the whole of O3's security
    argument is that this path is a pure function of a path the host already holds, and a
    fixture that spelled its own would be a second opinion about where the record lives."""
    return sym("runtime.run_end", "sidecar_path")(Path(run_dir))


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
    """Land `worlds/<label>/run_end.json` directly, for the scenarios about what the JUDGE does
    with a record rather than about how the archive produced one."""
    world = Path(episode_dir) / "worlds" / label
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


def graded(episode_dir: Path) -> dict[str, dict]:
    """`grade_family`'s per-world rows, keyed by label — the real mechanical pass over a real
    episode dir, which is the entry point every O1 demand is stated at."""
    return rows(mod("learning.judge.family").grade_family(Path(episode_dir)))


def family_word(episode_dir: Path) -> str:
    """The family-level `verdict_word` the same pass computes."""
    return word_of(mod("learning.judge.family").grade_family(Path(episode_dir)))


def world_facts(episode_dir: Path, label: str) -> Any:
    """`read_world_facts` over one archived world — the judge's own reader, driven directly for
    the premises that are about what a record READS AS rather than about the row it produces."""
    return mod("learning.judge.family").read_world_facts(
        Path(episode_dir), label, episode_token=EPISODE_TOKEN)


# --------------------------------------------------------------------------------------
# The ticket lane.
# --------------------------------------------------------------------------------------

#: The config `_load_config` returns on a configured lane. Three keys, because
#: `ticket_writer._load_config` refuses anything short of them and `_request` reads all three.
TICKET_CONFIG = {
    "URL_BASE": "http://tickets.test",
    "BASTION_HOST": "bastion.test",
    "TIMEOUT_SEC": "10",
}


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
    """The ticket system's HTTP endpoint, injected through `TicketWriterDeps`.

    TIER 2 OF THE FAULT HIERARCHY AND NOTHING MORE. A real ticket system is neither cheap nor
    deterministic to drive, so the transport's ANSWER is scripted and every REQUEST is
    recorded — a fake that only returned statuses would leave the entire outbound channel
    unpinned, and the outbound channel is the whole of what O2 is about.

    It injects faults only; it classifies nothing. `status=None` is `_request`'s own
    transport-error answer (`ticket_writer.py:70-75`: a `TransportFault` returns
    `(None, "transport error: …")`), and `configured=False` is `_load_config` returning `None`,
    the unconfigured lane F-R resolved to today's silence. No other fault is induced here,
    because no claim in the ledger observes one on this dependency.
    """

    status: str | None = "200"
    configured: bool = True
    calls: list[TicketCall] = field(default_factory=list)

    def load_config(self) -> dict[str, str] | None:
        return dict(TICKET_CONFIG) if self.configured else None

    def request(self, _config: dict[str, str], method: str, path: str,
                body: dict | None = None) -> tuple[str | None, str]:
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
        return sym("scripts.case_history.ticket_writer", "TicketWriterDeps")(
            load_config=self.load_config, request=self.request)

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
    mod("scripts.case_history.ticket_writer").record_case_ticket(
        Path(run_dir), fake.deps(), **kw)
    return fake


def open_ticket(run_dir: Path, *, ticket: FakeTicketSystem | None = None) -> FakeTicketSystem:
    """Drive the REAL `open_case_ticket` — the leg that establishes the ticket key's namespace,
    with no `report.md` anywhere on disk (round-2 probe #30, EXECUTED)."""
    fake = ticket or FakeTicketSystem()
    mod("scripts.case_history.ticket_writer").open_case_ticket(Path(run_dir), fake.deps())
    return fake


def receipt(run_dir: Path) -> dict | None:
    """`ticket_write.json`, the lane's own record of what it did — or `None` when the lane
    wrote none. Demand #0b's stated observable, and F-L's resolution puts the note call's
    outcome here too."""
    path = Path(run_dir) / "ticket_write.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def closed_run_dir(tmp_path: Path, *, disposition: str = "malicious", report: bool = True,
                   name: str = "2026-09-16T12-00-00Z_case-1047-lotl-web1") -> Path:
    """A finished run dir as `run.py`'s tail meets it: an alert, and a committed `report.md`
    unless `report=False`.

    `report=False` is the shape the three no-report exit classes leave (claim h1) and the shape
    F-K's unreachable sub-case has: a forced-close-set exit whose own forced close failed."""
    run_dir = Path(tmp_path) / name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_text(
        json.dumps({"rule": {"id": ALERT_ID, "description": "lateral movement from web1"},
                    "timestamp": "2026-09-16T11:00:00Z"}), encoding="utf-8")
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

    from defender.runtime import challenge_gate, driver
    from defender.tests import _spec923
    from defender.tests._invlang_warn_836 import build_main_agent

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
    (`runtime/circuit_breaker.py`). What is under test is the driver's classification, not
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
    "session_store_pointer.json",
    "ticket_write.json",
    "provenance.json",
    "lessons_loaded.jsonl",
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
