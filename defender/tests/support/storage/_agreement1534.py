"""#1534 reader agreement (no tests): one planted run per record outcome, read by each reader that holds a run through its own
entry, answered in one shape. Production names are imported inside functions.

An answer is `("disposition", d)`, `("never", "")`, `("fault", <the reader's outward text>)` or, for the feedback outcome whose tenant
word cannot tell the three apart, `("unreadable", "")`. `slots` is every outward text the reader produced (its stdout, comment,
receipt, page or failure chain); the log is read by the test."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.storage import _readers1534 as R

ANSWER_DISPOSITION, ANSWER_NEVER, ANSWER_FAULT, ANSWER_UNREADABLE = "disposition", "never", "fault", "unreadable"

#: Kinds a run-handle reader cannot meet (they belong to the episode view's route), by kind: not applicable to any reader here.
EPISODE_ONLY = ("roster-gone", "arm-refused")

#: Per reader, the plantable kinds its route does not answer in its own slot, and why. The run page refuses a folder with no usable
#: pointer, and a database that will not open or is at another version fails the page's other reads first, so those kinds are not
#: its own. `store-unreadable` as a QUERY-TIME fault (`Plan.at_query`: the file opens, the ledger reads, the record's query errors)
#: does reach the page and is run against it (`applies`).
NOT_APPLICABLE = {
    "page": ("no-pointer", "legacy-link", "pointer-unreadable", "store-unreadable", "schema-version"),
}


@dataclass(frozen=True)
class Plan:
    """What one planted run holds: a record (`disposition`), a store with no row (`closed=False`), or a fault (`fault`, a
    `_readers1534` fault; `NO_POINTER` and `LEGACY_LINK` among them). `invalid_as` is what a `row-invalid` leaves in the column."""

    label: str
    disposition: str = "benign"
    closed: bool = True
    fault: str | None = None
    invalid_as: str | None = None
    at_query: bool = False  # `store-unreadable` by a VIEW over a missing table: the file opens and the rest of the store reads

    @property
    def kind(self) -> str:
        """The lookup outcome this plan means, for a reader whose route reaches every plantable fault."""
        if self.fault in (None, R.NO_POINTER, R.LEGACY_LINK) and self.closed is False:
            return ANSWER_NEVER
        if self.fault == R.NO_POINTER:
            return ANSWER_NEVER
        return ANSWER_FAULT if self.fault else ANSWER_DISPOSITION

    @property
    def lookup_kind(self) -> str | None:
        """The `CouldNotLook` kind a fault plan reads as."""
        return None if self.kind != ANSWER_FAULT else self.fault

    @property
    def case_id(self) -> str:
        """The case id (so the database's file name) the plan's store gets: the only place `DETAIL_MARK` is planted."""
        return f"{R.DETAIL_MARK}-{self.label}"

    def fields(self) -> dict | None:
        return R.valid_fields(self.disposition) if self.closed else None


def applies(route: str, plan: Plan) -> bool:
    """Does `route` answer `plan` in its own slot? (`NOT_APPLICABLE`, less the query-time fault the run page does reach.)"""
    if plan.at_query and plan.fault == "store-unreadable":
        return True
    return plan.fault not in NOT_APPLICABLE.get(route, ())


def plant(run_dir: Path, plan: Plan) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    R.plant_run(run_dir, plan.fields(), fault=plan.fault, invalid_as=plan.invalid_as, case_id=plan.case_id,
                  at_query=plan.at_query)


def _run_id(plan: Plan) -> str:
    return fixture_uuid(f"agree-{plan.label}")


def _fault_text(*parts: str) -> str:
    return "\n".join(parts)


# --- the readers --------------------------------------------------------------------------------------

def ticket(root: Path, plan: Plan) -> tuple[tuple[str, str], list[str]]:
    """The record leg: the head of the posted comment, or no comment and the error receipt's reason."""
    from defender.tests.support.runtime.engine._spec767 import ALERT, ALERT_MAPPING, FakeStore, receipt, record
    from defender.tests.support.storage._alert_plant import plant_alert

    run_dir = root / _run_id(plan)
    plant(run_dir, plan)
    plant_alert(run_dir, ALERT, mapping=ALERT_MAPPING)
    store = FakeStore(root / "store")
    record(run_dir, store)
    if store.calls:
        body = store.comment_body()
        if "No disposition was recorded" in body:
            return (ANSWER_NEVER, ""), [body]
        return (ANSWER_DISPOSITION, body.split(" — ", 1)[0]), [body]
    reason = receipt(run_dir)["reason"] or ""
    return (ANSWER_FAULT, reason), [json.dumps(receipt(run_dir))]


def page(root: Path, plan: Plan, monkeypatch) -> tuple[tuple[str, str], list[str]]:
    """The run page: the headline's disposition badge, or the post-run step's failure chain."""
    from defender._vocab import UNKNOWN_DISPOSITION
    from defender.presentation.visualize_run import VisualizeFailed, save_page
    from defender.tests.support.presentation import _page1534 as P
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root / "state"))
    root.mkdir(parents=True, exist_ok=True)
    run = P._build_run(root, plan.fields(), record=plan.closed, case_id=plan.case_id)
    R.fault_run(run, plan.fault, invalid_as=plan.invalid_as, at_query=plan.at_query)
    try:
        html = P._page(run)
    except VisualizeFailed:
        html = None
    if html is not None:
        badge = re.search(r"disp-badge disp-([^\s\"']+)", html)
        shown = badge.group(1) if badge else ""
        return ((ANSWER_NEVER, "") if shown == UNKNOWN_DISPOSITION else (ANSWER_DISPOSITION, shown)), [html]
    chain, link = [], None
    try:
        save_page(fixture_run(run))
    except VisualizeFailed as failed:
        link = failed
    while link is not None:
        chain.append(str(link))
        link = link.__cause__ or link.__context__
    text = " | ".join(chain)
    return (ANSWER_FAULT, text), [text]


def trace(root: Path, plan: Plan, monkeypatch, capsys) -> tuple[tuple[str, str], list[str]]:
    """The trace CLI's row for the run: its disposition column, the unknown mark, or the fault row."""
    from defender._vocab import UNKNOWN_DISPOSITION
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105
    from defender.tests.support.learning.retrieval._lessons_corpus import trace_main
    from defender.tests.support.shared.contracts._by_path import load_trace_lesson
    from defender.tests.support.storage._alert_plant import plant_alert

    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data))
    H1105.tenant(data, H1105.T_ID)
    runs = data / H1105.T_ID / "runs"
    run_dir = runs / _run_id(plan)
    run_dir.mkdir(parents=True)
    plant_alert(run_dir)
    plant(run_dir, plan)
    (run_dir / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}) + "\n", encoding="utf-8")
    lessons = root / "lessons"
    lessons.mkdir()
    (lessons / "L.md").write_text("---\nname: L\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n", encoding="utf-8")
    capsys.readouterr()
    rc = trace_main(load_trace_lesson("trace_lesson"), ["L", "--lessons-dir", str(lessons), "--tenant", H1105.T_ID])
    out = capsys.readouterr()
    assert rc == 0, out.err
    rows = {line.split("\t")[0]: line for line in out.out.splitlines() if "\t" in line}
    row = rows[run_dir.name]
    word = row.split("\t")[1]
    slots = [out.out, out.err]
    if plan.kind == ANSWER_FAULT:
        return (ANSWER_FAULT, row), slots
    return ((ANSWER_NEVER, "") if word == UNKNOWN_DISPOSITION else (ANSWER_DISPOSITION, word)), slots


def held_out(root: Path, plan: Plan) -> tuple[tuple[str, str], list[str]]:
    """Held-out scoring of one case whose truth is the plan's disposition: `OK` is that disposition read; `WRONG` with its
    failure reason is anything else (a record that is not the truth is not planted here)."""
    from defender.tests.storage.ids_1187 import _spec1187 as S
    from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
    from evaluations import held_out as held
    from evaluations.tests import _frozen_cases as F

    slug = "agree-case"
    runs = root / "runs"
    fixtures = root / "fixtures"
    (fixtures / slug).mkdir(parents=True)
    (fixtures / slug / "alert.json").write_text('{"alert": "held-out"}\n', encoding="utf-8")
    (fixtures / slug / "ground_truth.yaml").write_text(f"held_out: true\ndisposition: {plan.disposition}\n", encoding="utf-8")
    F.make_cases(fixtures)
    run_dir = S.make_run(runs, _run_id(plan))
    plant(run_dir, plan)
    index = F.write_index(root / "ops" / "held-out-index.jsonl", F.row(fixtures, slug, run_dir.name))
    got = P.drive_cli(lambda argv: held.main(argv), [str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)])
    verdict = re.search(rf"^(OK|WRONG)\s+{slug}:", got.out, re.M)
    assert verdict, got.out + got.err
    bucket = got.out.partition("## Failure bucket")[2].partition("\n")[2]
    reason = next((line.partition(":")[2].strip() for line in bucket.splitlines() if line.strip().startswith(f"{slug}:")), "")
    slots = [got.out, got.err]
    if verdict.group(1) == "OK":
        return (ANSWER_DISPOSITION, plan.disposition), slots
    return ((ANSWER_FAULT, reason) if plan.kind == ANSWER_FAULT else (ANSWER_NEVER, "")), slots


def feedback(root: Path, plan: Plan) -> tuple[tuple[str, str], list[str]]:
    """The feedback outcome: the run's disposition word, or the tenant word `unreadable` for no record and every fault."""
    from defender.tests.learning.feedback_1414 import _spec1414 as S
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    run_dir = root / _run_id(plan)
    plant(run_dir, plan)
    word = S.run_outcome(fixture_run(run_dir), truncated_by=None, closed_before_cut=False)
    return ((ANSWER_UNREADABLE, "") if word == ANSWER_UNREADABLE else (ANSWER_DISPOSITION, word)), [word]


def worker(root: Path, plan: Plan) -> tuple[tuple[str, str], list[str]]:
    """The job lane's read (the worker's route: the database its pointer's case id derives): the lookup result, as its kind."""
    from defender.records import closing as C
    from defender.records import job_lane

    tenant = fixture_uuid("agree-tenant")
    runs = root / "data" / tenant / "runs"
    run_dir = runs / _run_id(plan)
    plant(run_dir, plan)
    (root / "data" / tenant / "sessions").mkdir(exist_ok=True)
    with job_lane.JobLane.open(root / "data", tenant) as lane:
        found = lane.closing_disposition(run_dir.name)
    if isinstance(found, C.Record):
        return (ANSWER_DISPOSITION, found.record.disposition), []
    if isinstance(found, C.NeverClosed):
        return (ANSWER_NEVER, ""), []
    return (ANSWER_FAULT, found.kind), []
