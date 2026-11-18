"""#1534 reader agreement (no tests): one planted run per plan, read by one reader through its own entry, answered in one
shape. Production names are imported inside functions.

An answer is `("disposition", d)`, `("never", "")`, `("fault", <the reader's outward text>)` or, for the feedback outcome whose
tenant word cannot tell the three apart, `("unreadable", "")`. `Read.slots` is every outward text the reader produced (its
stdout, comment, receipt, page, failure chain or refusal); `Read.run` is the planted run's handle, for the test's own lookup."""
from __future__ import annotations

import ast
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.storage import _readers1534 as R

ANSWER_DISPOSITION, ANSWER_NEVER, ANSWER_FAULT, ANSWER_UNREADABLE = "disposition", "never", "fault", "unreadable"

#: Every reader that holds a run through a run handle (V-READERS' run-handle row), and the worker's job-lane read.
READERS = ("ticket", "page", "trace", "held_out", "feedback", "worker", "questioner")

#: Kinds a run-handle reader cannot meet (they belong to the episode view's route).
EPISODE_ONLY = ("roster-gone", "arm-refused")

#: The lookup kinds a run handle can meet, as plantable faults (`R.LEGACY_LINK` among them); the test checks this against
#: `FAULT_KINDS` by membership.
FAULTS = ("database-missing", "pointer-unreadable", "store-unreadable", "schema-version", "recorded-before-1534",
          "legacy-link", "row-invalid")

#: Per reader, the plans another read of the reader refuses although the lookup answers: the run page refuses a folder
#: with no pointer before a page exists (design, Lookup's accepted residuals). The reader must still refuse (a fault, never a
#: record or an absence), in that other read's wording.
REFUSED_BEFORE = {"page": (R.NO_POINTER,),
                  # A branch is taken from the source's session store: a source with none is refused as today (V-READERS).
                  "questioner": (R.NO_POINTER,)}

#: Readers with a log of their own (not a CLI, whose log is its stderr, an outward slot): a fault's detail must reach it.
LOGGED = ("ticket", "page")

#: A committed disposition and a different drafted one: a forced-inconclusive close (the host overrode the model's draft).
DRAFTED = "malicious"


@dataclass(frozen=True)
class Plan:
    """What one planted run holds: a record (`disposition`, `extra` over its valid fields), a store with no row
    (`closed=False`), or a fault (`fault`, a `_readers1534` fault; `NO_POINTER` and `LEGACY_LINK` among them). `invalid_as` is
    what a `row-invalid` leaves in the column; `at_query` makes `store-unreadable` a VIEW over a missing table (the file opens,
    the ledger reads, the record's query errors)."""

    label: str
    disposition: str = "benign"
    extra: dict[str, Any] = field(default_factory=dict)
    closed: bool = True
    fault: str | None = None
    invalid_as: str | None = None
    at_query: bool = False

    @property
    def kind(self) -> str:
        """The lookup outcome this plan means."""
        if self.fault == R.NO_POINTER or (self.fault is None and not self.closed):
            return ANSWER_NEVER
        return ANSWER_FAULT if self.fault else ANSWER_DISPOSITION

    def fields(self) -> dict | None:
        return {**R.valid_fields(self.disposition), **self.extra} if self.closed else None


def plan_labels() -> list[str]:
    """Every plan's label, for parametrizing at collection (no production name imported)."""
    from defender._vocab import DISPOSITION_VALUES

    return ([f"is-{d}" for d in DISPOSITION_VALUES] + ["forced-inconclusive", "never-no-row", "never-no-pointer"]
            + [f"fault-{k}" for k in FAULTS] + ["fault-store-unreadable-at-query"])


def plan(label: str) -> Plan:
    """The plan `label` names (`plan_labels`)."""
    from defender.records import closing as C

    if label == "forced-inconclusive":
        return Plan(label, disposition="unresolved", extra={
            "outcome": C.FORCED_INCONCLUSIVE, "cause": C.CAUSE_REVIEW_INCOMPLETE, "failure_kind": C.TIMEOUT,
            "drafted_disposition": DRAFTED})
    if label == "never-no-row":
        return Plan(label, closed=False)
    if label == "never-no-pointer":
        return Plan(label, fault=R.NO_POINTER)
    if label == "fault-store-unreadable-at-query":
        return Plan(label, fault="store-unreadable", at_query=True)
    if label.startswith("fault-"):
        kind = label.removeprefix("fault-")
        return Plan(label, fault=R.LEGACY_LINK if kind == "legacy-link" else kind)
    return Plan(label, disposition=label.removeprefix("is-"))


def refused_before(reader: str, plan: Plan) -> bool:
    """Does another read of `reader` refuse `plan` before its lookup's slot? (`REFUSED_BEFORE`)"""
    return plan.fault in REFUSED_BEFORE.get(reader, ())


@dataclass
class Read:
    answer: tuple[str, str]
    slots: list[str]
    run: Any
    #: The lookup taken after the plant and before the reader ran, for a reader whose run writes the store (else None: the
    #: test looks the run up itself).
    found: Any = None


def read(reader: str, root: Path, plan: Plan, monkeypatch, capsys) -> Read:
    """`reader`'s answer for a run planted by `plan` under `root`, with a case id (so a database) of this leg's own."""
    root.mkdir(parents=True, exist_ok=True)
    case = f"{R.DETAIL_MARK}-{reader}-{plan.label}-{uuid.uuid4().hex[:8]}".lower().replace("_", "-")
    legs = {"ticket": ticket, "page": page, "trace": trace, "held_out": held_out, "feedback": feedback,
            "worker": worker, "questioner": questioner}
    return legs[reader](root, plan, case=case, run_id=fixture_uuid(f"agree-{reader}-{plan.label}"),
                        monkeypatch=monkeypatch, capsys=capsys)


def plant(run_dir: Path, plan: Plan, case: str) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    R.plant_run(run_dir, plan.fields(), fault=plan.fault, invalid_as=plan.invalid_as, case_id=case, at_query=plan.at_query)


def fault_kinds_named(text: str) -> frozenset[str]:
    """The lookup kinds whose fixed wording `text` carries: a fault answer compared across runs whose ids differ."""
    from defender.records import closing as C

    return frozenset(k for k, w in C.FAULT_WORDING.items() if w in text)


# --- the readers --------------------------------------------------------------------------------------

def ticket(root: Path, plan: Plan, *, case: str, run_id: str, **_: Any) -> Read:
    """The record leg: the head of the posted comment, or no comment and the error receipt's reason."""
    from defender.tests.support.runtime.engine._spec767 import ALERT, ALERT_MAPPING, FakeStore, receipt, record
    from defender.tests.support.shared.contracts._spec1077 import fixture_run
    from defender.tests.support.storage._alert_plant import plant_alert

    run_dir = root / "runs" / run_id
    plant(run_dir, plan, case)
    plant_alert(run_dir, ALERT, mapping=ALERT_MAPPING)
    store = FakeStore(root / "store")
    record(run_dir, store)
    run = fixture_run(run_dir)
    if store.calls:
        body = store.comment_body()
        if "No disposition was recorded" in body:
            return Read((ANSWER_NEVER, ""), [body], run)
        return Read((ANSWER_DISPOSITION, body.split(" — ", 1)[0]), [body], run)
    reason = receipt(run_dir)["reason"] or ""
    return Read((ANSWER_FAULT, reason), [json.dumps(receipt(run_dir))], run)


def page(root: Path, plan: Plan, *, case: str, run_id: str, monkeypatch, **_: Any) -> Read:
    """The run page through the post-run step's save: the headline's disposition badge, or the failure chain. The ledger is
    sealed before the fault is applied, as a run that ended cleanly leaves it."""
    from defender._vocab import UNKNOWN_DISPOSITION
    from defender.presentation.visualize_run import VisualizeFailed, save_page
    from defender.tests.support.presentation import _page1534 as P
    from defender.tests.support.shared._locations_1210 import fixture_runs_base
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    del run_id  # the page builder names its own run
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root / "state"))
    run_dir = P._build_run(root, plan.fields(), record=plan.closed, case_id=case)
    P.seal_at(fixture_runs_base(run_dir.parent), case, run_dir.name)
    P._SEALED.add(run_dir)
    R.fault_run(run_dir, plan.fault, invalid_as=plan.invalid_as, at_query=plan.at_query)
    run = fixture_run(run_dir)
    try:
        html = save_page(run)
    except VisualizeFailed as failed:
        link = failed
    else:
        badge = re.search(r"disp-badge disp-([^\s\"']+)", html)
        shown = badge.group(1) if badge else ""
        return Read((ANSWER_NEVER, "") if shown == UNKNOWN_DISPOSITION else (ANSWER_DISPOSITION, shown), [html], run)
    chain = []
    while link is not None:
        chain.append(str(link))
        link = link.__cause__ or link.__context__
    text = " | ".join(chain)
    return Read((ANSWER_FAULT, text), [text], run)


def trace(root: Path, plan: Plan, *, case: str, run_id: str, monkeypatch, capsys, **_: Any) -> Read:
    """The trace CLI's row for the run: its disposition column, the unknown mark, or the fault row less its run-id column."""
    from defender._vocab import UNKNOWN_DISPOSITION
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105
    from defender.tests.support.learning.retrieval._lessons_corpus import trace_main
    from defender.tests.support.shared.contracts._by_path import load_trace_lesson
    from defender.tests.support.shared.contracts._spec1077 import fixture_run
    from defender.tests.support.storage._alert_plant import plant_alert

    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data))
    H1105.tenant(data, H1105.T_ID)
    run_dir = data / H1105.T_ID / "runs" / run_id
    run_dir.mkdir(parents=True)
    plant_alert(run_dir)
    plant(run_dir, plan, case)
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
    columns = rows[run_dir.name].split("\t")
    slots, run = [out.out, out.err], fixture_run(run_dir)
    word = columns[1]
    if word == UNKNOWN_DISPOSITION:
        return Read((ANSWER_NEVER, ""), slots, run)
    from defender._vocab import DISPOSITION_VALUES

    if word in DISPOSITION_VALUES:
        return Read((ANSWER_DISPOSITION, word), slots, run)
    return Read((ANSWER_FAULT, "\t".join(columns[1:])), slots, run)


def held_out(root: Path, plan: Plan, *, case: str, run_id: str, **_: Any) -> Read:
    """Held-out scoring of one indexed case: the run's `predicted=` disposition, or (none predicted) the failure bucket's
    reason, an absence when it is the scorer's no-record reason. The truth label is the plan's disposition where it is a
    label a fixture may carry, else another one (a host-only disposition is never a right answer)."""
    from defender.records import Run
    from defender.tests.storage.ids_1187 import _spec1187 as S
    from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
    from defender.tests.support.shared._locations_1210 import fixture_runs_base
    from evaluations import held_out as held
    from evaluations.tests import _frozen_cases as F

    slug = "agree-case"
    runs = root / "runs"
    fixtures = root / "fixtures"
    truth = plan.disposition if plan.disposition in held.LABELS else sorted(held.LABELS)[0]
    (fixtures / slug).mkdir(parents=True)
    (fixtures / slug / "alert.json").write_text('{"alert": "held-out"}\n', encoding="utf-8")
    (fixtures / slug / "ground_truth.yaml").write_text(f"held_out: true\ndisposition: {truth}\n", encoding="utf-8")
    F.make_cases(fixtures)
    run_dir = S.make_run(runs, run_id)
    plant(run_dir, plan, case)
    index = F.write_index(root / "ops" / "held-out-index.jsonl", F.row(fixtures, slug, run_dir.name))
    got = P.drive_cli(lambda argv: held.main(argv), [str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)])
    slots, run = [got.out, got.err], Run.under(fixture_runs_base(runs), run_dir.name)
    scored = re.search(rf"^\s*(?:OK|WRONG)\s+{slug}: predicted=(\S+)", got.out, re.M)
    assert scored, got.out + got.err
    predicted = ast.literal_eval(scored.group(1))
    if predicted is not None:
        return Read((ANSWER_DISPOSITION, predicted), slots, run)
    bucket = got.out.partition("## Failure bucket")[2].partition("\n")[2]
    reason = next((line.partition(":")[2].strip() for line in bucket.splitlines() if line.strip().startswith(f"{slug}:")), "")
    return Read((ANSWER_NEVER, "") if reason == held.NO_CLOSING_RECORD else (ANSWER_FAULT, reason), slots, run)


def feedback(root: Path, plan: Plan, *, case: str, run_id: str, **_: Any) -> Read:
    """The feedback outcome: the run's disposition word, or the tenant word `unreadable` for no record and every fault."""
    from defender.tests.learning.feedback_1414 import _spec1414 as S
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    run_dir = root / "runs" / run_id
    plant(run_dir, plan, case)
    run = fixture_run(run_dir)
    word = S.run_outcome(run, truncated_by=None, closed_before_cut=False)
    return Read((ANSWER_UNREADABLE, "") if word == ANSWER_UNREADABLE else (ANSWER_DISPOSITION, word), [word], run)


def worker(root: Path, plan: Plan, *, case: str, run_id: str, **_: Any) -> Read:
    """The job lane's read (the worker's route: the database its pointer's case id derives): the lookup result, as its kind."""
    from defender.records import closing as C
    from defender.records import job_lane
    from defender.tenancy import data_root_from_path
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    tenant = fixture_uuid("agree-tenant")
    run_dir = root / "data" / tenant / "runs" / run_id
    plant(run_dir, plan, case)
    (root / "data" / tenant / "sessions").mkdir(exist_ok=True)
    with job_lane.JobLane.open(data_root_from_path(root / "data"), tenant) as lane:
        found = lane.closing_disposition(run_dir.name)
    run = fixture_run(run_dir)
    if isinstance(found, C.Record):
        return Read((ANSWER_DISPOSITION, found.record.disposition), [], run)
    if isinstance(found, C.NeverClosed):
        return Read((ANSWER_NEVER, ""), [], run)
    return Read((ANSWER_FAULT, found.kind), [], run)


#: The questioner leg's source run's captured calls, each answered the same by the live estate (`_spec1224`'s fixture tenant).
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1", "ts": "2026-07-28T15:00:00Z"}]}


class _LooksUpFirst:
    """The estate's directory, made on first use, which takes the source's lookup then: after the source is planted, before
    the launch reads it (the launch's writer open of the source's store can change what the lookup finds)."""

    def __init__(self, make: Any, look: Any) -> None:
        self._make, self._look, self._inner, self.found = make, look, None, None

    def __getattr__(self, name: str) -> Any:
        if self._inner is None:
            self.found, self._inner = self._look(), self._make()
        return getattr(self._inner, name)


def questioner(root: Path, plan: Plan, *, monkeypatch, **_: Any) -> Read:
    """A branch launch over the planted source, its questioner silent on world A's disposition: world A's declared
    disposition (from the family written, or from the refusal of a value no world may declare), an absence when the family
    was refused for lacking that field, else the refusal. The data root is this leg's own (the source's id is fixed)."""
    import yaml

    from defender.tests.support.shared.contracts._data_root_1078 import DATA_ROOT_ENV

    from defender.tests.learning.oracle.live_contracts import _spec1224 as S
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    monkeypatch.setenv(DATA_ROOT_ENV, str(root / "data-root"))
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(root / "defender-runs"))
    doc = S.family_v2()
    doc["worlds"][0].pop("disposition_declared")
    agent = S.questioner_for(doc)
    calls = [S.Call("idp", "query", S.query_params("user:alice"), _BASE),
             S.Call("edr", "query", S.query_params("host:db-1"), _BASE)]
    from defender.records import closing as C

    fault = None if plan.fault is None else {"fault": plan.fault, "invalid_as": plan.invalid_as, "at_query": plan.at_query}

    def source() -> Path:
        return next(Path(os.environ["DEFENDER_DATA_ROOT"]).glob(f"*/runs/{T.SOURCE_RUN_ID}"))

    est = S.estate(root)
    directory = _LooksUpFirst(lambda: est.directory(tenant_id=S.FIXTURE_TENANT), lambda: C.for_run(fixture_run(source())))
    got = S.launch(root, est, calls=calls, questioner=agent, source_closing=plan.fields(), source_fault=fault,
                   directory=directory, oracle=S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)), verifier=S.passing_verifier())
    slots, run = [got.message], fixture_run(source())
    family = got.ep / "family.yaml"
    if family.is_file():
        worlds = yaml.safe_load(family.read_text(encoding="utf-8"))["worlds"]
        declared = next(w for w in worlds if w.get("role") == "A")["disposition_declared"]
        return Read((ANSWER_DISPOSITION, declared), slots, run, directory.found)
    refused = re.search(r"\.disposition_declared is '([^']+)'", got.message)
    if refused:
        return Read((ANSWER_DISPOSITION, refused.group(1)), slots, run, directory.found)
    if "disposition_declared" in got.message:
        return Read((ANSWER_NEVER, ""), slots, run, directory.found)
    assert got.rc != 0, (got.rc, got.message)
    assert agent.calls == 0, "the questioner was called although the launch was refused for the source's record"
    return Read((ANSWER_FAULT, got.message), slots, run, directory.found)
