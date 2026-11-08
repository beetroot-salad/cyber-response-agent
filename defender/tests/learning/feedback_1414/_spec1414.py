"""#1414 sketch: every name the design leaves to the implementation, kept in this one module so a
rename touches one file. Each target is resolved at call time (collection never imports it).

Nothing here implements policy: the decide fake answers from a script and records calls; the
readers below read what the code under test wrote.
"""
from __future__ import annotations

import datetime as dt
import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path

# ---------------------------------------------------------------- forced names (see the report)

#: The label the bot puts on every feedback issue (FC: the design names no label).
FEEDBACK_LABEL = "defender-feedback"
#: The tenant's feedback setting, under `settings/` (FC: file name and shape).
SETTING_FILE = "feedback.yaml"
#: Run end's open-issue requests, one file per case, beside `author-queue/` (FC).
REQUEST_QUEUE = "feedback-issue-queue"
#: The registry lane's branch prefix, the third value of the lane-prefix choice (FC).
FEEDBACK_PREFIX = "feedback/"
#: The registry file in the tenant repo (design: the lane admits exactly this path).
REGISTRY = "agent/skills/tacit-knowledge/registry.yaml"


def setting_text(outcomes: list[str]) -> str:
    """The feedback setting listing `outcomes` (FC: a top-level `open_issue_on:` list)."""
    return "open_issue_on:\n" + "".join(f"  - {o}\n" for o in outcomes)


def marker(comment_id: int) -> str:
    """The marker a reply carries naming the comment it answers (FC: its spelling)."""
    return f"<!-- defender-feedback-reply:{comment_id} -->"


def entry_id(issue: int, comment: int, n: int = 1) -> str:
    """The design's entry id `fb-<issue>-<comment>-<n>` (O6). Whether `n` starts at 1 is FC."""
    return f"fb-{issue}-{comment}-{n}"


def answer(*, approve: tuple[int, ...] = (), review_by: str | None = None,
           instruction: str | None = None, reason: str | None = None) -> dict:
    """The model's answer for one comment (FC: its schema): lookup indices it approves, an earlier
    review date the comment names, instruction text, or nothing with a reason."""
    return {"approve": list(approve), "review_by": review_by, "instruction": instruction,
            "reason": reason}


# ---------------------------------------------------------------- targets, resolved at call time

def run_common() -> Any:
    return importlib.import_module("defender.run_common")


def enqueue_feedback_issue(run: Any, alert: Path | None, **kw: Any) -> bool:
    """F1's enqueue beside `enqueue_curation` (FC: `run_common.enqueue_feedback_issue`, keywords
    `tenant=`, `truncated_by=`, `closed_before_cut=`, `run_state=`, `fixtures_dir=`)."""
    return run_common().enqueue_feedback_issue(run, alert, **kw)


def run_outcome(run: Any, *, truncated_by: str | None, closed_before_cut: bool) -> str:
    """The one outcome function shared with the ticket's comment body (FC: name and home)."""
    return importlib.import_module("defender.investigation.ticket_writer").run_outcome(
        run, truncated_by=truncated_by, closed_before_cut=closed_before_cut)


def captured_lookups(state: Any) -> list[dict]:
    """The successful string-valued `tacit-knowledge` lookups in a run's in-memory state (FC:
    `record_query.captured_lookups`, rows as `{actor, host, pattern}`)."""
    return importlib.import_module("defender.investigation.record_query").captured_lookups(state)


def feedback_setting_findings(knowledge: Path) -> list[str]:
    """`tenant check`'s findings over the feedback setting (FC: `cli.tenant._feedback_findings`)."""
    return importlib.import_module("defender.cli.tenant")._feedback_findings(knowledge)


def queue_open_issue(paths: Any, *, case_id: str, tenant_id: str, run_id: str, outcome: str,
                     lookups: list[dict]) -> None:
    """File an open-issue request as run end does (FC: `LearningState.enqueue_feedback_issue`)."""
    from defender.learning.core.state import LearningState

    with LearningState.open(paths) as state:
        state.enqueue_feedback_issue(case_id, {
            "case_id": case_id, "tenant_id": tenant_id, "run_id": run_id, "outcome": outcome,
            "lookups": lookups})


def open_issue_requests(paths: Any) -> dict[str, dict]:
    """Run end's queued open-issue requests, by file name."""
    q = Path(location_path(paths.state_root)) / REQUEST_QUEUE
    return ({p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(q.glob("*.json"))}
            if q.is_dir() else {})


def feedback_drain(t: Any, paths: Any, *, decide: Any, **seams: Any) -> int:
    """The feedback tick (FC: `drains.feedback_drain`, seam `decide=`) through the CLI's stage
    runner, over the tenant's forge fake and a fresh issuer-fake identity."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drains, run_stage

    seams.setdefault("client", t.forge.client)
    seams.setdefault("directory", t.directory)
    seams.setdefault("identity", t.vault.identity())
    return run_stage(lambda: drains().feedback_drain(paths, decide=decide, **seams))


def lessons_rows(paths: Any) -> list[dict]:
    """The lessons author's pending finding rows (D8: feedback rows go there)."""
    from defender.learning.core.state import FINDINGS
    from defender.tests.support.learning.curation._drain719 import pending

    return pending(paths, FINDINGS)


class Decider:
    """The tick's `decide` seam (FC: `decide(item, *, box=None) -> answer`, `item["comment_id"]`):
    answers each comment from `script` by comment id, and records the items it was handed."""

    def __init__(self, script: dict[int, dict] | None = None) -> None:
        self.script = dict(script or {})
        self.items: list[dict] = []

    def __call__(self, item: Any, *, box: Any = None, **_kw: Any) -> dict:
        self.items.append(dict(item))
        return self.script.get(int(item["comment_id"]), answer(reason="script: nothing"))

    @property
    def decided(self) -> list[int]:
        return [int(i["comment_id"]) for i in self.items]


# ---------------------------------------------------------------- the tick's scene

#: A lookup a run made: what a drafted entry copies (P3).
LOOKUP = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "pg_dump --all as root"}
LOOKUP_2 = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "read /etc/pgpass"}
#: The merge whitelist: `ann` through the Owners team, `bea` by name; `mallory` is on neither.
OWNER, NAMED, OUTSIDER = "ann", "bea", "mallory"


@dataclass
class Feedback:
    """One published tenant's feedback scene: its runs, its queued requests, its ticks, and what its forge shows."""

    t: Any
    paths: Any
    bot: str
    tmp: Path
    runs_made: int = 0

    @property
    def forge(self) -> Any:
        return self.t.forge

    def run(self, label: str) -> Path:
        """A finished run of the tenant under its runs folder (what a request's address opens)."""
        from defender.tests.support.sandbox._spec791 import make_run_dir
        from defender.tests.support.shared._fixture_uuid import fixture_uuid

        runs = Path(location_path(self.t.tenant.tenant_root)) / "runs"
        runs.mkdir(exist_ok=True)
        return make_run_dir(runs, name=fixture_uuid(label), disposition="inconclusive")

    def request(self, case_id: str, *, lookups: list[dict] | None = None, label: str | None = None) -> Path:
        from defender.tests.support.learning.core._state1135 import run_of

        self.runs_made += 1
        run_dir = self.run(label or f"{case_id}-{self.runs_made}")
        queue_open_issue(self.paths, case_id=case_id, tenant_id=self.t.tenant_id,
                         run_id=str(run_of(run_dir).id), outcome="inconclusive", lookups=[LOOKUP] if lookups is None else lookups)
        return run_dir

    def tick(self, decide: Any, **seams: Any) -> int:
        return feedback_drain(self.t, self.paths, decide=decide, **seams)

    def issues(self, case_id: str) -> list[dict]:
        """The feedback issues whose host-written first line names `case_id`."""
        return [i for i in self.forge.issues
                if FEEDBACK_LABEL in {label["name"] for label in i["labels"]}
                and case_id in (i["body"].splitlines() or [""])[0]]

    def opened(self, case_id: str, decide: Any = None) -> int:
        """Queue a request for `case_id`, tick once, and return its issue's number."""
        self.request(case_id)
        assert self.tick(decide or Decider()) == 0
        [issue] = self.issues(case_id)
        return issue["number"]

    def replies(self, number: int, comment_id: int) -> list[dict]:
        return [c for c in self.forge.comments_on(number, by=self.bot) if marker(comment_id) in c["body"]]


def today() -> dt.date:
    return dt.datetime.now(dt.UTC).date()
