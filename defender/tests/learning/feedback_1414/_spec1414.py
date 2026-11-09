"""#1414 sketch: every name the design leaves to the implementation, kept in this one module so a
rename touches one file. Each target is resolved at call time (collection never imports it).

Nothing here implements policy: the decide fake answers from a script and records calls; the
readers below read what the code under test wrote.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import importlib
import json
import re
from dataclasses import dataclass, field
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


def run_marker(run_id: str) -> str:
    """The marker a run's summary comment (and the issue body, for the first run) carries (A6; FC: its spelling)."""
    return f"<!-- defender-feedback-run:{run_id} -->"


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


def entry_problem(raw: Any) -> str | None:
    """A7's public per-entry validity check (FC: `tacit_registry.entry_problem(raw) -> str | None`:
    None for a loadable entry, else why not)."""
    return importlib.import_module("defender.systems.tacit_registry").entry_problem(raw)


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


def quarantined_requests(paths: Any, case_id: str) -> list[Path]:
    """Open-issue requests for `case_id` kept in a quarantine folder beneath the state root (A8: as the lead-author
    lane's `failed/`; FC: the folder's name holds `fail` or `quarantin`), apart from the live queue."""
    root = Path(location_path(paths.state_root))
    live = root / REQUEST_QUEUE
    found = []
    for p in sorted(root.rglob("*.json")):
        kept = str(p.relative_to(root)).lower()
        if p.parent != live and ("fail" in kept or "quarantin" in kept):
            try:
                if json.loads(p.read_text(encoding="utf-8")).get("case_id") == case_id:
                    found.append(p)
            except (ValueError, AttributeError):
                continue
    return found


def feedback_drain(t: Any, paths: Any, *, decide: Any, **seams: Any) -> int:
    """The feedback tick (FC: `drains.feedback_drain`, seam `decide=`) through the CLI's stage
    runner, over the tenant's forge fake and a fresh issuer-fake identity."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drains, run_stage

    seams.setdefault("client", t.forge.client)
    seams.setdefault("directory", t.directory)
    seams.setdefault("identity", t.vault.identity())
    return run_stage(lambda: drains().feedback_drain(paths, decide=decide, **seams))


def lessons_rows(paths: Any) -> list[dict]:
    """The lessons author's pending feedback-channel rows (D11)."""
    from defender.learning.core import state
    from defender.tests.support.learning.curation._drain719 import pending

    return pending(paths, getattr(state, FEEDBACK_LESSONS_CHANNEL))


def lessons_queue_file(paths: Any) -> Path:
    """The feedback channel's queue file, for a test that loses a row the way a crash would."""
    from defender.learning.core import state

    return Path(location_path(paths.state_root)) / getattr(state, FEEDBACK_LESSONS_CHANNEL).queue


class Decider:
    """The tick's `decide` seam (FC: `decide(item, *, box=None) -> answer`). The item carries (FC):
    `comment_id`, `issue`, `author`, `body`, `case_id`, `run_id` and `outcome` (the framing run's, A6/A3),
    and `lookups` (that run's captured lookups, indexed by position). It answers each comment from `script`
    by comment id: a dict every time, or a list consumed one per attempt (the last repeats); an `Exception`
    value is raised. It records the items it was handed."""

    def __init__(self, script: dict[int, Any] | None = None) -> None:
        self.script = dict(script or {})
        self.items: list[dict] = []

    def __call__(self, item: Any, *, box: Any = None, **_kw: Any) -> Any:
        self.items.append(dict(item))
        cid = int(item["comment_id"])
        got = self.script.get(cid, answer(reason="script: nothing"))
        if isinstance(got, list):
            got = got[min(self.decided.count(cid) - 1, len(got) - 1)]
        if isinstance(got, Exception):
            raise got
        return got

    @property
    def decided(self) -> list[int]:
        return [int(i["comment_id"]) for i in self.items]

    def item(self, comment_id: int) -> dict:
        return [i for i in self.items if int(i["comment_id"]) == comment_id][-1]


# ---------------------------------------------------------------- the tick's scene

#: A lookup a run made: what a drafted entry copies (P3).
LOOKUP = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "pg_dump --all as root"}
LOOKUP_2 = {"actor": "svc-backup", "host": "db-07.prod", "pattern": "read /etc/pgpass"}
#: Two eligible people (the service's record, D13); `mallory` is on no record (the forge's own rule names her: a decoy).
OWNER, NAMED, OUTSIDER = "ann", "bea", "mallory"


@dataclass
class Feedback:
    """One published tenant's feedback scene: its runs, its queued requests, its ticks, and what its forge shows."""

    t: Any
    paths: Any
    bot: str
    tmp: Path
    runs_made: int = 0
    #: case id -> the run ids its requests carried, in order (what the host may write on an issue's head).
    run_ids: dict = field(default_factory=dict)

    def eligible(self, *logins: str, age: dt.timedelta = dt.timedelta(0)) -> None:
        """What the lifecycle service wrote to the tenant's row (D13): `logins` read `age` ago.
        """
        repo = self.t.repository
        asyncio.run(repo.record_merge_eligibility(
            self.t.tenant_id, logins=frozenset(logins), read_at=dt.datetime.now(dt.UTC) - age))

    def at(self, seconds: float) -> str:
        """Forgejo's timestamp `seconds` from now (negative: the past), whole seconds."""
        when = dt.datetime.now(dt.UTC).replace(microsecond=0) + dt.timedelta(seconds=seconds)
        return when.isoformat().replace("+00:00", "Z")

    def requests_to(self, *fragments: str) -> list[str]:
        """The forge requests made so far whose path holds any fragment, as `METHOD path`."""
        return [f"{r.method} {r.url.path}" for r in self.forge.requests
                if any(f in r.url.path.lower() for f in fragments)]

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
        run_id = str(run_of(run_dir).id)
        self.run_ids.setdefault(case_id, []).append(run_id)
        queue_open_issue(self.paths, case_id=case_id, tenant_id=self.t.tenant_id,
                         run_id=run_id, outcome="inconclusive", lookups=[LOOKUP] if lookups is None else lookups)
        return run_dir

    def tick(self, decide: Any, **seams: Any) -> int:
        return feedback_drain(self.t, self.paths, decide=decide, **seams)

    def issues(self, case_id: str) -> list[dict]:
        """The feedback issues whose host-written head (the body's first two lines) names exactly `case_id` or one of
        the run ids its requests carried (`case-1` is not `case-10`). Which of the two the head names is the
        implementation's; the tests that pin the head (one issue per run, recovery) assert it themselves."""
        names = [case_id, *self.run_ids.get(case_id, [])]
        named = re.compile("|".join(rf"(?<![\w-]){re.escape(n)}(?![\w-])" for n in names))
        return [i for i in self.forge.issues
                if FEEDBACK_LABEL in {label["name"] for label in i["labels"]}
                and named.search("\n".join(i["body"].splitlines()[:2]))]

    def opened(self, case_id: str, decide: Any = None) -> int:
        """Queue a request for `case_id`, tick once, and return the number of the one issue that tick created (read
        from the forge's own record, not from any text the host wrote)."""
        before = {i["number"] for i in self.forge.issues}
        self.request(case_id)
        assert self.tick(decide or Decider()) == 0
        [number] = [i["number"] for i in self.forge.issues if i["number"] not in before]
        return number

    def replies(self, number: int, comment_id: int) -> list[dict]:
        """The bot's replies to `comment_id`: bot comments whose first line carries its marker (ruling 2026-11-09: a
        marker is read only from the first line of a comment a tenant bot wrote)."""
        return [c for c in self.forge.comments_on(number, by=self.bot)
                if marker(comment_id) in (c["body"].splitlines() or [""])[0]]


def run_id_of(run_dir: Path) -> str:
    """The id a request carries for the run folder `Feedback.request` returned."""
    from defender.tests.support.learning.core._state1135 import run_of

    return str(run_of(run_dir).id)


def today() -> dt.date:
    return dt.datetime.now(dt.UTC).date()


# ---------------------------------------------------------------- r5 shared names (orchestrator-owned)
# Fixed by the orchestrator before the thorough pass so the four slices agree. A slice that needs a
# change asks the orchestrator; it does not edit this block.

#: D13: the tenant row's eligibility record, written by the lifecycle service on every pass and read
#: by the feedback tick. FC names:
#:   `await TenantRepository.record_merge_eligibility(tenant_id, *, logins: frozenset[str], read_at: datetime)`
#:   `await TenantRepository.merge_eligibility(tenant_id) -> MergeEligibility | None`
#:   `TenantDirectory.merge_eligibility(tenant_id) -> MergeEligibility | None`
#: with `MergeEligibility(logins: frozenset[str], read_at: datetime)` exported from `defender.tenancy`.
#: Bot logins are the tenant's generations' `bot_login` (already on the row).
ELIGIBILITY_RECORD = "merge_eligibility"

#: D13: the tick's staleness bound. FC: `feedback_drain(..., eligibility_max_age=timedelta)`; default
#: from env `LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE` (seconds), default 60 (human ruling 2026-11-09).
ELIGIBILITY_MAX_AGE_ENV = "LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE"

#: D11: the lessons author's feedback channel. FC: `defender.learning.core.state.FEEDBACK_LESSONS`
#: (a `Channel`), one row per comment keyed by `comment_id`:
#:   {"comment_id": str, "issue": int, "author": str, "case_id": str, "instruction": str}
#: `comment_id` is the Forgejo comment id as a decimal STRING: the curator queues dedup and retire
#: by string id (`LearningState.append(dedup_key=)`, `retire_rows`). Wakes on any one row (no knob).
#: Module `defender.learning.author.feedback.run` (curator key "feedback_curator"); a feedback lesson
#: cites the comment id under `source_finding_ids`.
FEEDBACK_LESSONS_CHANNEL = "FEEDBACK_LESSONS"


def feedback_lesson_row(*, comment_id: int, issue: int, author: str, case_id: str, instruction: str) -> dict:
    """One D11 feedback-channel row, as the tick writes it and the lessons author reads it."""
    return {"comment_id": str(comment_id), "issue": issue, "author": author, "case_id": case_id,
            "instruction": instruction}
