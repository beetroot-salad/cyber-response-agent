"""#1414 F1 support: the outcome words, the run plans that produce each, and the run-end tail that fills a run's memory.

Nothing here implements policy: a plan is a report and an exit class a run could end with, and the tail only plays the lifecycle's
part (it writes the run folder, fills the run state it is handed, scrubs, answers the summary).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender import _vocab
from defender.records import run_end
from defender.tests.support.sandbox._spec791 import SpecTail, populate_run_dir

#: Every outcome word of the setting (A5): each report disposition, each escalated exit, and `unreadable`.
VOCABULARY = sorted({*_vocab.DISPOSITION_VALUES, *run_end.ESCALATED_EXITS, "unreadable"})

#: Words the setting refuses: other exit classes (silent ones, forced-close ones), a made-up word, other spellings.
REFUSED_WORDS = ["escalated", "budget", "store", "request-limit", "provider-down", "Benign", "false_positive"]

UNPARSABLE = "this is no report, and has no front matter\n"


@dataclass(frozen=True)
class Plan:
    """How a run ends: its exit class and the report it leaves (`None`: none planted beyond the default)."""

    truncated_by: str | None
    disposition: str
    report: str | None = None


def plan_for(outcome: str) -> Plan:
    """A run whose outcome is `outcome`. An escalated run leaves a `benign` report behind: its word is the exit, never that."""
    if outcome in run_end.ESCALATED_EXITS:
        return Plan(truncated_by=outcome, disposition="benign")
    if outcome == "unreadable":
        return Plan(truncated_by=None, disposition="benign", report=UNPARSABLE)
    return Plan(truncated_by=None, disposition=outcome)


def lookup_row(lead: str, seq: int, params: dict, *, exit_code: int = 0, system: str = "tacit-knowledge",
               verb: str = "lookup") -> dict:
    """A query row with the real column set, as the run state holds it."""
    from defender.investigation.record_query import QUERY_ROW_COLUMNS

    row = dict.fromkeys(QUERY_ROW_COLUMNS)
    row.update(lead_id=lead, seq=seq, system=system, verb=verb, query_id=f"q-{lead}-{seq}", params=params,
               exit_code=exit_code)
    return row


class FeedbackTail(SpecTail):
    """`SpecTail` whose lifecycle ends the run as `plan` says, fills the run state `run.py` hands it, and runs `mid_run`.

    `rows` (lead -> rows) go into the `RunState` found among the lifecycle's keywords; `run_state` stays `None` when `run.py`
    hands none. `copy_text` is what the run's own settings copy held for `feedback.yaml` when the lifecycle began.
    `box_planted` is written over the box-writable `executed_queries.jsonl`."""

    def __init__(  # noqa: PLR0913 — one knob per way a test ends a run
            self, paths: Any, *, plan: Plan | None = None, rows: dict[str, list[dict]] | None = None,
                 box_planted: str | None = None, mid_run: Callable[[], None] | None = None,
                 raises: BaseException | None = None, teardown_faulted: bool = False,
                 certify: bool = True, setting_file: str = "feedback.yaml") -> None:
        plan = plan or Plan(truncated_by=None, disposition="inconclusive")
        super().__init__(paths, truncated_by=plan.truncated_by, certify=certify)
        self.plan = plan
        self.rows = rows or {}
        self.box_planted = box_planted
        self.mid_run = mid_run
        self.raises = raises
        self.teardown_faulted = teardown_faulted
        self.setting_file = setting_file
        self.run_state: Any = None
        self.copy_text: str | None = None

    def lifecycle(self, *, run: Any, **kw: Any) -> dict:
        from defender.box import _scrub as scrub_mod
        from defender.investigation.run_state import RunState

        run_dir = run.run_dir
        self.run_dirs.append(run_dir)
        copy = Path(kw["tenant"].settings) / self.setting_file
        self.copy_text = copy.read_text(encoding="utf-8") if copy.is_file() else None
        if self.raises is not None:
            raise self.raises
        populate_run_dir(run_dir, disposition=self.plan.disposition)
        if self.plan.report is not None:
            (run_dir / "report.md").write_text(self.plan.report, encoding="utf-8")
        if self.box_planted is not None:
            (run_dir / "executed_queries.jsonl").write_text(self.box_planted, encoding="utf-8")
        self.run_state = next((v for v in kw.values() if isinstance(v, RunState)), None)
        if self.run_state is not None:
            self.run_state.rows.update(self.rows)
        if self.mid_run is not None:
            self.mid_run()
        if self._certify:
            scrub_mod.scrub(run_dir)
        self._note("lifecycle", run_dir)
        summary = {"output": "feedback1414", "requests": 1, "truncated_by": self._truncated_by,
                   "closed_before_cut": self._closed_before_cut}
        if self.teardown_faulted:
            from defender.run import TEARDOWN_FAULTED

            summary[TEARDOWN_FAULTED] = True
        return summary


def box_row(row: dict) -> str:
    """One `executed_queries.jsonl` line."""
    return json.dumps(row) + "\n"
