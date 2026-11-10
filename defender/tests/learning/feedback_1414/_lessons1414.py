"""#1414 D11 support: the lessons author's feedback channel, driven through the existing drain seams.

Nothing here implements policy. `FeedbackCurator` is `FakeCurator` keyed on `comment_id`; `FeedbackTrigger`
is `CuratorTrigger` that also serves the feedback curator; `feedback_scene` is `build_*_draft_scene` for it.
Every target is resolved at call time, so collection never imports code that does not exist yet.

Forced names (FC, owned here, not in the shared r5 block; reported to the orchestrator):
  - module `defender.learning.author.feedback.run`: `build_feedback_config(paths, *, state, trees,
    manifest_seed=None, box=None, batch=None)`, `build_feedback_user_prompt(rows, batch_id, cfg, *, salt=None)`,
    `run_batch(hold_committed=, cfg=, box=)`; drain module key `FEEDBACK_MODULE` in `_CURATOR_MODULES`.
  - a feedback lesson cites its comment id (as a string) under `source_finding_ids`, like any lesson.
"""
from __future__ import annotations

import dataclasses
import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.tests.learning.feedback_1414._spec1414 import feedback_lesson_row
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    AUTHOR_DRAFT_LANES,
    CuratorTrigger,
    draft_lane_trees,
)

FEEDBACK_MODULE = "feedback_curator"
FEEDBACK_RUN = "defender.learning.author.feedback.run"
FEEDBACK_LESSON_NAME = "p4-feedback-lesson.md"
FEEDBACK_LESSON_PATH = f"agent/lessons/{FEEDBACK_LESSON_NAME}"

SALT = "7e" * 16
FRAME_RE = re.compile(r"<run-(?P<salt>[0-9a-f]+)-(?P<tag>[^>\n]+)>\n(?P<body>.*?)\n</run-(?P=salt)-(?P=tag)>",
                      re.DOTALL)


def channel() -> Any:
    """The feedback channel (`FEEDBACK_LESSONS`), resolved now."""
    return importlib.import_module("defender.learning.core.state").FEEDBACK_LESSONS


def row(comment_id: int = 101, **over: Any) -> dict:
    """One channel row as the tick writes it (shared shape)."""
    kw = {"comment_id": comment_id, "issue": 7, "author": "ann", "case_id": "case-7",
          "instruction": "check the VPN log first for this user"}
    kw.update(over)
    return feedback_lesson_row(**kw)


def lesson(comment_id: int, body: str = "check the VPN log first") -> str:
    """A lesson the feedback curator authored: cites its comment id like any lesson cites its source row."""
    return S.lesson(str(comment_id), body=body)


@dataclass
class FeedbackCurator(S.FakeCurator):
    """`FakeCurator` whose self-report names the rows' comment ids (as strings) unless told otherwise."""

    def __call__(self, rows: list[dict], batch_id: str, cfg: Any) -> dict:
        saved = self.committed
        self.committed = saved if saved is not None else [str(r["comment_id"]) for r in rows]
        try:
            return super().__call__(rows, batch_id, cfg)
        finally:
            self.committed = saved

    def comment_ids(self) -> list[list[str]]:
        """The comment ids each call was handed."""
        return [[r["comment_id"] for r in c["rows"]] for c in self.calls]


class FeedbackTrigger(CuratorTrigger):
    """`CuratorTrigger` that also serves the feedback curator module with `feedback=`."""

    def __init__(self, *, feedback: Any = None, **curators: Any) -> None:
        super().__init__(**curators)
        self.feedback = feedback

    def __call__(self, paths: Any, state: Any, channel: Any, threshold_env: str, module_name: str,
                 pending_label: str, *, batch: Any, **kw: Any) -> None:
        if module_name != FEEDBACK_MODULE:
            return super().__call__(paths, state, channel, threshold_env, module_name, pending_label,
                                    batch=batch, **kw)
        self.calls.append(module_name)
        self.handed.append(dict(kw))
        self.batches.append(batch)
        self.paths_seen.append(paths)
        if self.feedback is None:
            return
        mod = importlib.import_module(FEEDBACK_RUN)
        box = kw.pop("box", None)
        with draft_lane_trees(batch, AUTHOR_DRAFT_LANES) as trees:
            cfg = mod.build_feedback_config(paths, state=state, trees=trees, box=box, batch=batch, **kw)
            mod.run_batch(hold_committed=True, cfg=dataclasses.replace(cfg, invoke_agent=self.feedback), box=box)


def feedback_scene(tmp_path: Path, *, rows: list[dict] | None = None,
                   curator: FeedbackCurator | None = None, **cfg_overrides: Any) -> S.DraftScene:
    """The feedback channel's tick over a draft lane (`build_questioner_draft_scene` for this channel)."""
    mod = importlib.import_module(FEEDBACK_RUN)
    lane = C.draft_lane(tmp_path)
    S.seed(lane.paths, channel(), list(rows if rows is not None else [row()]))
    fake = curator if curator is not None else FeedbackCurator()
    base = mod.build_feedback_config(lane.paths, state=C.open_state(lane.paths), trees=C.draft_trees(lane),
                                     manifest_seed=None, box=None, batch=lane.batch)
    cfg = dataclasses.replace(base, invoke_agent=fake, **cfg_overrides)
    return S.DraftScene(paths=lane.paths, cfg=cfg, channel=channel(), repo=lane.clone,
                        corpus=lane.agent / "lessons", rows=rows or [], curator=fake,
                        runner=mod.run_batch, base_sha=lane.base, lane=lane)


def frames(prompt: str) -> list[tuple[str, str, str]]:
    """`[(salt, tag, body)]` of every run-salted frame in `prompt`."""
    return [(m["salt"], m["tag"], m["body"]) for m in FRAME_RE.finditer(prompt)]
