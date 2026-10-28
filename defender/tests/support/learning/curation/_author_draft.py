"""The lessons author over a batch's git-free draft, for the author pre-flight, post-flight and
atomicity suites."""
from __future__ import annotations

import json
from pathlib import Path

from defender.learning.core.state import FINDINGS
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.shared._locations_1210 import location_path


class DraftRepo:
    """A batch draft (`_curator1134.draft_lane`) and the lessons author over it; its config
    (`_curator1134.draft_author_cfg`) is built on first use of `cfg`."""

    def __init__(self, lane):
        from defender.learning.author.lessons import run as author_mod

        self.lane = lane
        self.author = author_mod
        self.paths = lane.paths
        self.lessons_dir = lane.lessons_dir
        self.state = C.open_state(lane.paths)
        self._cfg = None

    @classmethod
    def over(cls, tmp_path: Path, *, files: dict[str, str | bytes] | None = None) -> DraftRepo:
        """The fixture tenant's batch draft (lanes `lessons`, `lessons-questioner`), with `files`
        in the export commit it is built from."""
        return cls(C.draft_lane(tmp_path, files=files))

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg = C.draft_author_cfg(self.lane, state=self.state)
        return self._cfg

    @property
    def queue(self) -> Path:
        return location_path(self.paths.state_root) / FINDINGS.queue

    @property
    def consumed(self) -> Path:
        return location_path(self.paths.state_root) / FINDINGS.consumed

    @property
    def deadletter(self) -> Path:
        return location_path(self.paths.state_root) / FINDINGS.deadletter

    def write_lesson(self, name: str, finding_id: str) -> None:
        """Write a lesson citing `finding_id` into the draft's corpus; no git (the loop commits)."""
        (self.lessons_dir / f"{name}.md").write_text(
            "---\n"
            f"name: {name}\n"
            "description: a teachable pitfall\n"
            "source_finding_ids:\n"
            f"  - {finding_id}\n"
            "created_at: 2026-05-09T00:00:00+00:00\n"
            "---\n\nbody\n"
        )


def rows_without_attempts(text: str) -> list[dict]:
    """The queue's rows with the retirement counter dropped."""
    return [
        {k: v for k, v in json.loads(line).items() if k != "attempts"}
        for line in text.splitlines() if line.strip()
    ]


def attempts(text: str) -> list[int]:
    return [json.loads(line).get("attempts") for line in text.splitlines() if line.strip()]
