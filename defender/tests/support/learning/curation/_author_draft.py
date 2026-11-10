"""The lessons author over a batch's git-free draft, for the author pre-flight, post-flight and
atomicity suites."""
from __future__ import annotations

from pathlib import Path

from defender.tests.support.learning.curation import _curator1134 as C


class DraftRepo:
    """A batch draft (`_curator1134.draft_lane`) and the lessons author over it; its config
    (`_curator1134.draft_author_cfg`) is built on first use of `cfg`."""

    def __init__(self, lane):
        from defender.learning.author.lessons import run as author_mod

        self.lane = lane
        self.author = author_mod
        self.paths = lane.paths
        self.lessons_dir = lane.lessons_dir
        self._cfg = None
        self.rows: list[dict] = []
        #: The fates the claims wrote, keyed `(kind, key)` (the drain's `outcomes=` map).
        self.outcomes: dict = {}

    @classmethod
    def over(cls, tmp_path: Path, *, files: dict[str, str | bytes] | None = None) -> DraftRepo:
        """The fixture tenant's batch draft (lanes `lessons`, `lessons-questioner`), with `files`
        in the export commit it is built from."""
        return cls(C.draft_lane(tmp_path, files=files))

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg = C.draft_author_cfg(self.lane)
        return self._cfg

    def add(self, finding_id: str, *, run_id: str | None = None) -> dict:
        """Claim a finding row `finding_id` (the lessons gate admits it): the claim's items are these rows."""
        from defender.tests.support.learning.curation._drain719 import finding_row

        row = finding_row(finding_id, run_id=run_id or finding_id.split("/")[0])
        self.rows.append(row)
        return row

    def items(self) -> list[tuple[str, str, dict]]:
        """The claim's items, `(kind, key, payload)`, as the store hands the curator its rows (#1278 D1)."""
        return [("finding", r["finding_id"], r) for r in self.rows]

    def run(self, cfg=None, **kw) -> int:
        """`run_batch` over the claim's items (`cfg`, else this draft's), the fates written to `outcomes`."""
        return self.author.run_batch(cfg=cfg or self.cfg, items=self.items(), outcomes=self.outcomes, **kw)

    def fate(self, finding_id: str):
        """`(outcome name, reason)` the claim wrote for `finding_id`, or `None` if it named none."""
        out = self.outcomes.get(("finding", finding_id))
        return None if out is None else (out.name, out.reason)

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
