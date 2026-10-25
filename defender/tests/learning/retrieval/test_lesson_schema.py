"""The lessons author's view of the corpus: which finding ids its lessons already cite.

#1108 P4 (O7, OD7): the corpus is a batch draft's `agent/lessons` lane, not a product-shaped repo."""
from __future__ import annotations

import pytest

from defender.tests.support.learning.curation import _curator1134 as C


# #1108 P4 (O7, OD7): the lessons author over a git-free draft, not `tmp_repo`'s product-shaped
# repo. The config is built with the assumed `batch=` seam (`_curator1134.draft_author_cfg`) on
# first use, so a test reaches its own body before that seam's absence fails it.
class _DraftRepo:
    def __init__(self, lane):
        from defender.learning.author.lessons import run as author_mod

        self.lane = lane
        self.author = author_mod
        self.paths = lane.paths
        self.lessons_dir = lane.lessons_dir
        self.state = C.open_state(lane.paths)
        self._cfg = None

    @property
    def cfg(self):
        if self._cfg is None:
            self._cfg = C.draft_author_cfg(self.lane, state=self.state)
        return self._cfg


@pytest.fixture
def draft_repo(tmp_path):
    """The fixture tenant's batch draft (lanes `lessons`, `lessons-questioner`) and its author."""
    return _DraftRepo(C.draft_lane(tmp_path))


def test_existing_finding_ids_handles_empty_dir(draft_repo):
    a = draft_repo.author
    assert a.existing_finding_ids(draft_repo.cfg) == set()


def test_existing_finding_ids_aggregates_across_lessons(draft_repo):
    a = draft_repo.author
    (draft_repo.lessons_dir / "one.md").write_text(
        "---\nname: one\ndescription: d\nsource_finding_ids:\n  - r/0\n  - r/1\ncreated_at: 2026-05-09T00:00:00+00:00\n---\nbody\n"
    )
    (draft_repo.lessons_dir / "two.md").write_text(
        "---\nname: two\ndescription: d\nsource_finding_ids:\n  - r/2\ncreated_at: 2026-05-09T00:00:00+00:00\n---\nbody\n"
    )
    assert a.existing_finding_ids(draft_repo.cfg) == {"r/0", "r/1", "r/2"}


def test_lesson_with_no_frontmatter_is_ignored(draft_repo):
    a = draft_repo.author
    (draft_repo.lessons_dir / "nofm.md").write_text("just a body, no frontmatter\n")
    assert a.existing_finding_ids(draft_repo.cfg) == set()


def test_existing_finding_ids_skips_an_undecodable_lesson(draft_repo, capsys):
    a = draft_repo.author
    (draft_repo.lessons_dir / "good.md").write_text(
        "---\nname: good\ndescription: d\nsource_finding_ids:\n  - r/0\n---\nbody\n"
    )
    (draft_repo.lessons_dir / "corrupt.md").write_bytes(b"---\nname: c\n---\n\xff\xfe\n")
    assert a.existing_finding_ids(draft_repo.cfg) == {"r/0"}
    assert "corrupt.md" in capsys.readouterr().err


def test_existing_finding_ids_skips_underscore_prefixed_files(draft_repo):
    """``_``-prefixed files are not lessons — every other corpus reader skips them, so a template's
    placeholder ids must not be counted as already-consumed and strand the real findings."""
    a = draft_repo.author
    (draft_repo.lessons_dir / "_TEMPLATE.md").write_text(
        "---\nname: t\ndescription: d\nsource_finding_ids:\n  - r/placeholder\n---\nbody\n"
    )
    assert a.existing_finding_ids(draft_repo.cfg) == set()
