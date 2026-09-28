"""The lessons author's view of the corpus: which finding ids its lessons already cite."""
from __future__ import annotations


def test_existing_finding_ids_handles_empty_dir(tmp_repo):
    a = tmp_repo.author
    assert a.existing_finding_ids(tmp_repo.cfg) == set()


def test_existing_finding_ids_aggregates_across_lessons(tmp_repo):
    a = tmp_repo.author
    (tmp_repo.paths.lessons_dir / "one.md").write_text(
        "---\nname: one\ndescription: d\nsource_finding_ids:\n  - r/0\n  - r/1\ncreated_at: 2026-05-09T00:00:00+00:00\n---\nbody\n"
    )
    (tmp_repo.paths.lessons_dir / "two.md").write_text(
        "---\nname: two\ndescription: d\nsource_finding_ids:\n  - r/2\ncreated_at: 2026-05-09T00:00:00+00:00\n---\nbody\n"
    )
    assert a.existing_finding_ids(tmp_repo.cfg) == {"r/0", "r/1", "r/2"}


def test_lesson_with_no_frontmatter_is_ignored(tmp_repo):
    a = tmp_repo.author
    (tmp_repo.paths.lessons_dir / "nofm.md").write_text("just a body, no frontmatter\n")
    assert a.existing_finding_ids(tmp_repo.cfg) == set()


def test_existing_finding_ids_skips_an_undecodable_lesson(tmp_repo, capsys):
    """One corrupt byte must not abort the author drain. ``read_text()`` raises
    ``UnicodeDecodeError`` — a ``ValueError``, not an ``OSError`` — so the un-guarded read this
    walk used to do took the whole pre-flight down, where the corpus manifest beside it warned and
    skipped the one file. The well-formed siblings' ids must still come back."""
    a = tmp_repo.author
    (tmp_repo.paths.lessons_dir / "good.md").write_text(
        "---\nname: good\ndescription: d\nsource_finding_ids:\n  - r/0\n---\nbody\n"
    )
    (tmp_repo.paths.lessons_dir / "corrupt.md").write_bytes(b"---\nname: c\n---\n\xff\xfe\n")
    assert a.existing_finding_ids(tmp_repo.cfg) == {"r/0"}
    assert "corrupt.md" in capsys.readouterr().err


def test_existing_finding_ids_skips_underscore_prefixed_files(tmp_repo):
    """``_``-prefixed files are not lessons — every other corpus reader skips them, so a template's
    placeholder ids must not be counted as already-consumed and strand the real findings."""
    a = tmp_repo.author
    (tmp_repo.paths.lessons_dir / "_TEMPLATE.md").write_text(
        "---\nname: t\ndescription: d\nsource_finding_ids:\n  - r/placeholder\n---\nbody\n"
    )
    assert a.existing_finding_ids(tmp_repo.cfg) == set()


