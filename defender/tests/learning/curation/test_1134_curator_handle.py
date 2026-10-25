"""#1134 curator readers over the lane's held mount: an aliased, refused, absent or undecodable
lesson is never followed, cites nothing and shows as unavailable, on the lessons and questioner
channels alike.

#1108 P4 (O7, OD12): the lane's corpus is a batch's git-free draft (`_curator1134.draft_world`),
not a product-shaped worktree. Deleted here as (i), pinning only the legacy worktree mechanism
that amendments 2-3 replace with `Batch.change_set()` / `Batch.reset()` / the commit-maker:
  - the before-state snapshot (`_snapshot_corpus`: regular blobs at HEAD, symlinks, submodules,
    the commit given, git faults) -> the ChangeSet base is read from git objects:
    tests/tenancy/tenant_1108_delivery/test_changes.py::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files;
  - the fault/settle/unapproved restores, `_put_back`, `_revert_strays`, sweeps below linked
    folders, FIFOs/folders/links at snapshot names, failing disks, gitignored names, broken
    index -> one reset from git objects that never follows box output:
    test_changes.py::test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links and
    ::test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole;
  - `_byte_identical_to_head` / settle comparisons (CRLF, mode-only, links holding HEAD bytes,
    paths outside the mounts) -> the ChangeSet compares bytes against the base blobs
    (test_changes.py, test_change_set_fuzz.py::test_derivation_keeps_its_invariant_on_random_box_output);
  - `git_commit_paths` and the approved-file/deletion commit -> the commit-maker
    (test_changes.py::test_the_commit_maker_takes_nothing_but_a_change_set,
    ::test_claims_commit_and_reset_one_after_another_within_one_batch);
  - the clean-corpus gate (`assert_clean_corpus_dir`, git status) -> a draft is built fresh from
    the export commit per batch: test_batches.py::test_start_batch_makes_a_git_free_draft_of_the_export_commit_and_no_checkout.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from defender.learning.author import drain
from defender.learning.author.version_control import AgentChange
from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.author.questioner import run as questioner_run
from defender.tests.support.learning.curation._curator1134 import (
    OUT_MARK,
    JournalHeld,
    draft_world,
    lesson_text,
    plant_alias,
    put,
)
from defender.tests.support.learning.curation._shared_readers_1134 import kernel_watch


#: The lesson name every row plants at: distinctive, so a log line naming it names this entry.
PLANTED = "planted-lesson.md"
FIELD = "source_finding_ids"


def _watch_for(kind: str, target: Path):
    """The watch that sees a plant followed: no open of a symlink's (or a moved folder's)
    target; no read of a hard link's shared inode (which the no-follow open does reach)."""
    return kernel_watch(reads=[target]) if kind == "hard link" else kernel_watch(opens=[target])


def _change(content: bytes) -> AgentChange:
    return AgentChange(f"agent/lessons/{PLANTED}", content)


def test_a_lesson_cites_what_its_landing_bytes_cite_whatever_its_line_endings():
    """A changed lesson's citations are read from the bytes it would land, never read back from
    the corpus (so an alias at its name is the change set's refusal, test_changes.py), decoded
    as a text read decodes a file: CRLF and CR line endings cite as LF ones do."""
    body = lesson_text("f1", mark=OUT_MARK).encode()
    for content in (body, body.replace(b"\n", b"\r\n"), body.replace(b"\n", b"\r")):
        assert drain._change_cites(_change(content), FIELD) == {"f1"}, content[:40]


def test_an_undecodable_lesson_cites_nothing():
    """A changed lesson that is not UTF-8 cites nothing, so it is unattributable."""
    content = b"---\nsource_finding_ids:\n- f1\n---\n\xff\xfe\n"
    assert drain._change_cites(_change(content), FIELD) == set()


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_idempotency_read_skips_an_aliased_lesson(tmp_path, kind):
    """The lane's idempotency read over the draft skips an aliased lesson and counts it once
    plain (#1134, P4 O7: config over the draft, assumed `batch=` seam)."""
    w = draft_world(tmp_path)
    put(w.corpus_dir / "plain.md", lesson_text("f-plain"))
    body = lesson_text("f-out", mark=OUT_MARK)
    target = w.target("secret.md", body)
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)
    log: list = []
    cfg = w.cfg(corpus=JournalHeld(w.corpus_dir, log))

    assert author_shared.existing_finding_ids(cfg) == {"f-plain"}
    assert {("read", "plain.md"), ("read", PLANTED)} <= set(log), log

    put(at, body)
    assert author_shared.existing_finding_ids(cfg) == {"f-plain", "f-out"}


def test_the_idempotency_read_leaves_out_a_lesson_cfg_corpus_refuses(tmp_path):
    """A draft lesson the held corpus refuses is left out of the idempotency read; read when not
    refused (#1134, P4 O7: assumed `batch=` seam)."""
    w = draft_world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("f-a"))
    put(w.corpus_dir / "b.md", lesson_text("f-b"))
    log: list = []
    refusing = w.cfg(corpus=JournalHeld(w.corpus_dir, log, refuse=("b.md",)))

    assert author_shared.existing_finding_ids(refusing) == {"f-a"}
    assert {("read", "a.md"), ("read", "b.md")} <= set(log), log

    plain = w.cfg(corpus=JournalHeld(w.corpus_dir, []))
    assert author_shared.existing_finding_ids(plain) == {"f-a", "f-b"}


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_manifest_shows_an_aliased_lesson_as_unavailable(tmp_path, kind):
    """The corpus manifest over the draft shows an aliased lesson as unavailable, never its
    target's bytes; the plain file shows its fields (#1134, P4 O7)."""
    w = draft_world(tmp_path)
    body = lesson_text("f1", mark=OUT_MARK, topic=OUT_MARK)
    target = w.target("secret.md", body)
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)

    with _watch_for(kind, target) as events:
        manifest = author_shared.build_corpus_manifest(w.view, where=w.corpus_dir)
        seen = events()

    stem = PLANTED.removesuffix(".md")
    assert f"## {stem}" in manifest
    assert "unavailable" in manifest
    assert OUT_MARK not in manifest
    assert seen == []

    put(at, body)
    rendered = author_shared.build_corpus_manifest(w.view, where=w.corpus_dir)
    assert f"topic: {OUT_MARK}" in rendered
    assert "unavailable" not in rendered


def _channel_prompt(w, channel):
    """`(draft corpus root, the channel's prompt builder, its config over the draft's trees)`."""
    if channel == "lessons":
        return w.corpus_dir, lessons_run.build_user_prompt, w.cfg()
    return w.sibling_dir, questioner_run.build_questioner_user_prompt, w.questioner_cfg()


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_each_channel_prompt_shows_a_lesson_cfg_corpus_refuses_as_unavailable(tmp_path, channel):
    """Each channel's prompt over its draft lane shows a refused lesson as unavailable and the
    rest as written (#1134, P4 O7: assumed `batch=` seam)."""
    w = draft_world(tmp_path)
    root, prompt_of, cfg = _channel_prompt(w, channel)
    put(root / "a.md", lesson_text("f-a", topic="topic-of-a"))
    put(root / "b.md", lesson_text("f-b", topic="topic-of-b"))
    log: list = []
    refusing = dataclasses.replace(cfg, corpus=JournalHeld(root, log, refuse=("b.md",)))

    prompt = prompt_of([{"finding_id": "f1"}], "batch-1", refusing)

    assert "topic-of-a" in prompt
    assert "topic-of-b" not in prompt
    assert "## b\n(unavailable" in prompt, prompt
    assert {("read", "a.md"), ("read", "b.md")} <= set(log), log

    plain = dataclasses.replace(cfg, corpus=JournalHeld(root, []))
    rendered = prompt_of([{"finding_id": "f1"}], "batch-1", plain)
    assert "topic-of-b" in rendered
    assert "unavailable" not in rendered
