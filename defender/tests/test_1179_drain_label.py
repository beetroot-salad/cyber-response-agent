"""#1179: the drain labels are the members of a plain `enum.Enum`, so no string is a label.

The contract is #1179's intent+design comment (2026-10-03):

- O1, `LoopPaths.drain_writable_trees` grants a tree only to a `DrainLabel` member. The members'
  own values as bare strings get nothing (`test_1134_mount_list.py` carries them as rows of
  every unknown-label test). Here the same strings are driven through the lead-author lane's
  own grant check (`lead_author.run(deps=...)`), the one consumer of the list outside the box
  and the holder.
- O2, the two records that persist a label still write its value as a JSON string: the
  pending-delivery record (`drains._record_pending_delivery`) and the quarantine manifest
  (`quarantine.preserve_tainted_tree`). Each is read back from disk. The quarantine writer
  swallows its own failures (a missed `.value` would lose the manifest silently and log an
  error), so these rows assert on the written file, never on an exception.
- O3, every message that carries a label shows its value, never `DrainLabel.AUTHOR` or
  `<DrainLabel.AUTHOR: ...>`: the claim log of `markers.claim_markers`, the quarantine log, and
  the lead-author refusal (formatted with `!r` before #1179).

Real primitives throughout: a real scrub taints a real tree with a planted link, the real writers
write, and the records are read back with `json.loads`. Nothing is monkeypatched (`caplog`
only captures).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.learning.author.branch import AuthorBranch
from defender.learning.core import drains, markers
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.core.quarantine import preserve_tainted_tree
from defender.learning.leads import lead_author
from defender.learning.leads.lead_author import LeadAuthorError
from defender.runtime import scrub as scrub_mod

VALUES = {AUTHOR_DRAIN_LABEL: "author_drain", LEAD_AUTHOR_DRAIN_LABEL: "lead_author_drain"}
MEMBERS = list(VALUES)
#: What a member's display would leak if formatted as the enum's own `str`/`repr`.
LEAKS = ("DrainLabel", "<", "AUTHOR:")


def _paths(tmp_path: Path) -> LoopPaths:
    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _assert_shows_value(text: str, label: DrainLabel) -> None:
    assert VALUES[label] in text, text
    for leak in LEAKS:
        assert leak not in text, (leak, text)


# ---------------------------------------------------------------------------------------
# O2: the written records carry the value
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_pending_delivery_record_writes_the_labels_value(tmp_path: Path, label: DrainLabel):
    """The real `_record_pending_delivery` writes `"label": "<value>"`, a JSON string, beside
    the branch and batch it already wrote.

    Catches: the member handed to `json.dumps` (a `TypeError` out of the delivery path), its
    `str()`/`repr()` or its name written instead of its value, and a record that drops the
    label."""
    paths = _paths(tmp_path)
    branch = AuthorBranch(repo_root=paths.repo_root, worktree_base=tmp_path / "wts")

    drains._record_pending_delivery(paths, branch, "batch-7", label=label, reason="push failed")

    [record] = sorted(paths.pending_delivery_dir.glob("*.json"))
    doc = json.loads(record.read_text(encoding="utf-8"))
    assert doc["label"] == VALUES[label]
    assert type(doc["label"]) is str
    assert doc["batch_id"] == "batch-7"
    assert doc["branch"] == branch.branch_name("batch-7")
    assert doc["reason"] == "push failed"


def _tainted(tree: Path) -> scrub_mod.RunTainted:
    """A real taint: a link planted in a real tree, caught by the real scrub."""
    tree.mkdir(parents=True)
    (tree / "lesson.md").write_text("ok\n", encoding="utf-8")
    os.symlink("/etc/passwd", tree / "stolen.md")
    try:
        scrub_mod.scrub(tree)
    except scrub_mod.RunTainted as taint:
        return taint
    raise AssertionError("the planted link did not taint the tree: the drive is vacuous")


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_quarantine_manifest_writes_the_labels_value_and_logs_it(
        tmp_path: Path, label: DrainLabel, caplog: pytest.LogCaptureFixture):
    """The real `preserve_tainted_tree` over a really tainted tree writes its archive and a
    manifest whose `"label"` is the value, a JSON string, and logs the preservation under the
    value.

    The manifest is read back: the writer swallows any failure (it must not mask the taint),
    so a member handed to `json.dumps` shows only as a missing manifest and an error log.

    Catches: a missed `.value` (no manifest, the archive alone), a written `str()`/`repr()`,
    and a log line that shows `DrainLabel.AUTHOR`."""
    wt = tmp_path / "wt"
    taint = _tainted(wt)
    qdir = tmp_path / "quarantine"

    with caplog.at_level(logging.WARNING):
        archive = preserve_tainted_tree(
            wt, qdir, batch_id="batch-9", branch="lessons/batch-9", label=label, taint=taint)

    assert archive == qdir / "batch-9.tar.gz"
    assert archive.is_file()
    manifest = qdir / "batch-9.json"
    assert manifest.is_file(), f"no manifest beside the archive; logs: {caplog.text}"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    assert doc["label"] == VALUES[label]
    assert type(doc["label"]) is str
    assert doc["batch_id"] == "batch-9"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    [preserved] = [r.getMessage() for r in caplog.records if "preserved at" in r.getMessage()]
    _assert_shows_value(preserved, label)


# ---------------------------------------------------------------------------------------
# O3: messages show the value
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_claim_log_shows_the_labels_value(
        tmp_path: Path, label: DrainLabel, caplog: pytest.LogCaptureFixture):
    """`claim_markers(label=<member>)` logs its queue count under the value.

    Catches: an f-string `{label}` over a member whose `str()` is the enum's default
    (`DrainLabel.AUTHOR`)."""
    queue = tmp_path / "queue"
    queue.mkdir()
    with caplog.at_level(logging.INFO):
        assert list(markers.claim_markers(
            queue, identity_key="run_id", label=label, noun="authoring")) == []
    [line] = [r.getMessage() for r in caplog.records if "queued for authoring" in r.getMessage()]
    _assert_shows_value(line, label)
    assert line.startswith(f"{VALUES[label]}: ")


def test_the_lead_author_refusal_names_the_labels_value(tmp_path: Path):
    """`lead_author.run(deps=..., label=<member>)` whose list lacks `skills/` is refused, and the
    refusal names the lane by its value, quoted: `the 'author_drain' lane does not mount`.

    The author member is that case: its list is the two lessons corpora. The positive control,
    the lead member over the same `deps.paths`, gets past the check (to the queue lock, which
    the stub deps answers with a sentinel).

    Catches: `{label!r}` over a member, rendering `<DrainLabel.AUTHOR: 'author_drain'>`."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    paths = _paths(tmp_path)

    class Reached(Exception):
        pass

    def lock() -> None:
        raise Reached

    deps = SimpleNamespace(paths=paths, acquire_queue_lock=lock)
    with pytest.raises(LeadAuthorError) as e:
        lead_author.run(run_dir, label=AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]
    msg = str(e.value)
    assert "the 'author_drain' lane does not mount" in msg, msg
    _assert_shows_value(msg, AUTHOR_DRAIN_LABEL)

    with pytest.raises(Reached):
        lead_author.run(run_dir, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------------------
# O1 through the lead-author lane's own grant check
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["lead_author_drain", "author_drain"])
def test_the_lead_author_lane_refuses_a_labels_value_as_a_bare_string(tmp_path: Path, value: str):
    """`lead_author.run(deps=..., label="lead_author_drain")`, the lead lane's value as a bare
    string, is refused before the queue lock: a string is no label, so its list is empty and
    lacks `skills/`. The control is the member itself, above.

    Catches: a `str`-mixin enum, or a list that accepts a member's value (`DrainLabel(label)`
    coercion, an `==` table keyed by the strings)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    paths = _paths(tmp_path)

    def lock() -> None:
        raise AssertionError("a bare string got past the grant check to the queue lock")

    deps = SimpleNamespace(paths=paths, acquire_queue_lock=lock)
    assert paths.drain_writable_trees(value) == ()  # type: ignore[arg-type]
    with pytest.raises(LeadAuthorError):
        lead_author.run(run_dir, label=value, deps=deps)  # type: ignore[arg-type]
