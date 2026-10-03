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

import ast
import inspect
import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.author.branch import AuthorBranch
from defender.learning.core import drains, lane_trees, markers
from defender.learning.core import quarantine as quarantine_mod
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.core.quarantine import preserve_tainted_tree
from defender.learning.leads import lead_author
from defender.learning.leads.lead_author import LeadAuthorError
from defender.runtime import scrub as scrub_mod
from defender.tests.e2e import _box665 as B

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


# ---------------------------------------------------------------------------------------
# O1 at the batch entry: the box a string-labelled batch starts mounts nothing writable
# ---------------------------------------------------------------------------------------


def _writable(request: Any) -> list[Path]:
    return [Path(m.source) for m in request.mounts if m.writable]


@pytest.mark.parametrize("value", ["author_drain", "lead_author_drain"])
def test_a_batch_labelled_by_a_bare_string_starts_a_box_with_no_writable_mount(
        tmp_path: Path, value: str):
    """The real `_run_worktree_batch(label="<value>")`: the one `BoxRequest` its box seam is
    handed has no writable mount (only the leaf, read-only). The positive control, the member
    whose value it is, over a fresh drive: its box mounts the lane's trees writable.

    Catches: a string coerced into a member at the batch entry (`DrainLabel(label)` before
    `_drain_box_request`), which the per-function no-grant rows never see."""
    member = {v: m for m, v in VALUES.items()}[value]
    expected = {AUTHOR_DRAIN_LABEL: ("defender/lessons", "defender/lessons-questioner"),
                LEAD_AUTHOR_DRAIN_LABEL: ("defender/skills",)}[member]

    rec = B.BoxLifecycleRecorder()
    B.drive_worktree_batch(tmp_path / "string", rec, do_work=lambda *_a, **_k: None,
                           label=value)
    assert _writable(rec.only_request()) == []

    rec = B.BoxLifecycleRecorder()
    B.drive_worktree_batch(tmp_path / "member", rec, do_work=lambda *_a, **_k: None,
                           label=member)
    request = rec.only_request()
    [leaf] = [Path(m.source) for m in request.mounts if not m.writable]
    assert _writable(request) == [leaf / rel for rel in expected]


# ---------------------------------------------------------------------------------------
# O3 by construction: every label in a message is formatted bare (its `str()`, the value)
# ---------------------------------------------------------------------------------------

#: The modules whose messages carry a drain label (design O3's sites).
O3_MODULES = (drains, quarantine_mod, markers, lead_author)


def _label_formats(tree: ast.AST) -> list[tuple[int, str]]:
    """Every f-string field naming `label` that is not a bare `{label}` (no `!r`/`!s`/`!a`, no
    format spec) or `{str(label)!r}`: those would show something other than the value."""
    bad = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.FormattedValue):
            continue
        names = {x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)}
        if "label" not in names:
            continue
        bare = (isinstance(n.value, ast.Name) and n.conversion == -1 and n.format_spec is None)
        via_str = (isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                   and n.value.func.id == "str" and len(n.value.args) == 1
                   and isinstance(n.value.args[0], ast.Name) and n.format_spec is None)
        if not (bare or via_str):
            bad.append((n.lineno, ast.unparse(n)))
    return bad


@pytest.mark.parametrize("module", O3_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_every_message_formats_the_label_bare(module: Any):
    """In every module with a label-carrying message, each f-string field over `label` is a bare
    `{label}` (which renders `str(member)`, the value, pinned above) or `{str(label)!r}`.

    Non-vacuity: the drains and quarantine modules have such fields at all.

    Catches: a `{label!r}`, `{label!s}` with a spec, `{label.name}` or `{label:...}` at any of
    the message sites, captured by a test or not (the per-message rows cover only some)."""
    tree = ast.parse(inspect.getsource(module))
    assert _label_formats(tree) == []
    if module in (drains, quarantine_mod):
        fields = [n for n in ast.walk(tree) if isinstance(n, ast.FormattedValue)
                  and isinstance(n.value, ast.Name) and n.value.id == "label"]
        assert fields, f"{module.__name__} formats no label: the check judged nothing"


# ---------------------------------------------------------------------------------------
# M1: the label is typed `DrainLabel` along the flow (mypy does not check tests or callers'
# strings, so the annotation is pinned here)
# ---------------------------------------------------------------------------------------

TYPED = {
    "LoopPaths.drain_writable_trees": LoopPaths.drain_writable_trees,
    "open_drain_trees": lane_trees.open_drain_trees,
    "_invoke_lead_author": drains._invoke_lead_author,
    "_maybe_trigger_author": drains._maybe_trigger_author,
    "_invoke_pitfalls": drains._invoke_pitfalls,
    "_run_worktree_batch": drains._run_worktree_batch,
    "_open_batch": drains._open_batch,
    "_land_batch": drains._land_batch,
    "_deliver_pending": drains._deliver_pending,
    "_record_pending_delivery": drains._record_pending_delivery,
    "_drain_box_request": drains._drain_box_request,
    "preserve_tainted_tree": preserve_tainted_tree,
    "claim_markers": markers.claim_markers,
    "lead_author.run": lead_author.run,
}


@pytest.mark.parametrize("name", list(TYPED))
def test_the_label_parameter_is_typed_drainlabel(name: str):
    """Each function on the label's flow annotates `label` as exactly `DrainLabel`: not `str`,
    not a union with `str`, not `Any`.

    Catches: a widened `DrainLabel | str` that lets a string through every type check."""
    fn = TYPED[name]
    annotation = inspect.signature(fn).parameters["label"].annotation
    resolved = eval(annotation, {**fn.__globals__, "DrainLabel": DrainLabel}) \
        if isinstance(annotation, str) else annotation
    assert resolved is DrainLabel, (name, annotation)
