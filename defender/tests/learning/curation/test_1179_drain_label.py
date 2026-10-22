from __future__ import annotations


import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.learning.core.state import LEAD_QUEUE_LOCK, TRY_ONCE
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.leads import lead_author
from defender.learning.leads.lead_author import LeadAuthorError
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of, state_for_paths
from defender.tests.learning.curation.test_1134_mount_list import UNKNOWN_LABELS

VALUES = {AUTHOR_DRAIN_LABEL: "author_drain", LEAD_AUTHOR_DRAIN_LABEL: "lead_author_drain"}
MEMBERS = list(VALUES)
#: Non-members, as `test_1134_mount_list` spells them: values and names as strings, look-alikes,
#: `.value` carriers, near misses.
NON_MEMBERS = list(UNKNOWN_LABELS)
#: What a member's display would leak if formatted as the enum's own `str`/`repr`.
LEAKS = ("DrainLabel", "<", "AUTHOR:")


def _paths(tmp_path: Path) -> LoopPaths:
    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def _assert_shows_value(text: str, label: DrainLabel) -> None:
    assert VALUES[label] in text, text
    for leak in LEAKS:
        assert leak not in text, (leak, text)


@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_claim_log_shows_the_labels_value(
        tmp_path: Path, label: DrainLabel, caplog: pytest.LogCaptureFixture):
    state = state_for_paths(_paths(tmp_path))
    with caplog.at_level(logging.INFO):
        assert list(state.claim(
            "run_id", label=label, noun="authoring")) == []  # type: ignore[arg-type]
    [line] = [r.getMessage() for r in caplog.records if "queued for authoring" in r.getMessage()]
    _assert_shows_value(line, label)
    assert line.startswith(f"{VALUES[label]}: ")


def test_the_lead_author_refusal_names_the_labels_value(tmp_path: Path):
    run = run_of(curation_run_dir("run"))  # the opened run the lane is handed (#1105 PR 2)
    paths = _paths(tmp_path)

    class Reached(Exception):
        pass

    def lock(_role: object, *, wait: object) -> None:
        raise Reached

    deps = SimpleNamespace(paths=paths, state=SimpleNamespace(lock=lock))
    with pytest.raises(LeadAuthorError) as e:
        lead_author.run(run, label=AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]
    msg = str(e.value)
    assert "the 'author_drain' lane does not mount" in msg, msg
    _assert_shows_value(msg, AUTHOR_DRAIN_LABEL)

    with pytest.raises(Reached):
        lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, deps=deps)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", NON_MEMBERS, ids=repr)
def test_the_lead_author_lane_raises_on_a_non_member_before_the_queue_lock(
        tmp_path: Path, value: object):
    run = run_of(curation_run_dir("run"))  # the opened run the lane is handed (#1105 PR 2)
    paths = _paths(tmp_path)

    def lock(_role: object, *, wait: object) -> None:
        raise AssertionError("a non-member got past the grant check to the queue lock")

    deps = SimpleNamespace(paths=paths, state=SimpleNamespace(lock=lock))
    with pytest.raises(AttributeError):
        lead_author.run(run, label=value, deps=deps)  # type: ignore[arg-type]

    with state_for_paths(paths).lock(LEAD_QUEUE_LOCK, wait=TRY_ONCE) as held:
        assert held, "precondition: the test holds the queue lock"
        assert lead_author.run(run, label=LEAD_AUTHOR_DRAIN_LABEL, paths=paths) == \
            lead_author.QUEUE_LOCK_SKIP_RC, "control: the held lock makes a member skip"
        with pytest.raises(AttributeError):
            lead_author.run(run, label=value, paths=paths)  # type: ignore[arg-type]


def test_the_paths_carry_no_label_table():
    """`LoopPaths` has no `drain_writable_trees` (#1179 M1'): the member owns its trees, so no
    second, string-keyed table can sit behind it on the paths."""
    assert not hasattr(LoopPaths, "drain_writable_trees")
