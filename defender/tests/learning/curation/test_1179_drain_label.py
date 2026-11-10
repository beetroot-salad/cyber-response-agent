from __future__ import annotations


import logging
from pathlib import Path

import pytest

from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, DrainLabel, LoopPaths,
)
from defender.learning.leads import lead_author
from defender.learning.leads.lead_author import LeadAuthorError
from defender.tests.support.learning.core._state1135 import curation_run_dir, run_of
from defender.tests.support.learning.core._store1278 import migrated_database, world  # noqa: F401 — fixtures
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on
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


class _PastTheGrant:
    """Lead-author deps that answer only what the lane's grant check reads (`paths`, no `batch`, no `skills_dir` of
    their own); reading anything else means the run got past the grant check, and raises `past`."""

    def __init__(self, paths: LoopPaths, past: type[Exception]) -> None:
        self.paths, self.batch, self.skills_dir, self._past = paths, None, None, past

    def __getattr__(self, name: str) -> object:
        raise self._past(name)


@pytest.mark.postgres
@pytest.mark.parametrize("label", MEMBERS, ids=lambda m: m.value)
def test_the_claim_log_shows_the_labels_value(world, label: DrainLabel, caplog: pytest.LogCaptureFixture):  # noqa: F811 — the imported fixture
    """UPDATED (#1278 C15, A2: the file queue's claim is replaced by the store's): the drain tick over an empty store
    logs its lane by the label's value."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, lead_author_drain

    with caplog.at_level(logging.INFO):
        if label is AUTHOR_DRAIN_LABEL:
            author_drain(world.t, world.paths, trigger=None, box=BoxSpy())
        else:
            lead_author_drain(world.t, world.paths, box=BoxSpy())
    lines = [r.getMessage() for r in caplog.records if VALUES[label] in r.getMessage()]
    assert any(line.startswith(f"{VALUES[label]}: ") for line in lines), [r.getMessage() for r in caplog.records]
    for line in lines:
        _assert_shows_value(line, label)


def test_the_lead_author_refusal_names_the_labels_value(tmp_path: Path):
    run = run_of(curation_run_dir("run"))  # the opened run the lane is handed
    paths = _paths(tmp_path)

    class Reached(Exception):
        pass

    deps = _PastTheGrant(paths, Reached)  # #1278 r8 Locks: no queue lock is the next step; whatever is, is past the grant
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
    run = run_of(curation_run_dir("run"))  # the opened run the lane is handed
    paths = _paths(tmp_path)

    class GotPast(AssertionError):
        pass

    deps = _PastTheGrant(paths, GotPast)  # a non-member reading anything past the grant check fails the test
    with pytest.raises(AttributeError):
        lead_author.run(run, label=value, deps=deps)  # type: ignore[arg-type]

    # Conflict (design r8 Locks): the lead-queue file lock and its skip control are gone; a non-member still fails first.
    with pytest.raises(AttributeError):
        lead_author.run(run, label=value, paths=paths)  # type: ignore[arg-type]


def test_the_paths_carry_no_label_table():
    """The label owns its trees: `LoopPaths` carries no second, string-keyed table behind it
    (`drain_writable_trees`)."""
    assert not hasattr(LoopPaths, "drain_writable_trees")
