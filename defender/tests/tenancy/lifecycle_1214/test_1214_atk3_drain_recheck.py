# ruff: noqa: PT018
"""#1214 attack-3 holes 1, 2, 4 (Flow 4, P3): the lead drain re-reads the tenant's state at each claim, fails
closed on a directory error, treats offboarded and unknown as not active, and never counts a set-aside claim.
"""
from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.lifecycle_1214.test_1214_host_entry import (
    _FlipOnFirst,
    _twin_directory,
)
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture

#: What the directory answers after the first claim: a state, None (no row), or an error to raise.
AFTER = ["offboarding", "offboarded", "creating", None]


class _Failing(Exception):
    pass


def _scripted(directory: Any) -> tuple[Any, Any]:
    """`directory` with a `state` that can be overridden from now on: (directory, set_answer)."""
    box: dict[str, Any] = {}
    real = directory.state

    def state(tenant_id: Any) -> Any:
        if "answer" in box:
            answer = box["answer"]
            if isinstance(answer, Exception):
                raise answer
            return answer
        return real(tenant_id)

    object.__setattr__(directory, "state", state)
    return directory, lambda answer: box.update(answer=answer)


def _drain(t: Any, tmp_path: Path, monkeypatch: Any, answer: Any) -> tuple[list[str], dict[str, str], Any, Any]:
    """Two queued runs, then ticks of the lead drain with `answer` given after the first claim.
    Returns (labels served over the ticks, run name -> label, paths, directory)."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy,
        LeadStep,
        drain_paths,
        executed_lead,
        lead_author_drain,
        product_repo,
        queued_run,
    )

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    directory, answer_with = _scripted(_twin_directory(t.tenant_id, t.origin)[0])
    paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
    runs = {queued_run(t, paths, label).name: label for label in ("claim-1", "claim-2")}
    inner = LeadStep(executed={r: [executed_lead("cmdb.owner-by-tag")] for r in runs}, edits={})
    step = _FlipOnFirst(inner, lambda: answer_with(answer))
    for _ in range(4):  # repeated ticks: a set-aside claim must not wear out
        with contextlib.suppress(_Failing):
            lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step, run_pitfalls=lambda *_a, **_k: 0,
                              directory=directory)
    return step.served, runs, paths, directory


@pytest.mark.parametrize("answer", AFTER)
def test_a_claim_of_a_tenant_no_longer_active_stays_queued_uncounted_across_ticks(p4_tenant, tmp_path, monkeypatch, answer):  # noqa: F811
    """Whatever the tenant became after the first claim, the second is never served, keeps `attempts`, and survives repeated ticks (Flow 4)."""
    t = p4_tenant
    served, runs, paths, _ = _drain(t, tmp_path, monkeypatch, answer)
    assert len(served) == 1, served
    unserved = next(label for run, label in runs.items() if run != served[0])
    queued = Path(location_path(paths.state_root)) / "author-queue" / f"case-{unserved}.json"
    assert queued.is_file(), "the claim of a tenant no longer active must stay queued"
    assert json.loads(queued.read_text(encoding="utf-8")).get("attempts", 0) == 0, "a set-aside claim was counted"


def test_a_directory_that_fails_at_the_second_claim_does_not_serve_it(p4_tenant, tmp_path, monkeypatch):  # noqa: F811
    """A state read that raises at the second claim: that claim is not served and is not lost (fails closed, deck PR #678)."""
    t = p4_tenant
    served, runs, paths, _ = _drain(t, tmp_path, monkeypatch, _Failing("database away"))
    assert len(served) == 1, served
    unserved = next(label for run, label in runs.items() if run != served[0])
    root = Path(location_path(paths.state_root)) / "author-queue"
    assert list(root.rglob(f"case-{unserved}.json")), "the unserved claim vanished"
