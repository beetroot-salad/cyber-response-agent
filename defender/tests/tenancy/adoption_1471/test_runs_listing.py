"""#1471 R13-1.7: whatever the adoption container's outcome, the tenant's runs listing still serves (#1546 A-O2: the outcome is
the `result` it sends on the job socket, never a file in `<T>/runs`; `_enter` asserts no `.adoption.json` is written). The same check the readiness writers get (`jobs/test_1471_readiness_*`); the unknown-suffix control (a run id with an unknown suffix) shows the
listing does refuse a folder holding a record it does not know."""
from __future__ import annotations

import uuid

import pytest

from .test_container_entry import _enter, forge  # noqa: F401 — the entry driver and its forge fixture


def _listed(repo) -> list[str]:
    return [str(r) for r in repo[0].runs_repository().list()]


@pytest.mark.parametrize("outcome", ["opened", "failed-delivery", "failed-handover"])
def test_a_runs_folder_holding_the_adoption_record_still_lists(repo, forge, tmp_path, outcome):  # noqa: F811
    """After the container's outcome (opened or a failure, sent as its `result`), the tenant's runs listing succeeds and names
    no run for it. (R13-1.7; #1546: the `silent` arm went with the file, `failed-handover` is facts of another kind)"""
    if outcome == "failed-delivery":
        forge.protection = {**forge.protection, "protected": False}
    other_kind = (lambda facts: {**facts, "kind": "readiness"}) if outcome == "failed-handover" else None
    record = _enter(repo, forge, tmp_path, facts=other_kind)
    assert record is not None, "premise: the container sent its result"
    assert record["outcome"] == ("opened" if outcome == "opened" else "failed")
    assert _listed(repo) == [], "the runs listing refuses, or lists, the adoption record"

    from defender.tests.support.shared._locations_1210 import location_path

    stray = location_path(repo[0].tenant_root) / "runs" / f"{uuid.uuid4()}.unknown.json"
    stray.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception, match="unknown.json"):  # noqa: PT011 — the listing's own sentence names the file
        _listed(repo)
