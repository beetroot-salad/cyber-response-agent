"""#1471 R13-1.7: every record the adoption container writes into `<T>/runs` is one the tenant's runs listing serves (its suffix is an accepted
sidecar), whatever the outcome. The same check the readiness writers get (`jobs/test_1471_readiness_*`); the stray-suffix control shows the
listing does refuse a folder holding a record it does not know."""
from __future__ import annotations

import pytest

from .test_container_entry import _enter, forge  # noqa: F401 — the entry driver and its forge fixture


def _listed(repo) -> list[str]:
    return [str(r) for r in repo[0].runs_repository().list()]


@pytest.mark.parametrize("outcome", ["opened", "failed-delivery", "failed-handover"])
def test_a_runs_folder_holding_the_adoption_record_still_lists(repo, forge, tmp_path, outcome):  # noqa: F811
    """After the container writes its `.adoption.json` (an outcome or a failure), the tenant's runs listing succeeds and names no run for it. (R13-1.7)"""
    if outcome == "failed-delivery":
        forge.protection = {**forge.protection, "protected": False}
    record = _enter(repo, forge, tmp_path, silent=outcome == "failed-handover", facts=None)
    assert record is not None, "premise: the container wrote its record"
    assert record["outcome"] == ("opened" if outcome == "opened" else "failed")
    assert _listed(repo) == [], "the runs listing refuses, or lists, the adoption record"

    from defender.tests.support.shared._locations_1210 import location_path

    stray = location_path(repo[0].tenant_root) / "runs" / "stray.unknown.json"
    stray.write_text("{}", encoding="utf-8")
    with pytest.raises(Exception, match="stray"):  # noqa: PT011 — the listing's own sentence names the file
        _listed(repo)
