"""#1618 D11: the fetch child's refusal line carries `transient` or `lasting` and a reason, never `misconfigured`, `stale` or `operator`."""
from __future__ import annotations

from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4._support import OTHER_TENANT_ID

RETIRED_WORDS = ("misconfigured", "stale", "operator")


def _dest(tmp_path):
    return K.owned_dest(tmp_path / "run-knowledge")


def test_d11_a_fetch_that_validates_answers_ok_with_the_commit_and_no_class_word(t, tmp_path):
    """Control: main fetched and valid answers `ok <commit>`, no refusal class on the line. (D11)"""
    report = K.child_report(t, tmp_path, _dest(tmp_path))
    assert (report.rc, report.word, report.commit) == (0, "ok", t.commit), report


def test_d11_forgejo_unreachable_is_refused_transient_with_a_reason(t, tmp_path):
    """Forgejo refusing the connection is `refused transient <reason>`: the outage the drains wait out, none of the retired words. (D11, K9)"""
    K.forge_down(t)
    report = K.child_report(t, tmp_path, _dest(tmp_path))
    assert report.word == "refused", report
    assert (report.klass, bool(report.reason)) == ("transient", True), report.line
    assert not [w for w in RETIRED_WORDS if w in report.line.lower()], report.line


def test_d11_a_merged_tenant_id_naming_another_tenant_is_refused_lasting_with_a_reason(t, tmp_path):
    """Content that will not validate is `refused lasting <reason>` (a retry changes nothing), none of the retired words. (D11, K6, K9)"""
    t.merge({"agent/.tenant-id": f"{OTHER_TENANT_ID}\n"})
    dest = _dest(tmp_path)
    report = K.child_report(t, tmp_path, dest)
    assert report.word == "refused", report
    assert (report.klass, bool(report.reason)) == ("lasting", True), report.line
    assert not [w for w in RETIRED_WORDS if w in report.line.lower()], report.line
    assert not any(dest.iterdir()), "a refused copy left files in the caller's folder"

