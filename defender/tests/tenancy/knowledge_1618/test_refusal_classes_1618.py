"""#1618 D11: the fetch child's refusal line carries `transient` or `lasting` and a reason, never `misconfigured`, `stale` or `operator`."""
from __future__ import annotations

import pytest

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



def test_d11_a_tenant_the_child_does_not_accept_is_refused_lasting_naming_why(t, tmp_path):
    """A tenant id the child cannot accept (no such tenant under the data root) carries no class of its own: the child
    reports it `refused lasting <reason>` (a retry changes nothing), exit 0, and writes nothing. (D11, K4)"""
    import uuid
    from types import SimpleNamespace

    unknown = str(uuid.uuid4())
    dest = _dest(tmp_path)
    report = K.child_report(SimpleNamespace(tenant_id=unknown, origin=t.origin, data_root=t.data_root), tmp_path, dest)
    assert (report.rc, report.word) == (0, "refused"), report
    assert (report.klass, bool(report.reason)) == ("lasting", True), report.line
    assert "not accepted" in report.reason, report.line
    assert not [w for w in RETIRED_WORDS if w in report.line.lower()], report.line
    assert not any(dest.iterdir())


#: Spellings of the seed commit that are not the full lowercase id the records hold: git would resolve either.
_NOT_FULL = {"abbreviated": lambda commit: commit[:12], "uppercase": str.upper}


@pytest.mark.parametrize("spelling", sorted(_NOT_FULL))
def test_d11_a_commit_that_is_not_a_full_id_is_refused_lasting_naming_it_without_asking_forgejo(t, tmp_path, spelling):
    """A pin that is not a full lowercase commit id (an abbreviation, an uppercase spelling, either of which git would
    resolve) is refused by the child itself, `refused lasting`, naming the id, exit 0: no request reaches Forgejo's git
    listener. Control: the full id is fetched. (D11, K5)"""
    short = _NOT_FULL[spelling](t.commit)
    before = len(t.server.seen)
    report = K.child_report(t, tmp_path, _dest(tmp_path), commit=short)
    assert (report.rc, report.word) == (0, "refused"), report
    assert report.klass == "lasting", report.line
    assert short in report.reason, report.line
    assert len(t.server.seen) == before, f"a malformed id reached Forgejo: {t.server.seen[before:]}"
    full = K.child_report(t, tmp_path, _dest(tmp_path / "control"), commit=t.commit)
    assert (full.word, full.commit) == ("ok", t.commit), "control: the full id is fetched"
