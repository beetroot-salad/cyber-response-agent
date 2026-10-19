from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender import _episode_handle as EH
from defender import _provenance
from defender._episode_handle import Episode
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.branch import test_976_family_anchor as A
from defender.tests.tenancy import test_1204_knowledge_revision as R
from defender.tests.support.shared.contracts._data_root_1078 import FIXTURE


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots inside `tmp_path`, as every launcher suite sets them."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def _cli():
    return T.mod("learning.branch.cli")


K = T.KNOWLEDGE_SHA
K2 = T.OTHER_KNOWLEDGE_SHA
K3 = "1204" + "f" * 36

#: Two unavailable reasons whose TEXT differs — `capture_knowledge`'s two commonest.
UNAVAILABLE_REFTABLE = {"unavailable": "reftable refs: this reader reads files-backend refs only"}
UNAVAILABLE_UNBORN = {"unavailable": "unborn branch: HEAD names refs/heads/main, which is nowhere"}

UNPROVABLE: dict[str, Any] = {
    "absent": T.NO_KNOWLEDGE_KEY,
    "null": None,
    "unversioned": "unversioned",
    "unavailable": UNAVAILABLE_REFTABLE,
}

#: Text each unprovable shape's fault names, beyond the word "knowledge" — `None` where the
#: shape carries nothing to quote.
UNPROVABLE_SAYS: dict[str, str | None] = {
    "absent": None, "null": None, "unversioned": "unversioned",
    "unavailable": UNAVAILABLE_REFTABLE["unavailable"],
}


def _verify(tmp_path: Path, name: str, *, source: dict,
            siblings: dict[str, dict] | None = None,
            allow_dirty: bool = False, reverse: bool = False) -> tuple[dict, dict | None]:
    """`verify_family` over three REAL sibling stamp files (`T.sibling_run_dir`, each with the
    overrides `siblings[label]` names) against `source`."""
    ep = T.episode(tmp_path, root=tmp_path / "episodes" / name)
    for w in T.WORLDS:
        T.sibling_run_dir(ep / "runs", w, **(siblings or {}).get(w, {}))
    labels = list(reversed(T.WORLDS)) if reverse else list(T.WORLDS)
    with Episode.open(ep) as episode:
        report = _cli().verify_family(episode, T.family_arms(episode, labels), source=source,
                                      allow_dirty=allow_dirty)
    assert not (ep / "outcome.yaml").exists(), "verify wrote the outcome record pre-flight owns"
    stamp_path = ep / "provenance.json"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8")) if stamp_path.exists() else None
    assert (stamp is not None) is report["comparable"], report
    return report, stamp


def _never_called_dirt(text: str) -> None:
    """A refusal whose faults are ALL about knowledge (every stamp in these scenarios is
    clean) never describes itself, or what `--allow-dirty` would waive, as dirt."""
    assert "dirt" not in text.replace("allow-dirty", ""), text


def _incomplete(report: dict, *phrases: str, waivable: bool) -> str:
    """The family was refused for its knowledge."""
    assert report["comparable"] is False, report
    reason = report["reason"]
    assert "knowledge" in reason, reason
    for phrase in phrases:
        assert phrase in reason, (phrase, reason)
    assert ("allow-dirty" in reason) is waivable, reason
    _never_called_dirt(reason)
    return reason


def test_1204_a_family_on_the_sources_knowledge_commit_is_accepted_and_stamped_with_it(
        tmp_path):
    """O2's positive control at the authority tier."""
    report, stamp = _verify(tmp_path, "same", source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["source"]["knowledge"] == {"commit": K}
    assert stamp["agreed"]["knowledge"] == {"commit": K}
    assert stamp["allow_dirty"] is False


def test_1204_siblings_on_another_knowledge_commit_are_incomplete_even_with_the_override(
        tmp_path):
    """O2/A2."""
    on_k2 = {w: {"knowledge": {"commit": K2}} for w in T.WORLDS}
    for allow_dirty in (False, True):
        report, _ = _verify(tmp_path, f"moved-{allow_dirty}".lower(),
                                      source=T.provenance_record(), siblings=on_k2,
                                      allow_dirty=allow_dirty)
        _incomplete(report, K, K2, waivable=False)

    report, stamp = _verify(
        tmp_path, "anchored-k2", source=T.provenance_record(knowledge={"commit": K2}),
        siblings=on_k2)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["source"]["knowledge"] == {"commit": K2}


def test_1204_siblings_off_the_sources_knowledge_are_each_named_against_the_source(tmp_path):
    """O2/D4."""
    report, _ = _verify(
        tmp_path, "two-off", source=T.provenance_record(),
        siblings={"b": {"knowledge": {"commit": K2}}, "c": {"knowledge": {"commit": K3}}})
    reason = _incomplete(report, K2, K3, waivable=False)
    assert "siblings disagree on knowledge" not in reason, reason


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_siblings_disagreeing_on_knowledge_are_incomplete_even_with_the_override(
        tmp_path, shape):
    """O2/A2."""
    source = T.provenance_record(knowledge=UNPROVABLE[shape])
    for allow_dirty in (True, False):
        report, _ = _verify(
            tmp_path, f"split-{shape}-{allow_dirty}".lower(), source=source,
            siblings={"b": {"knowledge": {"commit": K2}}}, allow_dirty=allow_dirty)
        _incomplete(report, K, K2, waivable=False)

    report, stamp = _verify(tmp_path, f"agree-{shape}", source=source,
                                      allow_dirty=True)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["agreed"]["knowledge"] == {"commit": K}
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_source_whose_knowledge_is_unprovable_is_waivable(tmp_path, shape):
    """O2/A2."""
    source = T.provenance_record(knowledge=UNPROVABLE[shape])
    says = UNPROVABLE_SAYS[shape]
    report, _ = _verify(tmp_path, f"src-{shape}", source=source)
    _incomplete(report, "source", *([says] if says else []), waivable=True)

    report, stamp = _verify(tmp_path, f"src-{shape}-waived", source=source,
                                      allow_dirty=True)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_sibling_whose_knowledge_is_unprovable_is_waivable(tmp_path, shape):
    """O2/A2, the member side."""
    siblings = {"b": {"knowledge": UNPROVABLE[shape]}}
    says = UNPROVABLE_SAYS[shape]
    report, _ = _verify(tmp_path, f"sib-{shape}", source=T.provenance_record(),
                                  siblings=siblings)
    reason = _incomplete(report, "'b'", *([says] if says else []), waivable=True)
    assert "disagree" not in reason, reason

    report, stamp = _verify(tmp_path, f"sib-{shape}-waived",
                                      source=T.provenance_record(), siblings=siblings,
                                      allow_dirty=True)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["source"]["knowledge"] == {"commit": K}


def test_1204_two_unavailable_reasons_are_not_a_knowledge_disagreement(tmp_path):
    """A2/D4."""
    no_commit = {"a": {"knowledge": UNAVAILABLE_REFTABLE},
                 "b": {"knowledge": UNAVAILABLE_UNBORN}, "c": {"knowledge": "unversioned"}}
    beside_k = {"b": {"knowledge": UNAVAILABLE_UNBORN}, "c": {"knowledge": "unversioned"}}
    for name, source, mixed in (
            ("on-k", T.provenance_record(), no_commit),
            ("unavailable", T.provenance_record(knowledge=UNAVAILABLE_UNBORN), no_commit),
            ("absent", T.provenance_record(knowledge=T.NO_KNOWLEDGE_KEY), beside_k)):
        report, _ = _verify(tmp_path, f"reasons-{name}", source=source,
                                      siblings=mixed)
        reason = _incomplete(report, waivable=True)
        assert "disagree" not in reason, reason

        report, stamp = _verify(tmp_path, f"reasons-{name}-waived", source=source,
                                          siblings=mixed, allow_dirty=True)
        assert report["comparable"] is True, report["reason"]
        assert stamp is not None


def test_1204_a_launch_whose_live_knowledge_matches_the_source_is_accepted(tmp_path):
    launch = A._prepare(tmp_path)
    stamp = A._accepted(launch)
    assert launch.live_tree.calls == 1
    assert stamp["source"]["knowledge"] == {"commit": K}
    assert stamp["agreed"]["knowledge"] == {"commit": K}
    assert stamp["waived"] == [], "nothing was waived, and the flag was not given"


def test_1204_a_live_tenant_clone_on_another_knowledge_commit_is_refused_and_never_waived(
        tmp_path):
    """O2/A2 at preflight."""
    for argv in ((), ("--allow-dirty",)):
        launch = A._prepare(tmp_path, live_tree=T.source_capture(knowledge={"commit": K2}))
        message = A._refused_before_spending(launch, *argv)
        A._never_waivable(message, "live tree", "knowledge", K2, K)
        assert launch.live_tree.calls == 1


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_live_capture_whose_knowledge_is_unprovable_is_waivable(tmp_path, shape):
    capture = {"knowledge": UNPROVABLE[shape]}
    launch = A._prepare(tmp_path, live_tree=T.source_capture(**capture))
    message = A._refused_before_spending(launch)
    A._waivable(message, "live tree", "knowledge")
    _never_called_dirt(message)

    waived = A._prepare(tmp_path, live_tree=T.source_capture(**capture))
    stamp = A._accepted(waived, "--allow-dirty")
    assert waived.live_tree.calls == 1
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_source_whose_knowledge_is_unprovable_is_refused_at_preflight_unless_waived(
        tmp_path, shape):
    """O2/A2 at preflight, the source side."""
    launch = A._prepare(tmp_path)
    A._restamp(launch.src, knowledge=UNPROVABLE[shape])
    message = A._refused_before_spending(launch)
    A._waivable(message, "source", "knowledge")
    _never_called_dirt(message)

    waived = A._prepare(tmp_path)
    A._restamp(waived.src, knowledge=UNPROVABLE[shape])
    stamp = A._accepted(waived, "--allow-dirty")
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("argv", [(), ("--allow-dirty",)], ids=["plain", "allow-dirty"])
def test_1204_a_launch_whose_siblings_read_another_knowledge_commit_ends_incomplete(
        tmp_path, argv, caplog):
    """O2 end to end, the authority tier."""
    T.runs_base(tmp_path)
    episode_dir = EH.episode_dir(T.current_tenant().data_root, T.EPISODE_ID)
    launch = A._prepare(tmp_path, spawn=J.FakeSibling(episode_dir, knowledge={"commit": K2}))
    assert launch.run(*argv) == 0, "the exit is about the launch; the outcome is the family's"
    assert launch.questioner.calls > 0, "the launch was refused at preflight instead"
    assert sorted(launch.spawn.worlds) == list(T.WORLDS)
    assert A._outcome(launch.episode_dir)["outcome"] == "accepted"
    reason = A._withheld_reason(caplog)
    assert "knowledge" in reason, reason
    assert K2 in reason, reason
    assert "allow-dirty" not in reason, reason
    assert not (launch.episode_dir / "provenance.json").exists()


WAIVED: dict[str, tuple[dict, dict[str, dict], bool, list[str]]] = {
    "clean-flag-off": (T.provenance_record(), {}, False, []),
    "clean-flag-on": (T.provenance_record(), {}, True, []),
    "dirty-sibling": (T.provenance_record(), {"b": {"dirty": True}}, True, ["dirt"]),
    "unknown-tree-sibling": (
        T.provenance_record(), {"c": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED}},
        True, ["dirt"]),
    "dirty-source": (T.provenance_record(dirty=True), {}, True, ["dirt"]),
    "pre-1204-source": (T.provenance_record(knowledge=T.NO_KNOWLEDGE_KEY), {}, True,
                        ["knowledge"]),
    "unversioned-sibling": (T.provenance_record(), {"b": {"knowledge": "unversioned"}}, True,
                            ["knowledge"]),
    "unavailable-source": (T.provenance_record(knowledge=UNAVAILABLE_REFTABLE), {}, True,
                           ["knowledge"]),
    "both": (T.provenance_record(knowledge=T.NO_KNOWLEDGE_KEY), {"b": {"dirty": True}}, True,
             ["dirt", "knowledge"]),
}


@pytest.mark.parametrize("case", sorted(WAIVED))
def test_1204_the_family_stamp_records_which_fault_kinds_the_override_waived(tmp_path, case):
    """Review fix (faults carry their kind)."""
    source, siblings, flag, waived = WAIVED[case]
    report, stamp = _verify(tmp_path, f"waived-{case}", source=source,
                                      siblings=siblings, allow_dirty=flag)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["waived"] == waived, stamp.get("waived")
    assert stamp["allow_dirty"] is flag


@pytest.mark.parametrize("dirty_source", [False, True], ids=["clean-code", "dirty-code"])
def test_1204_a_launch_that_waives_a_pre_1204_sources_knowledge_records_it_as_knowledge(
        tmp_path, dirty_source):
    """The same record end to end through the launcher."""
    launch = A._prepare(tmp_path)
    A._restamp(launch.src, knowledge=T.NO_KNOWLEDGE_KEY, dirty=dirty_source)
    stamp = A._accepted(launch, "--allow-dirty")
    assert stamp["waived"] == (["dirt", "knowledge"] if dirty_source else ["knowledge"])
    assert stamp["source"]["dirty"] is dirty_source
    assert stamp["allow_dirty"] is True
    assert stamp["agreed"]["knowledge"] == {"commit": K}


#: Siblings that name no knowledge commit, in the FIRST position (`a` is handed over first).
NO_COMMIT_FIRST: dict[str, dict[str, dict]] = {
    "unversioned": {"a": {"knowledge": "unversioned"}},
    "unavailable": {"a": {"knowledge": UNAVAILABLE_REFTABLE}},
    "absent": {"a": {"knowledge": T.NO_KNOWLEDGE_KEY}, "b": {"knowledge": None}},
}


@pytest.mark.parametrize("reverse", [False, True], ids=["unprovable-first", "unprovable-last"])
@pytest.mark.parametrize("shape", sorted(NO_COMMIT_FIRST))
def test_1204_agreed_knowledge_is_the_commit_the_check_held_not_the_first_siblings(
        tmp_path, shape, reverse):
    """Review fix (the agreed record)."""
    report, stamp = _verify(
        tmp_path, f"agreed-{shape}-{reverse}".lower(), source=T.provenance_record(),
        siblings=NO_COMMIT_FIRST[shape], allow_dirty=True, reverse=reverse)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert stamp["agreed"]["knowledge"] == {"commit": K}, stamp["agreed"]
    assert stamp["waived"] == ["knowledge"]
    assert (stamp["agreed"]["commit"], stamp["agreed"]["scope"], stamp["agreed"]["model"]) == (
        "deadbee", "repo", "m-1")


@pytest.mark.parametrize("source_shape", ["on-k", "absent"])
def test_1204_agreed_knowledge_is_null_when_no_sibling_names_a_commit(tmp_path, source_shape):
    """Review fix (the agreed record), the other half."""
    source = (T.provenance_record() if source_shape == "on-k"
              else T.provenance_record(knowledge=T.NO_KNOWLEDGE_KEY))
    siblings = {"a": {"knowledge": "unversioned"}, "b": {"knowledge": UNAVAILABLE_REFTABLE},
                "c": {"knowledge": T.NO_KNOWLEDGE_KEY}}
    report, stamp = _verify(tmp_path, f"no-agreed-{source_shape}", source=source,
                                      siblings=siblings, allow_dirty=True)
    assert report["comparable"] is True, report["reason"]
    assert stamp is not None
    assert "knowledge" in stamp["agreed"], stamp["agreed"]
    assert stamp["agreed"]["knowledge"] is None, stamp["agreed"]
    assert stamp["waived"] == ["knowledge"]


def _versioned_tenant_knowledge() -> str:
    """Place the episode tenant's knowledge folder as a real git repo (the committed fixture,
    committed) BEFORE `A._prepare` sets the tenant up — the tenant set-up then keeps it and
    the real `accept_tenant` admits it (C10). Returns its HEAD. The episode tenant is the
    fixture tenant `A._prepare`'s source run belongs to (#1224's live-oracle estate)."""
    tenant_id = A.S.FIXTURE_TENANT
    knowledge = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant_id / "knowledge"
    shutil.copytree(FIXTURE, knowledge, symlinks=True)
    (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    R._repo(knowledge)
    return R._head(knowledge)


def test_1204_the_default_live_capture_reads_the_episode_tenants_knowledge_clone(tmp_path):
    """D3."""
    from defender import run_common

    code = _provenance.capture_tree(run_common.REPO_ROOT)
    if not code.commit:
        pytest.skip("no git answers for this checkout here, so the default live capture names "
                    "no code commit and the member comparison never reaches knowledge")
    live = _versioned_tenant_knowledge()
    assert live not in (K, K2)

    mismatched = A._prepare(tmp_path)
    mismatched.live_tree = None
    A._restamp(mismatched.src, knowledge={"commit": K2})
    message = A._refused_before_spending(mismatched)
    assert "live tree is at commit" in message, message
    for phrase in ("knowledge", live, K2):
        assert phrase in message, (phrase, message)

    matched = A._prepare(tmp_path)
    matched.live_tree = None
    A._restamp(matched.src, knowledge={"commit": live})
    message = A._refused_before_spending(matched)
    assert "live tree is at commit" in message, message
    assert "knowledge" not in message, message


#: D4's classification, as the design states it.
D4 = {
    "commit": "anchored", "scope": "anchored", "knowledge": "anchored",
    "model": "constant",
    "dirty": "dedicated", "tenant_id": "dedicated",
    "dirty_paths": "informational", "dirty_path_count": "informational",
    "unavailable": "informational",
    "world_id": "expected_to_differ", "parent_run_id": "expected_to_differ",
    "fork_turn": "expected_to_differ",
}
CLASSES = {"anchored", "constant", "dedicated", "informational", "expected_to_differ"}

#: For each field the comparison must hold constant, a value one sibling can carry that differs
#: from the source's (`T.provenance_record()`) and is still a record a capture can produce.
DIFFERENT: dict[str, Any] = {
    "commit": "cafe1", "scope": "defender", "model": "m-2", "knowledge": {"commit": K2},
}


def _table() -> dict[str, str]:
    return T.sym("learning.branch.cli", "STAMP_FIELD_CLASSES")


def test_1204_each_anchored_and_constant_field_is_compared_through_verify_family(tmp_path):
    """O3 behavioural arm."""
    table = _table()
    compared = sorted(f for f, c in table.items() if c in ("anchored", "constant"))
    assert compared == sorted(DIFFERENT), (
        f"a compared field has no differing value to test it with: {set(compared) ^ set(DIFFERENT)}")
    for field in compared:
        for allow_dirty in (False, True):
            report, stamp = _verify(
                tmp_path, f"{field}-{allow_dirty}".lower(), source=T.provenance_record(),
                siblings={"b": {field: DIFFERENT[field]}}, allow_dirty=allow_dirty)
            assert report["comparable"] is False, (field, allow_dirty, report["reason"])
            assert field in report["reason"], (field, report["reason"])
            assert "allow-dirty" not in report["reason"], (field, report["reason"])
            assert stamp is None

    report, stamp = _verify(tmp_path, "none-differs", source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]


def test_1204_fields_expected_to_differ_or_informational_are_not_compared(tmp_path):
    """O3/D4, the other half."""
    ep = T.episode(tmp_path, root=tmp_path / "episodes" / "lineage")
    dirs = [T.sibling_run_dir(ep / "runs", w) for w in T.WORLDS]
    for turn, d in enumerate(dirs, start=1):
        doc = {**T.provenance_record(), "world_id": f"{T.EPISODE_ID}.{d.name[-1]}",
               "parent_run_id": f"source-{turn}", "fork_turn": turn}
        (d / "provenance.json").write_text(json.dumps(doc), encoding="utf-8")
    with Episode.open(ep) as episode:
        report = _cli().verify_family(episode, T.family_arms(episode, T.WORLDS),
                                      source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]

    report, _ = _verify(
        tmp_path, "dirt-differs", source=T.provenance_record(), allow_dirty=True,
        siblings={"b": {"dirty": True},
                  "c": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED}})
    assert report["comparable"] is True, report["reason"]
