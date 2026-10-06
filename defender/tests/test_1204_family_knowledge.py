"""#1204 — a fork family is not certified comparable across two tenant knowledge commits (O2,
O3, D3, D4).

A branched family (#947) forks one SOURCE run into siblings that must differ only in the one
axis the questioner declared. #976 anchored the family to the source's PRODUCT commit; since
runs read the tenant's own knowledge clone (settings today, lessons after #1108), a family
whose siblings read a different knowledge commit than the source is the same confound. The
fork check therefore compares the knowledge commit, at both tiers:

* **Preflight** (`cli.main` -> `preflight_episode`): the source's stamp against the launcher's
  live capture, which in production reads the episode tenant's clone (D3).
* **Verify** (`verify_family(..., source=)`): every sibling's own stamp against the source,
  and the siblings against each other.

A2, as settled: a member (sibling or live tree) whose knowledge commit DIFFERS from the
source's, or siblings that disagree among themselves, is NEVER waivable. Knowledge that is
`"unversioned"`, unavailable, or ABSENT (a pre-#1204 stamp) on either side is WAIVABLE with
`--allow-dirty` ("nothing proves the same knowledge"). Comparison is over the COMMIT only — two
unavailable reasons with different text are not a disagreement.

O3 / D4 — THE NAME CONTRACT for the field table: `defender.learning.branch.cli` holds a
module-level `STAMP_FIELD_CLASSES: dict[str, str]` from every `RunProvenance` field name to one
class among `"anchored"` (commit, scope, knowledge), `"constant"` (model), `"dedicated"`
(dirty, tenant_id), `"informational"` (dirty_paths, dirty_path_count, unavailable) and
`"expected_to_differ"` (world_id, parent_run_id, fork_turn). It drives the comparison that
replaces the hardcoded `("commit", "scope", "model")` loop. The wire value of knowledge is
`{"commit": "<sha>"}` | `"unversioned"` | `{"unavailable": "<reason>"}` | `null`
(`test_1204_knowledge_revision.py` pins it).

Fixtures: every fake stamp is `T.provenance_record(...)`, which by default carries
`{"commit": T.KNOWLEDGE_SHA}` — the source `T.runs_base` writes, every `T.sibling_run_dir` /
`J.FakeSibling` sibling and the `T.source_capture()` live capture all agree on it, as a real
family launched from one tenant clone does. `knowledge=T.NO_KNOWLEDGE_KEY` is a pre-#1204
stamp. Every fake enters by an injection seam (never `monkeypatch.setattr`); the launcher
scenarios reuse #976's `Launch` harness.

RED before #1204: no `STAMP_FIELD_CLASSES`, no knowledge comparison, no knowledge in the
read-back stamps.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender import _provenance
from defender._episode_handle import Episode
from defender._provenance import RunProvenance
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_976_family_anchor as A
from defender.tests import test_1204_knowledge_revision as R
from defender.tests._data_root_1078 import FIXTURE


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots inside `tmp_path`, as every launcher suite sets them."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _cli():
    return T.mod("learning.branch.cli")


K = T.KNOWLEDGE_SHA
K2 = T.OTHER_KNOWLEDGE_SHA
K3 = "1204" + "f" * 36

#: Two unavailable reasons whose TEXT differs — `capture_knowledge`'s two commonest.
UNAVAILABLE_REFTABLE = {"unavailable": "reftable refs: this reader reads files-backend refs only"}
UNAVAILABLE_UNBORN = {"unavailable": "unborn branch: HEAD names refs/heads/main, which is nowhere"}

#: A2's waivable shapes: nothing proves the same knowledge. `absent` is a stamp written before
#: #1204 (no key); `null` is a record that does not say (what `as_json` writes for `None`, and
#: what a malformed value read back folds to).
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
            allow_dirty: bool = False) -> tuple[dict, dict, dict | None]:
    """`verify_family` over three REAL sibling stamp files (`T.sibling_run_dir`, each with the
    overrides `siblings[label]` names) against `source`. Returns the report, the RECORDED
    episode outcome (`review.yaml`), and the family stamp (`None` when none was written)."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base / name, w, **(siblings or {}).get(w, {})) for w in T.WORLDS]
    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}")
    with Episode.open(ep) as episode:
        report = _cli().verify_family(episode, dirs, source=source, allow_dirty=allow_dirty)
    recorded = T.review_doc(ep)["episode"]
    assert recorded["outcome"] == report["outcome"], (recorded, report)
    stamp_path = ep / "provenance.json"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8")) if stamp_path.exists() else None
    assert (stamp is not None) is (report["outcome"] == "accepted"), report
    return report, recorded, stamp


def _incomplete(report: dict, recorded: dict, *phrases: str, waivable: bool) -> str:
    """The family was refused for its knowledge: `incomplete`, with the recorded reason naming
    knowledge and each phrase, and offering `--allow-dirty` exactly when passing it would let
    the family through (the message rule `_family_refusal` holds every fault to)."""
    assert report["outcome"] == "incomplete", report
    reason = recorded["reason"]
    assert reason == report["reason"]
    assert "knowledge" in reason, reason
    for phrase in phrases:
        assert phrase in reason, (phrase, reason)
    assert ("allow-dirty" in reason) is waivable, reason
    return reason


# ---------------------------------------------------------------------------------------
# O2 — verify tier: the siblings' own stamps against the source, and against each other
# ---------------------------------------------------------------------------------------


def test_1204_a_family_on_the_sources_knowledge_commit_is_accepted_and_stamped_with_it(
        tmp_path):
    """O2's positive control at the authority tier: source and every sibling on one knowledge
    commit is `accepted`, and the family stamp says which — `source.knowledge` is the source's
    and `agreed.knowledge` the siblings', both `{"commit": K}`. Every refusal below is only
    meaningful beside this."""
    report, recorded, stamp = _verify(tmp_path, "same", source=T.provenance_record())
    assert recorded["outcome"] == "accepted", report["reason"]
    assert stamp is not None
    assert stamp["source"]["knowledge"] == {"commit": K}
    assert stamp["agreed"]["knowledge"] == {"commit": K}
    assert stamp["allow_dirty"] is False


def test_1204_siblings_on_another_knowledge_commit_are_incomplete_even_with_the_override(
        tmp_path):
    """O2/A2: siblings that agree with each other on knowledge commit K2 while the source read
    K are not a comparable family — `incomplete`, naming knowledge and both commits, with and
    without `--allow-dirty` (a knowledge mismatch is a confound, not dirt, so the flag is not
    offered). The positive control anchors the same siblings to a K2 source. Without this two
    knowledge commits — different settings, different lessons — archive as one family."""
    on_k2 = {w: {"knowledge": {"commit": K2}} for w in T.WORLDS}
    for allow_dirty in (False, True):
        report, recorded, _ = _verify(tmp_path, f"moved-{allow_dirty}".lower(),
                                      source=T.provenance_record(), siblings=on_k2,
                                      allow_dirty=allow_dirty)
        _incomplete(report, recorded, K, K2, waivable=False)

    report, recorded, stamp = _verify(
        tmp_path, "anchored-k2", source=T.provenance_record(knowledge={"commit": K2}),
        siblings=on_k2)
    assert recorded["outcome"] == "accepted", report["reason"]
    assert stamp is not None
    assert stamp["source"]["knowledge"] == {"commit": K2}


def test_1204_siblings_off_the_sources_knowledge_are_each_named_against_the_source(tmp_path):
    """O2/D4: knowledge is ANCHORED to the source like the code commit, so two siblings on two
    other knowledge commits are each named against the source — and not ALSO as a sibling
    disagreement, which the anchor faults already said (#976's one-fact-once rule). The third
    sibling, on the source's commit, is not named."""
    report, recorded, _ = _verify(
        tmp_path, "two-off", source=T.provenance_record(),
        siblings={"b": {"knowledge": {"commit": K2}}, "c": {"knowledge": {"commit": K3}}})
    reason = _incomplete(report, recorded, K2, K3, waivable=False)
    assert "siblings disagree on knowledge" not in reason, reason


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_siblings_disagreeing_on_knowledge_are_incomplete_even_with_the_override(
        tmp_path, shape):
    """O2/A2: with the source's knowledge unprovable (so the source anchors nothing and its own
    fault is waived by the flag), siblings that disagree among THEMSELVES — a and c on K, b on
    K2 — are still `incomplete` under `--allow-dirty`: the disagreement is the only fault left,
    and it is never waivable. The positive control is the same source with all three siblings
    on K, accepted under the flag. Without this a family whose source predates #1204 could mix
    knowledge commits freely."""
    source = T.provenance_record(knowledge=UNPROVABLE[shape])
    for allow_dirty in (True, False):
        report, recorded, _ = _verify(
            tmp_path, f"split-{shape}-{allow_dirty}".lower(), source=source,
            siblings={"b": {"knowledge": {"commit": K2}}}, allow_dirty=allow_dirty)
        _incomplete(report, recorded, K, K2, waivable=False)

    report, recorded, stamp = _verify(tmp_path, f"agree-{shape}", source=source,
                                      allow_dirty=True)
    assert recorded["outcome"] == "accepted", report["reason"]
    assert stamp is not None
    assert stamp["agreed"]["knowledge"] == {"commit": K}
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_source_whose_knowledge_is_unprovable_is_waivable(tmp_path, shape):
    """O2/A2: a source stamped before #1204 (absent), with `null`, `"unversioned"` or an
    unavailable reason cannot prove its siblings read the same knowledge: `incomplete` without
    `--allow-dirty` — the reason names knowledge (and the shape's own words) and offers the flag
    — and `accepted` with it, the family stamp recording the waiver. Absent MUST be waivable,
    or every pre-#1204 run becomes permanently unforkable."""
    source = T.provenance_record(knowledge=UNPROVABLE[shape])
    says = UNPROVABLE_SAYS[shape]
    report, recorded, _ = _verify(tmp_path, f"src-{shape}", source=source)
    _incomplete(report, recorded, "source", *([says] if says else []), waivable=True)

    report, recorded, stamp = _verify(tmp_path, f"src-{shape}-waived", source=source,
                                      allow_dirty=True)
    assert recorded["outcome"] == "accepted", report["reason"]
    assert stamp is not None
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_sibling_whose_knowledge_is_unprovable_is_waivable(tmp_path, shape):
    """O2/A2, the member side: source and siblings a, c on K, sibling b's knowledge unprovable.
    `incomplete` without the flag — naming knowledge and sibling b, offering the flag — and
    `accepted` with it. An unprovable sibling drops out of the knowledge agreement rather than
    counting as a disagreeing value. Without this either every sibling stamped on a git-less
    tenant blocks its family for good, or one is silently accepted."""
    siblings = {"b": {"knowledge": UNPROVABLE[shape]}}
    says = UNPROVABLE_SAYS[shape]
    report, recorded, _ = _verify(tmp_path, f"sib-{shape}", source=T.provenance_record(),
                                  siblings=siblings)
    reason = _incomplete(report, recorded, "'b'", *([says] if says else []), waivable=True)
    assert "disagree" not in reason, reason

    report, recorded, stamp = _verify(tmp_path, f"sib-{shape}-waived",
                                      source=T.provenance_record(), siblings=siblings,
                                      allow_dirty=True)
    assert recorded["outcome"] == "accepted", report["reason"]
    assert stamp is not None
    assert stamp["source"]["knowledge"] == {"commit": K}


def test_1204_two_unavailable_reasons_are_not_a_knowledge_disagreement(tmp_path):
    """A2/D4: the comparison is over the COMMIT only, never the whole knowledge value. Siblings
    whose knowledge is unavailable for two different reasons (or one unavailable, one
    unversioned) disagree on nothing a commit could settle: under the flag the family is
    accepted, and without it the only faults are the waivable ones, so the flag is offered.
    Run against a source on K, a source that is itself unavailable, and a pre-#1204 source
    (which pins nothing, so the siblings' own agreement is the only comparison) with one
    sibling on K beside the two that name no commit — those drop out of the agreement rather
    than counting as values that disagree with K. Without this, differing error text (or an
    unprovable sibling) would make such a family unwaivable."""
    no_commit = {"a": {"knowledge": UNAVAILABLE_REFTABLE},
                 "b": {"knowledge": UNAVAILABLE_UNBORN}, "c": {"knowledge": "unversioned"}}
    beside_k = {"b": {"knowledge": UNAVAILABLE_UNBORN}, "c": {"knowledge": "unversioned"}}
    for name, source, mixed in (
            ("on-k", T.provenance_record(), no_commit),
            ("unavailable", T.provenance_record(knowledge=UNAVAILABLE_UNBORN), no_commit),
            ("absent", T.provenance_record(knowledge=T.NO_KNOWLEDGE_KEY), beside_k)):
        report, recorded, _ = _verify(tmp_path, f"reasons-{name}", source=source,
                                      siblings=mixed)
        reason = _incomplete(report, recorded, waivable=True)
        assert "disagree" not in reason, reason

        report, recorded, stamp = _verify(tmp_path, f"reasons-{name}-waived", source=source,
                                          siblings=mixed, allow_dirty=True)
        assert recorded["outcome"] == "accepted", report["reason"]
        assert stamp is not None


# ---------------------------------------------------------------------------------------
# O2 — preflight tier: the live tenant clone against the source, before anything is spent
# ---------------------------------------------------------------------------------------


def test_1204_a_launch_whose_live_knowledge_matches_the_source_is_accepted(tmp_path):
    """O2's positive control end to end: source, live capture and siblings all on knowledge K —
    the launch exits 0, the live tree was captured once, the family is accepted and its stamp
    carries K on both sides."""
    launch = A._prepare(tmp_path)
    stamp = A._accepted(launch)
    assert launch.live_tree.calls == 1
    assert stamp["source"]["knowledge"] == {"commit": K}
    assert stamp["agreed"]["knowledge"] == {"commit": K}


def test_1204_a_live_tenant_clone_on_another_knowledge_commit_is_refused_and_never_waived(
        tmp_path):
    """O2/A2 at preflight: the launcher's live capture says the tenant clone is at K2 while the
    source ran on K — the family would read other settings and lessons than the source did —
    so the launch refuses before the questioner is paid, with and without `--allow-dirty`,
    naming the live tree, knowledge and both commits, and not offering the flag."""
    for argv in ((), ("--allow-dirty",)):
        launch = A._prepare(tmp_path, live_tree=T.source_capture(knowledge={"commit": K2}))
        message = A._refused_before_spending(launch, *argv)
        A._never_waivable(message, "live tree", "knowledge", K2, K)
        assert launch.live_tree.calls == 1


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_live_capture_whose_knowledge_is_unprovable_is_waivable(tmp_path, shape):
    """O2/A2 at preflight, the member side: the live capture cannot prove the clone's knowledge
    commit (unversioned, unavailable, or no answer). Refused before spending without the flag —
    naming the live tree and knowledge, offering the flag — and accepted end to end with it."""
    capture = {"knowledge": UNPROVABLE[shape]}
    launch = A._prepare(tmp_path, live_tree=T.source_capture(**capture))
    message = A._refused_before_spending(launch)
    A._waivable(message, "live tree", "knowledge")

    waived = A._prepare(tmp_path, live_tree=T.source_capture(**capture))
    stamp = A._accepted(waived, "--allow-dirty")
    assert waived.live_tree.calls == 1
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("shape", sorted(UNPROVABLE))
def test_1204_a_source_whose_knowledge_is_unprovable_is_refused_at_preflight_unless_waived(
        tmp_path, shape):
    """O2/A2 at preflight, the source side: a source with absent, null, unversioned or
    unavailable knowledge refuses before spending without `--allow-dirty` (naming the source
    and knowledge, offering the flag), and with it the launch completes and the family is
    accepted — so every run stamped before #1204 stays forkable."""
    launch = A._prepare(tmp_path)
    T.source_stamp(launch.src, knowledge=UNPROVABLE[shape])
    message = A._refused_before_spending(launch)
    A._waivable(message, "source", "knowledge")

    waived = A._prepare(tmp_path)
    T.source_stamp(waived.src, knowledge=UNPROVABLE[shape])
    stamp = A._accepted(waived, "--allow-dirty")
    assert stamp["allow_dirty"] is True


@pytest.mark.parametrize("argv", [(), ("--allow-dirty",)], ids=["plain", "allow-dirty"])
def test_1204_a_launch_whose_siblings_read_another_knowledge_commit_ends_incomplete(
        tmp_path, argv):
    """O2 end to end, the authority tier: the live clone matches the source (K), so preflight
    passes and the family runs — but every sibling's own stamp says K2, so `verify_family`
    ends the family `incomplete` with no family stamp, with and without `--allow-dirty`. This is
    the pin that the knowledge comparison runs on the siblings' per-process stamps, not only on
    the launcher's capture."""
    T.runs_base(tmp_path)
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID, tenant=T.current_tenant())
    launch = A._prepare(tmp_path, spawn=J.FakeSibling(episode_dir, knowledge={"commit": K2}))
    assert launch.run(*argv) == 0, "the exit is about the launch; the outcome is the family's"
    assert launch.questioner.calls > 0, "the launch was refused at preflight instead"
    assert sorted(launch.spawn.worlds) == list(T.WORLDS)
    record = T.review_doc(launch.episode_dir)["episode"]
    assert record["outcome"] == "incomplete", record
    assert "knowledge" in record["reason"], record["reason"]
    assert K2 in record["reason"], record["reason"]
    assert "allow-dirty" not in record["reason"], record["reason"]
    assert not (launch.episode_dir / "provenance.json").exists()


# ---------------------------------------------------------------------------------------
# D3 — production's default live capture reads the EPISODE TENANT's clone
# ---------------------------------------------------------------------------------------


def _versioned_tenant_knowledge() -> str:
    """Place the episode tenant's knowledge folder as a real git repo (the committed fixture,
    committed) BEFORE `T.runs_base` sets the tenant up — `set_up_tenant` then keeps it and
    the real `accept_tenant` admits it (C10). Returns its HEAD."""
    knowledge = Path(os.environ["DEFENDER_DATA_ROOT"]) / T.SOURCE_TENANT / "knowledge"
    shutil.copytree(FIXTURE, knowledge, symlinks=True)
    (knowledge / "agent" / ".tenant-id").write_text(f"{T.SOURCE_TENANT}\n", encoding="utf-8")
    R._repo(knowledge)
    return R._head(knowledge)


def test_1204_the_default_live_capture_reads_the_episode_tenants_knowledge_clone(tmp_path):
    """D3: production's live capture (`live_tree` left to the launcher) captures knowledge from
    the EPISODE TENANT's clone, so preflight compares like with like. The tenant's knowledge is
    a real git repo at `live`; the default capture also asks git about this checkout, whose
    commit is not the fixture source's `deadbee`, so both launches refuse on the code commit —
    the discriminator is the knowledge clause. A source stamped on another knowledge commit is
    refused naming knowledge and the clone's own commit (read from the tenant's clone, nowhere
    else); a source stamped on the clone's commit draws no knowledge fault at all. Without this
    the default capture could carry no knowledge (every fork then waivably refused) or the
    product checkout's (C7)."""
    from defender import run_common

    code = _provenance.capture_tree(run_common.REPO_ROOT)
    if not code.commit:
        pytest.skip("no git answers for this checkout here, so the default live capture names "
                    "no code commit and the member comparison never reaches knowledge")
    live = _versioned_tenant_knowledge()
    assert live not in (K, K2)

    mismatched = A._prepare(tmp_path)
    mismatched.live_tree = None
    T.source_stamp(mismatched.src, knowledge={"commit": K2})
    message = A._refused_before_spending(mismatched)
    assert "live tree is at commit" in message, message
    for phrase in ("knowledge", live, K2):
        assert phrase in message, (phrase, message)

    matched = A._prepare(tmp_path)
    matched.live_tree = None
    T.source_stamp(matched.src, knowledge={"commit": live})
    message = A._refused_before_spending(matched)
    assert "live tree is at commit" in message, message
    assert "knowledge" not in message, message


# ---------------------------------------------------------------------------------------
# O3 / D4 — every stamp field is classified, and the classification drives the comparison
# ---------------------------------------------------------------------------------------

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


def test_1204_every_stamp_field_is_in_exactly_one_class_of_the_table():
    """O3 census: the fork check's table classifies EVERY `RunProvenance` field — its keys are
    exactly the dataclass's fields, so a field added to the stamp without a class fails here
    rather than being silently skipped by the comparison (the gap #1204 found: `knowledge`
    would have been) — each into one of the five classes, as D4 states them."""
    table = _table()
    declared = {f.name for f in dataclasses.fields(RunProvenance)}
    assert set(table) == declared, f"unclassified or stale: {declared ^ set(table)}"
    assert set(table.values()) <= CLASSES, set(table.values()) - CLASSES
    assert table == D4


def test_1204_each_anchored_and_constant_field_is_compared_through_verify_family(tmp_path):
    """O3 behavioural arm: for EVERY field the table classes `anchored` or `constant`, a family
    where ONE sibling differs from the source on that field alone is `incomplete` through the
    real `verify_family`, naming the field, with and without `--allow-dirty` — so the table is
    proven to drive the comparison, not merely to exist. Iterated off the table itself: a field
    newly classed there without a differing value here fails loudly. The positive control is
    the same family with no sibling differing."""
    table = _table()
    compared = sorted(f for f, c in table.items() if c in ("anchored", "constant"))
    assert compared == sorted(DIFFERENT), (
        f"a compared field has no differing value to test it with: {set(compared) ^ set(DIFFERENT)}")
    for field in compared:
        for allow_dirty in (False, True):
            report, recorded, stamp = _verify(
                tmp_path, f"{field}-{allow_dirty}".lower(), source=T.provenance_record(),
                siblings={"b": {field: DIFFERENT[field]}}, allow_dirty=allow_dirty)
            assert report["outcome"] == "incomplete", (field, allow_dirty, report["reason"])
            assert field in recorded["reason"], (field, recorded["reason"])
            assert "allow-dirty" not in recorded["reason"], (field, recorded["reason"])
            assert stamp is None

    report, recorded, stamp = _verify(tmp_path, "none-differs", source=T.provenance_record())
    assert recorded["outcome"] == "accepted", report["reason"]


def test_1204_fields_expected_to_differ_or_informational_are_not_compared(tmp_path):
    """O3/D4, the other half: fields the table says are NOT compared really are not. Siblings
    stamped with their own world, lineage and branch point (a forked sibling's real shape) are
    accepted; dirty siblings whose path samples, counts and reasons all differ are accepted
    under `--allow-dirty`, which waives the dirt and nothing else. Without this a table-driven
    loop that compared every field would refuse every real family."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base / "lineage", w) for w in T.WORLDS]
    for turn, d in enumerate(dirs, start=1):
        doc = {**T.provenance_record(), "world_id": f"{T.EPISODE_ID}.{d.name[-1]}",
               "parent_run_id": f"source-{turn}", "fork_turn": turn}
        (d / "provenance.json").write_text(json.dumps(doc), encoding="utf-8")
    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-lineage")
    with Episode.open(ep) as episode:
        report = _cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]

    report, recorded, _ = _verify(
        tmp_path, "dirt-differs", source=T.provenance_record(), allow_dirty=True,
        siblings={"b": {"dirty": True},
                  "c": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED}})
    assert recorded["outcome"] == "accepted", report["reason"]
