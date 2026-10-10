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

#1224: verify no longer writes the episode outcome (pre-flight's, written once before any
sibling starts); a family called `incomplete` here is a verify report with `comparable: False`
and no family stamp.

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

import ast
import dataclasses
import json
import os
import shutil
import sys
import types
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
    T.isolate_learning_state(tmp_path, monkeypatch)


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
            allow_dirty: bool = False, reverse: bool = False) -> tuple[dict, dict | None]:
    """`verify_family` over three REAL sibling stamp files (`T.sibling_run_dir`, each with the
    overrides `siblings[label]` names) against `source`. Returns the report and the family
    stamp (`None` when none was written). The run dirs are handed over in `T.WORLDS` order
    (a, b, c), or reversed with `reverse`.

    #1224: the family's verdict is the report's `comparable` and its `reason` — the outcome
    record is pre-flight's, written once before any sibling starts, and verify never writes it
    (so none exists here)."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base / name, w, **(siblings or {}).get(w, {})) for w in T.WORLDS]
    if reverse:
        dirs.reverse()
    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}")
    with Episode.open(ep) as episode:
        report = _cli().verify_family(episode, dirs, source=source, allow_dirty=allow_dirty)
    assert not (ep / "outcome.yaml").exists(), "verify wrote the outcome record pre-flight owns"
    stamp_path = ep / "provenance.json"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8")) if stamp_path.exists() else None
    assert (stamp is not None) is report["comparable"], report
    return report, stamp


def _never_called_dirt(text: str) -> None:
    """A refusal whose faults are ALL about knowledge (every stamp in these scenarios is
    clean) never describes itself, or what `--allow-dirty` would waive, as dirt: the flag now
    waives unprovable knowledge too, and an operator told "pass --allow-dirty to waive the
    dirt" over a tree git certified clean is sent looking for dirt that is not there."""
    assert "dirt" not in text.replace("allow-dirty", ""), text


def _incomplete(report: dict, *phrases: str, waivable: bool) -> str:
    """The family was refused for its knowledge: not comparable, with the reason naming
    knowledge and each phrase, and offering `--allow-dirty` exactly when passing it would let
    the family through (the message rule `_family_refusal` holds every fault to) — never
    calling a knowledge fault dirt."""
    assert report["comparable"] is False, report
    reason = report["reason"]
    assert "knowledge" in reason, reason
    for phrase in phrases:
        assert phrase in reason, (phrase, reason)
    assert ("allow-dirty" in reason) is waivable, reason
    _never_called_dirt(reason)
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
    report, stamp = _verify(tmp_path, "same", source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]
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
    """O2/D4: knowledge is ANCHORED to the source like the code commit, so two siblings on two
    other knowledge commits are each named against the source — and not ALSO as a sibling
    disagreement, which the anchor faults already said (#976's one-fact-once rule). The third
    sibling, on the source's commit, is not named."""
    report, _ = _verify(
        tmp_path, "two-off", source=T.provenance_record(),
        siblings={"b": {"knowledge": {"commit": K2}}, "c": {"knowledge": {"commit": K3}}})
    reason = _incomplete(report, K2, K3, waivable=False)
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
    """O2/A2: a source stamped before #1204 (absent), with `null`, `"unversioned"` or an
    unavailable reason cannot prove its siblings read the same knowledge: `incomplete` without
    `--allow-dirty` — the reason names knowledge (and the shape's own words) and offers the flag
    — and `accepted` with it, the family stamp recording the waiver. Absent MUST be waivable,
    or every pre-#1204 run becomes permanently unforkable."""
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
    """O2/A2, the member side: source and siblings a, c on K, sibling b's knowledge unprovable.
    `incomplete` without the flag — naming knowledge and sibling b, offering the flag — and
    `accepted` with it. An unprovable sibling drops out of the knowledge agreement rather than
    counting as a disagreeing value. Without this either every sibling stamped on a git-less
    tenant blocks its family for good, or one is silently accepted."""
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
        report, _ = _verify(tmp_path, f"reasons-{name}", source=source,
                                      siblings=mixed)
        reason = _incomplete(report, waivable=True)
        assert "disagree" not in reason, reason

        report, stamp = _verify(tmp_path, f"reasons-{name}-waived", source=source,
                                          siblings=mixed, allow_dirty=True)
        assert report["comparable"] is True, report["reason"]
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
    assert stamp["waived"] == [], "nothing was waived, and the flag was not given"


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
    _never_called_dirt(message)

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
    """O2 end to end, the authority tier: the live clone matches the source (K), so preflight
    passes and the family runs — but every sibling's own stamp says K2, so `verify_family`
    withholds the family stamp, with and without `--allow-dirty`, and the reason it logs names
    knowledge and K2 without offering the flag (#1224: verify's verdict is no longer written into
    the outcome record, which is pre-flight's). This is
    the pin that the knowledge comparison runs on the siblings' per-process stamps, not only on
    the launcher's capture."""
    T.runs_base(tmp_path)
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID, tenant=T.current_tenant())
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


def test_1204_the_allow_dirty_help_says_it_waives_unprovable_knowledge(capsys):
    """Non-obligation made visible (one `--allow-dirty` waives both): the flag's own help — the
    operator's reference for what passing it does — names knowledge among what it waives, and
    no longer says it waives dirt and only dirt. Without this the help contradicts the
    refusals that now offer the flag for a knowledge fault."""
    with pytest.raises(SystemExit):
        _cli().parse_branch_args(["--help"])
    text = " ".join(capsys.readouterr().out.split())
    # The option's own entry: after its LAST mention (the first is the usage line), up to the
    # next option.
    entry = text.rsplit("--allow-dirty", 1)[1].split("--model", 1)[0]
    assert "knowledge" in entry, entry
    assert "only dirt" not in entry.lower(), entry


# ---------------------------------------------------------------------------------------
# The family stamp says WHAT the override waived, and `agreed` is what the check held
# ---------------------------------------------------------------------------------------

#: `(source, sibling overrides, --allow-dirty, the "waived" the family stamp must record)`.
#: `"waived"` is the SORTED list of the fault kinds `--allow-dirty` actually waived for this
#: family: `"dirt"` (a tree on the source or a sibling not certified clean) and `"knowledge"`
#: (knowledge on the source or a sibling that no commit proves: unversioned, unavailable, or
#: not recorded); `[]` when nothing was waived, with the flag or without it.
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
    """Review fix (faults carry their kind): `--allow-dirty` now waives two kinds of fault, and
    one `allow_dirty: true` bit cannot say which — a family whose only waived fault was a
    pre-#1204 source's missing knowledge commit read, in the archive, exactly like one whose
    code was dirty. The accepted family stamp records `"waived"`: the sorted kinds the flag
    actually waived. A clean family is `[]` with the flag or without it; a pre-#1204 source on
    clean code is `["knowledge"]` and never `"dirt"`. `allow_dirty` keeps recording the flag."""
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
    """The same record end to end through the launcher: a source stamped before #1204 (no
    knowledge key), launched with `--allow-dirty`, is accepted and its family stamp says
    `"waived": ["knowledge"]` when its code was clean — the review's case: it must not read as
    a dirty family — and `["dirt", "knowledge"]` when the code was dirty too. The siblings
    agreed on K, so `agreed.knowledge` is K."""
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
    """Review fix (the agreed record): `agreed` is what the check HELD CONSTANT, not a copy of
    whichever sibling came first. Under the waiver, a family whose first sibling's knowledge is
    unprovable and whose others agree on K records `agreed.knowledge == {"commit": K}` — in
    either order — never the first sibling's `"unversioned"` or unavailable reason, which would
    say the family agreed on no commit. The other agreed fields are the siblings' shared
    values, as before."""
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
    """Review fix (the agreed record), the other half: when NO sibling names a knowledge commit
    there is no agreed knowledge, and `agreed.knowledge` is `null` — the key present, the value
    saying nothing was agreed — never one sibling's `"unversioned"` or unavailable reason
    presented as the family's. Against a source on K and against a pre-#1204 source, under the
    waiver."""
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


# ---------------------------------------------------------------------------------------
# D3 — production's default live capture reads the EPISODE TENANT's clone
# ---------------------------------------------------------------------------------------


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
            report, stamp = _verify(
                tmp_path, f"{field}-{allow_dirty}".lower(), source=T.provenance_record(),
                siblings={"b": {field: DIFFERENT[field]}}, allow_dirty=allow_dirty)
            assert report["comparable"] is False, (field, allow_dirty, report["reason"])
            assert field in report["reason"], (field, report["reason"])
            assert "allow-dirty" not in report["reason"], (field, report["reason"])
            assert stamp is None

    report, stamp = _verify(tmp_path, "none-differs", source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]


def _cli_with_table(reclassified: dict[str, str], monkeypatch) -> Any:
    """The fork-check module rebuilt from ITS OWN SOURCE with one difference: right after the
    module assigns `STAMP_FIELD_CLASSES`, the name is re-bound to that table with
    `reclassified` applied. Everything the module derives from the table at import, and
    everything it reads from it at call time, then sees the re-classified table; a comparison
    that does not consult the table does not change. No production seam: the module is
    executed as written, under a scratch name, beside the real one (which is untouched)."""
    real = _cli()
    path = Path(real.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def assigns_table(node: ast.stmt) -> bool:
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        return any(isinstance(t, ast.Name) and t.id == "STAMP_FIELD_CLASSES" for t in targets)

    at = [i for i, node in enumerate(tree.body) if assigns_table(node)]
    assert len(at) == 1, "STAMP_FIELD_CLASSES is not assigned once at the module's top level"
    tree.body[at[0] + 1:at[0] + 1] = ast.parse(
        f"STAMP_FIELD_CLASSES = {{**STAMP_FIELD_CLASSES, **{reclassified!r}}}").body
    ast.fix_missing_locations(tree)
    name = f"{real.__name__}_reclassified_1204"
    rebuilt = types.ModuleType(name)
    rebuilt.__file__ = str(path)
    rebuilt.__package__ = real.__package__
    monkeypatch.setitem(sys.modules, name, rebuilt)
    exec(compile(tree, str(path), "exec"), rebuilt.__dict__)  # noqa: S102 — the module's own source
    assert {**_table(), **reclassified} == rebuilt.STAMP_FIELD_CLASSES
    return rebuilt


def _verify_with(cli: Any, tmp_path: Path, name: str, docs: dict[str, dict]) -> dict:
    """`cli.verify_family` over three real sibling stamp files whose documents are `docs`
    (by label), against the default source."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base / name, w) for w in T.WORLDS]
    for d in dirs:
        (d / "provenance.json").write_text(json.dumps(docs[d.name[-1]]), encoding="utf-8")
    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}")
    with Episode.open(ep) as episode:
        return cli.verify_family(episode, dirs, source=T.provenance_record())


def test_1204_the_field_table_drives_the_comparison(tmp_path, monkeypatch):
    """O3/D4: the table DRIVES the comparison rather than sitting beside a hardcoded one —
    re-classify a field in it and the fork check follows. Three families, each judged by the
    real module and by the same module rebuilt with a re-classified table:
    * a sibling on another MODEL: `incomplete` (constant) -> `accepted` once model is
      informational;
    * a sibling measured over another SCOPE: `incomplete` (anchored) -> `accepted` once scope
      is informational;
    * siblings each stamped with their own WORLD (as every real fork is): `accepted`
      (expected to differ) -> `incomplete`, naming world_id, once world_id is constant.
    Without this a comparison that kept the old `("commit", "scope", "model")` loop and merely
    defined the table would pass every other arm of O3."""
    clean = T.provenance_record()
    families = {
        "model": {w: {**clean, "model": "m-2" if w == "b" else "m-1"} for w in T.WORLDS},
        "scope": {w: {**clean, "scope": "defender" if w == "b" else "repo"} for w in T.WORLDS},
        "world_id": {w: {**clean, "world_id": f"{T.EPISODE_ID}.{w}"} for w in T.WORLDS},
    }
    real_says = {"model": False, "scope": False, "world_id": True}
    rebuilt = _cli_with_table(
        {"model": "informational", "scope": "informational", "world_id": "constant"},
        monkeypatch)
    for field, docs in families.items():
        report = _verify_with(_cli(), tmp_path, f"real-{field}".replace("_", "-"), docs)
        assert report["comparable"] is real_says[field], (field, report["reason"])
        flipped = _verify_with(rebuilt, tmp_path, f"table-{field}".replace("_", "-"), docs)
        assert flipped["comparable"] is not real_says[field], (field, flipped["reason"])
        if not flipped["comparable"]:
            assert field in flipped["reason"], (field, flipped["reason"])


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
    assert report["comparable"] is True, report["reason"]

    report, _ = _verify(
        tmp_path, "dirt-differs", source=T.provenance_record(), allow_dirty=True,
        siblings={"b": {"dirty": True},
                  "c": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED}})
    assert report["comparable"] is True, report["reason"]
