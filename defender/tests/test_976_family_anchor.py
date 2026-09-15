"""#976 — the family is anchored to its source's commit (detect-and-refuse).

A branched family (#947) forks one finished SOURCE run into N siblings that must differ in
exactly the one axis the questioner declared. Before this change nothing compared what the
siblings ran against what the source ran: `verify_family` held the siblings to EACH OTHER and
the preflight never read the source's stamp at all — so a family launched after `main` had
moved past the source's commit was archived as comparable (C5), and a source with no usable
stamp cost a paid questioner call before anyone noticed.

Two tiers, both pinned here from the design's obligations (`design-976.md`):

* **Preflight** (`cli.main` → `preflight_episode`; M1, M2): the source's stamp is read through
  the one guarded reader; a source that cannot anchor (no stamp, no commit) refuses before the
  questioner is paid, never waivably; a dirty or unknown source refuses unless `--allow-dirty`.
  The LIVE tree is captured once through an injected seam (`capture=`) and refused, never
  waivably, when its commit or scope differs from the source's.
* **Verify** (`verify_family(..., source=)`; M3, M3b, M4): the siblings' own per-process stamps
  are the authority — agreeing with each other AND with the source's commit (and scope, when
  the source has one). The override waives dirt and only dirt; a silent sibling is never
  waived. The accepted family stamp carries the source's whole record beside `agreed`.

Every fake enters by an injection seam (`tests.idioms`: never `monkeypatch.setattr`). The
live-tree capture is `T.source_capture(...)`, a counted callable; without one the launcher
would compare the suite's own HEAD against the fixture's `deadbee` and refuse every launch.
Every negative is paired with a positive control on the same address; every fault is the real
one (an unlinked file, a real symlink, real forged JSON).

RED against ed890678: `main` has no `capture=` seam, `preflight_episode` reads no source
stamp, `verify_family` takes no `source=`, and the family stamp has no `source` key.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots inside `tmp_path`, as every launcher suite sets them."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _cli():
    return T.mod("learning.branch.cli")


#: A commit no fixture, no message and no argv could carry by accident — C13's sweep needs a
#: value whose absence from every launch payload is a fact about the launcher, not about luck.
ANCHOR = "c0ffee976anchor"


@dataclass
class Launch:
    """One launch's fakes, built BEFORE `main` runs so a refusal can still be asked what it
    cost: the questioner's calls, the door's created names, the capture's call count, and the
    role preflights that ran are all readable after `run()` has raised."""

    src: Path
    episode_dir: Path
    spawn: Any
    door: Any
    questioner: Any
    capture: Any
    invoke: Any = field(default_factory=lambda: T.FakeAgent(*["same"] * 24))
    #: The judge's model seam, scripted: an ACCEPTED family is graded at the tail of the
    #: launch, and left to its production value that grade is a real model call.
    judge: Any = field(default_factory=lambda: J.FakeJudge(default=J.as_reply_text(J.reply_doc())))
    roles: list = field(default_factory=list)
    rc: int | None = None

    def run(self, *argv_extra: str) -> int:
        self.rc = _cli().main(
            [str(self.src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go",
             *argv_extra],
            spawn=self.spawn, door=self.door, questioner=self.questioner,
            adapters=T.FakeAdapters(), invoke=self.invoke, judge=self.judge,
            preflight=lambda model: self.roles.append(model) or 0, capture=self.capture)
        return self.rc

    @property
    def family_stamp(self) -> dict:
        return json.loads((self.episode_dir / "provenance.json").read_text(encoding="utf-8"))


def _prepare(tmp_path, *, capture=None, siblings_at: str | None = "deadbee",
             spawn=None) -> Launch:
    """A source run under the configured runs base plus every fake a launch needs.

    The siblings are `J.FakeSibling`, which MATERIALISES finished run dirs stamped at
    `siblings_at`, so an accepted launch is one whose family really was verified and archived
    — `T.FakeSpawn` runs nothing, and a verify tier over three absent run dirs is
    `incomplete` for a reason this suite is not about.
    """
    _base, src = T.runs_base(tmp_path)
    episode_dir = _cli().episode_dir_for(T.EPISODE_ID)
    return Launch(
        src=src, episode_dir=episode_dir,
        spawn=J.FakeSibling(episode_dir, commit=siblings_at) if spawn is None else spawn,
        door=T.FakeDoor(),
        questioner=T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")),
        capture=T.source_capture() if capture is None else capture)


def _refused_before_spending(launch: Launch, *argv_extra: str) -> str:
    """Run the launch, require the preflight's own refusal class, and require that NOTHING was
    spent: no questioner call, no role-model preflight (the one in-process pass that sources a
    billable key), no cluster call at all — not the probe, not the sweep — no staged name, no
    episode directory. Returns the message.

    The role and cluster pins are here, on EVERY refusal, because an anchor check sited after
    the role preflight and the sweep greens every message assertion while sourcing keys and
    touching the namespace first (adversary H4)."""
    with pytest.raises(_cli().LauncherRefused) as refusal:
        launch.run(*argv_extra)
    assert launch.questioner.calls == 0, "the questioner was paid before the refusal"
    assert launch.roles == [], "the paid role preflight ran before the anchor was judged"
    assert launch.door.ops == [], "the cluster was touched before the anchor was judged"
    assert launch.door.created() == [], "a name was staged before the refusal"
    assert launch.spawn.launches == [], "a sibling started after the refusal"
    assert not launch.episode_dir.exists(), "an episode directory was claimed for a refused launch"
    return str(refusal.value)


def _never_waivable(message: str, *phrases: str) -> None:
    """A refusal the override does not reach NAMES ITS OWN SHAPE and does not offer the flag.

    The rule the messages hold to: `--allow-dirty` appears in a refusal exactly when passing it
    would let the launch through. A kitchen-sink message that names every field and offers the
    flag on every shape satisfied every substring the suite asked for (adversary H1) while
    telling an operator with a commit mismatch to waive it."""
    for phrase in phrases:
        assert phrase in message, (phrase, message)
    assert "allow-dirty" not in message, message


def _waivable(message: str, *phrases: str) -> None:
    """A refusal the override reaches names its shape AND offers the flag."""
    for phrase in phrases:
        assert phrase in message, (phrase, message)
    assert "allow-dirty" in message, message


def _accepted(launch: Launch, *argv_extra: str) -> dict:
    """Run the launch to completion and require the family to have been ACCEPTED: the exit is
    about the launch, the outcome is about the family, and a positive control needs both."""
    assert launch.run(*argv_extra) == 0
    assert launch.questioner.calls > 0, "the launch never reached the questioner"
    assert sorted(launch.spawn.worlds) == list(T.WORLDS)
    assert T.review_doc(launch.episode_dir)["episode"]["outcome"] == "accepted"
    return launch.family_stamp


# ---------------------------------------------------------------------------------------
# O2 — a source that cannot anchor the family is refused before the questioner is paid
# ---------------------------------------------------------------------------------------


def test_976_a_source_with_no_stamp_is_refused_before_the_questioner_and_never_waived(tmp_path):
    """O2/M1: a source run carrying no `provenance.json` refuses at preflight — no questioner
    call, no staged name, no episode dir — and `--allow-dirty` does not waive it: an absent
    stamp is not dirt. The refusal names the source and its stamp. Without this, a launch from
    an un-stamped source pays the questioner and archives a family anchored to nothing."""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path)
        (launch.src / "provenance.json").unlink()
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "source", "no usable provenance stamp")


def test_976_a_source_whose_git_could_not_be_asked_is_refused_and_never_waived(tmp_path):
    """O2/M1: a source stamped with no commit at all (`git unavailable`, the build-stamp-less
    shape) cannot anchor anything — there is no sha to hold the siblings to — so it refuses
    before the questioner is paid, and the override does not reach it. The message names THIS
    shape — the source and the reason its stamp gives for having no commit — rather than
    reporting the live tree as mismatching a commit that was never there: a silent source
    waived at M1 would still be refused by M2's comparison, with the operator sent at the wrong
    knob. Without this a family could be archived as "anchored" to a source nobody can name
    the code of."""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path)
        T.source_stamp(launch.src, commit=None, dirty=None, unavailable=T.GIT_UNAVAILABLE)
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "source", "names no commit", T.GIT_UNAVAILABLE)


def test_976_a_dirty_source_is_refused_without_the_override_and_proceeds_with_it(tmp_path):
    """O2/O4/M1: a source whose tree was dirty when it ran refuses at preflight without
    `--allow-dirty` (the message names the dirt and the override), and with it the launch
    proceeds past the preflight and completes. Without the negative, a source whose sha does
    not name its bytes silently anchors a family; without the positive, the override would be
    dead for the source side."""
    launch = _prepare(tmp_path)
    T.source_stamp(launch.src, dirty=True)
    message = _refused_before_spending(launch)
    _waivable(message, "source", "not certified clean", "dirty=True")

    waived = _prepare(tmp_path)
    T.source_stamp(waived.src, dirty=True)
    stamp = _accepted(waived, "--allow-dirty")
    assert stamp["source"]["dirty"] is True
    assert stamp["allow_dirty"] is True


def test_976_a_source_whose_tree_state_is_unknown_is_refused_without_the_override(tmp_path):
    """O2/O4/M1: a source with a sha but no answer about its tree (`git status` failed, `dirty:
    None`) is an unknown, not a clean bill of health: refused without `--allow-dirty`, waived
    with it. Without this, `dirty is not True` would be read as clean — the one error a
    provenance comparison must never make."""
    launch = _prepare(tmp_path)
    T.source_stamp(launch.src, dirty=None, unavailable=T.GIT_STATUS_FAILED)
    message = _refused_before_spending(launch)
    _waivable(message, "source", "not certified clean", "dirty=None", T.GIT_STATUS_FAILED)

    waived = _prepare(tmp_path)
    T.source_stamp(waived.src, dirty=None, unavailable=T.GIT_STATUS_FAILED)
    stamp = _accepted(waived, "--allow-dirty")
    assert stamp["source"]["dirty"] is None
    assert stamp["source"]["unavailable"] == T.GIT_STATUS_FAILED


def test_976_a_clean_matching_source_and_live_tree_launch_and_archive(tmp_path):
    """The positive control for both preflight tiers: a clean source at `deadbee`, a live tree
    captured clean at `deadbee` with the same scope, siblings at `deadbee` — the launch exits 0,
    the questioner is called, the family is accepted and stamped, and the live tree was captured
    exactly once. Every refusal above is only meaningful beside this."""
    launch = _prepare(tmp_path)
    stamp = _accepted(launch)
    assert launch.capture.calls == 1
    assert stamp["source"]["commit"] == "deadbee"
    assert stamp["agreed"]["commit"] == "deadbee"


# ---------------------------------------------------------------------------------------
# O3 — a live tree that does not match the source refuses before anything is spent
# ---------------------------------------------------------------------------------------


def test_976_a_live_tree_at_another_commit_is_refused_and_never_waived(tmp_path):
    """O3/O4/M2: the launcher's checkout is at a different commit from the source's — the
    family would run code the source did not — so the preflight refuses with nothing spent,
    the capture having been taken exactly once, and `--allow-dirty` does not waive a commit
    mismatch. Without this, the exact drift #976 was filed for is paid for and then (at best)
    found at verify."""
    for argv, live in (((), "0ther"), (("--allow-dirty",), "0ther"), ((), "deadbee0"),
                       ((), "deadbe")):
        # `deadbee0` and `deadbe` are the abbreviated-sha shapes: a prefix comparison in either
        # direction reads them as the source's `deadbee` (adversary H2). Equality is the rule.
        launch = _prepare(tmp_path, capture=T.source_capture(commit=live))
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "live tree is at commit", repr(live), "'deadbee'")
        assert "scope" not in message, ("a commit mismatch is not a scope mismatch", message)
        assert launch.capture.calls == 1, "the live tree was captured other than once"


def test_976_a_live_tree_git_cannot_answer_for_is_refused_and_never_waived(tmp_path):
    """O3/O4/M2: a live capture with no commit (git unavailable where the launcher runs) cannot
    be shown to match the source, so it refuses — an unknown is not a match — and the override
    does not reach it. Without this a launcher on a git-less host would anchor by assumption."""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path, capture=T.source_capture(
            commit=None, dirty=None, unavailable=T.GIT_UNAVAILABLE))
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "live tree names no commit", T.GIT_UNAVAILABLE)
        assert launch.capture.calls == 1


def test_976_a_dirty_live_tree_is_refused_without_the_override_and_proceeds_with_it(tmp_path):
    """O3/O4/M2: the live tree is at the source's commit but dirty — refused without
    `--allow-dirty`, proceeds with it (the override's one legitimate use on the live side).
    Without the negative, uncommitted edits to the code the siblings will mount pass as the
    source's commit; without the positive, `--allow-dirty` would refuse the case it exists
    for."""
    launch = _prepare(tmp_path, capture=T.source_capture(dirty=True))
    message = _refused_before_spending(launch)
    _waivable(message, "live tree", "not certified clean", "dirty=True")

    waived = _prepare(tmp_path, capture=T.source_capture(dirty=True))
    stamp = _accepted(waived, "--allow-dirty")
    assert waived.capture.calls == 1
    assert stamp["allow_dirty"] is True


def test_976_a_live_tree_of_unknown_state_is_refused_without_the_override(tmp_path):
    """O3/O4/M2: the live capture names the source's commit but could not answer for the tree
    (`dirty: None`, git status failed): refused without the override, proceeds with it.
    Without this the launcher would treat "git did not say" as "clean"."""
    launch = _prepare(tmp_path, capture=T.source_capture(
        dirty=None, unavailable=T.GIT_STATUS_FAILED))
    message = _refused_before_spending(launch)
    _waivable(message, "live tree", "not certified clean", "dirty=None",
              T.GIT_STATUS_FAILED)

    waived = _prepare(tmp_path, capture=T.source_capture(
        dirty=None, unavailable=T.GIT_STATUS_FAILED))
    _accepted(waived, "--allow-dirty")
    assert waived.capture.calls == 1


def test_976_a_live_scope_differing_from_the_sources_is_refused_and_never_waived(tmp_path):
    """O3/O4/M2: the source's stamp says its `dirty` was measured over scope `repo`; a live
    capture measured over `defender` answers a different question, so a matching commit does
    not make it a match — refused, and the override does not waive it. Without this two
    stamps whose `dirty` bits are not about the same subtree compare as one."""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path, capture=T.source_capture(scope="defender"))
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "measured over scope", "'defender'", "'repo'")


def test_976_a_source_stamped_before_scope_existed_is_compared_on_commit_alone(tmp_path):
    """Non-obligation, settled at preflight (design finding 2): a source stamp with `scope:
    None` — written before the field existed — is compared on commit only, at BOTH tiers. The
    live tree (scope `repo`) and the siblings (scope `repo`) match it on commit and the family
    is accepted, with the stamp recording the source's `scope` as `None`. Without this every
    pre-scope source run becomes unbranchable, or the mismatch surfaces later as a paid
    `incomplete`."""
    launch = _prepare(tmp_path)
    T.source_stamp(launch.src, scope=None)
    stamp = _accepted(launch)
    assert stamp["source"]["scope"] is None
    assert stamp["agreed"]["scope"] == "repo"


# ---------------------------------------------------------------------------------------
# O1 — the verify tier holds the siblings to the source (M3), through the named unit seam
# ---------------------------------------------------------------------------------------


def test_976_siblings_agreeing_at_a_commit_the_source_did_not_run_are_incomplete(tmp_path):
    """O1/M3, C5 closed: three siblings that agree with each other at `cafe1` while the source
    ran `deadbee` are NOT a comparable family — `incomplete`, the reason names the source and
    the commit, no family stamp is written, and every world is still archived per world. The
    positive control anchors the same siblings to a `cafe1` source and is accepted. Without
    this, sibling-to-sibling agreement alone archives a family that ran the wrong code."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base, w, commit="cafe1") for w in T.WORLDS]

    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-drifted")
    report = _cli().verify_family(ep, dirs, source=T.provenance_record(commit="deadbee"))
    assert report["outcome"] == "incomplete"
    assert "source" in report["reason"], report["reason"]
    assert "commit" in report["reason"], report["reason"]
    assert not (ep / "provenance.json").exists()
    assert sorted(p.name for p in (ep / "worlds").iterdir()) == list(T.WORLDS)
    assert T.review_doc(ep)["episode"]["outcome"] == "incomplete"

    # EQUALITY, NOT PREFIX (adversary H2): siblings at `cafe10` and at `cafe` are not siblings
    # of a `cafe1` source, whichever side an abbreviated sha would be read as extending.
    for extended in ("cafe10", "cafe"):
        near = [T.sibling_run_dir(base / extended, w, commit=extended) for w in T.WORLDS]
        ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{extended}")
        report = _cli().verify_family(ep, near, source=T.provenance_record(commit="cafe1"))
        assert report["outcome"] == "incomplete", extended
        assert "commit" in report["reason"], report["reason"]
        assert not (ep / "provenance.json").exists()

    ok = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-anchored")
    report = _cli().verify_family(ok, dirs, source=T.provenance_record(commit="cafe1"))
    assert report["outcome"] == "accepted"
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["commit"] == "cafe1"
    assert stamp["source"]["commit"] == "cafe1"


def test_976_siblings_whose_scope_differs_from_the_sources_are_incomplete(tmp_path):
    """O1/M3: siblings measured over scope `repo` against a source measured over `defender`
    are `incomplete` on scope even at one commit; a source with NO scope is compared on commit
    alone and accepted. Without the negative, two stamps whose dirt bits answer different
    questions compare as one; without the positive, every pre-scope source is unverifiable."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]

    # WITH AND WITHOUT THE OVERRIDE (adversary H3): a scope mismatch is not dirt, so
    # `--allow-dirty` does not reach it at this tier any more than at preflight.
    for allow_dirty in (False, True):
        ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-scoped-{allow_dirty}")
        report = _cli().verify_family(ep, dirs, source=T.provenance_record(scope="defender"),
                                      allow_dirty=allow_dirty)
        assert report["outcome"] == "incomplete", allow_dirty
        assert "scope" in report["reason"], report["reason"]
        assert not (ep / "provenance.json").exists()

    ok = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-unscoped")
    report = _cli().verify_family(ok, dirs, source=T.provenance_record(scope=None))
    assert report["outcome"] == "accepted"
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["source"]["scope"] is None


def test_976_a_dirty_source_under_the_override_is_still_held_to_its_commit(tmp_path):
    """O4/M3: under `--allow-dirty` a dirty source is compared on the fields it carries, as a
    dirty sibling is — siblings at the source's commit are accepted, siblings at another are
    `incomplete`. Without this the override would either refuse every dirty source (dead flag)
    or waive the commit along with the dirt (the confound the override must not admit)."""
    base, _src = T.runs_base(tmp_path)
    at_source = [T.sibling_run_dir(base / "same", w) for w in T.WORLDS]
    elsewhere = [T.sibling_run_dir(base / "moved", w, commit="cafe1") for w in T.WORLDS]

    ok = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-dirty-anchored")
    report = _cli().verify_family(ok, at_source, source=T.provenance_record(dirty=True),
                                  allow_dirty=True)
    assert report["outcome"] == "accepted"
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["source"]["dirty"] is True
    assert stamp["allow_dirty"] is True

    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-dirty-drifted")
    report = _cli().verify_family(ep, elsewhere, source=T.provenance_record(dirty=True),
                                  allow_dirty=True)
    assert report["outcome"] == "incomplete"
    assert "commit" in report["reason"], report["reason"]
    assert not (ep / "provenance.json").exists()


def test_976_a_launch_whose_siblings_ran_another_commit_ends_incomplete_end_to_end(tmp_path):
    """O1/M3/M5 through the real launcher: the live tree matches the source (`deadbee`), so
    the preflight passes and the family runs — but each sibling's own stamp says `cafe1`, so
    the verify tier ends the family `incomplete` with no family stamp. This is C5's
    reachability closed at the authority tier, and the pin that `_run_episode` actually
    threads the source stamp into `verify_family`. Without it the preflight's live capture
    could be mistaken for the authority, or the source returned from preflight dropped on the
    floor."""
    launch = _prepare(tmp_path, siblings_at="cafe1")
    assert launch.run() == 0, "the exit is about the launch; the outcome is about the family"
    assert launch.questioner.calls > 0, "the launch was refused at preflight instead"
    assert sorted(launch.spawn.worlds) == list(T.WORLDS)
    record = T.review_doc(launch.episode_dir)["episode"]
    assert record["outcome"] == "incomplete"
    assert "commit" in record["reason"], record["reason"]
    assert not (launch.episode_dir / "provenance.json").exists()


def test_976_the_anchor_verify_judges_is_the_one_preflight_read_not_a_second_read(tmp_path):
    """M5 through the real launcher: the source stamp `verify_family` holds the siblings to is
    the record `preflight_episode` read and judged — threaded, never re-read. The source run
    dir is a prior box's writable bind, so a stamp rewritten while the family runs is exactly
    the anchor a second read would swap in. Here the source is re-stamped `cafe1` from inside
    the spawn seam (after preflight, before verify): siblings at `deadbee` are accepted
    against the `deadbee` the preflight read, and the family stamp carries THAT record.
    Without this, `_run_episode` could drop the preflight's return and re-read the source at
    verify, and the suite would not notice (adversary H5)."""
    launch = _prepare(tmp_path)
    honest = launch.spawn

    def rewrite_then_run(argv, **kw):
        T.source_stamp(launch.src, commit="cafe1")
        return honest(argv, **kw)

    launch.spawn = rewrite_then_run
    assert launch.run() == 0
    assert honest.launches, "no sibling was launched — the rewrite never happened"
    assert T.review_doc(launch.episode_dir)["episode"]["outcome"] == "accepted"
    stamp = launch.family_stamp
    assert stamp["source"]["commit"] == "deadbee"
    assert stamp["agreed"]["commit"] == "deadbee"


def test_976_the_override_does_not_waive_a_sibling_commit_mismatch_end_to_end(tmp_path):
    """O4 through the real launcher: `--allow-dirty` with siblings at `cafe1` against a
    `deadbee` source is still `incomplete`. Without this the override would waive the very
    confound — a code difference between the source and the family — that it must never."""
    launch = _prepare(tmp_path, siblings_at="cafe1")
    assert launch.run("--allow-dirty") == 0
    assert launch.questioner.calls > 0
    assert T.review_doc(launch.episode_dir)["episode"]["outcome"] == "incomplete"
    assert not (launch.episode_dir / "provenance.json").exists()


# ---------------------------------------------------------------------------------------
# O4 — the override waives dirt and only dirt, end to end
# ---------------------------------------------------------------------------------------


def test_976_the_override_waives_dirt_on_both_sides_and_the_family_is_accepted(tmp_path):
    """O4's positive control (and O5's dirty case): `--allow-dirty` with a dirty-but-matching
    source, a dirty-but-matching live tree and siblings at the same commit is ACCEPTED and
    stamped — and the stamp says the source was dirty and the override was given, so the
    archive never reads as anchored to a clean sha. Without this the override could be made
    a no-op and every O4 negative would still pass."""
    launch = _prepare(tmp_path, capture=T.source_capture(dirty=True))
    T.source_stamp(launch.src, dirty=True)
    stamp = _accepted(launch, "--allow-dirty")
    assert stamp["source"]["dirty"] is True
    assert stamp["source"]["dirty_paths"] == ["defender/runtime/driver/__init__.py"]
    assert stamp["source"]["dirty_path_count"] == 1
    assert stamp["allow_dirty"] is True
    assert stamp["agreed"]["commit"] == stamp["source"]["commit"] == "deadbee"


# ---------------------------------------------------------------------------------------
# ONE JUDGEMENT AT BOTH TIERS — the properties the shape guarantees, not the sites remember
# ---------------------------------------------------------------------------------------


def test_976_the_authority_judges_the_sources_own_dirt_not_only_the_siblings(tmp_path):
    """The verify tier is the authority, so it asks everything the preflight asks — including
    whether the SOURCE's tree was certified clean. A dirty source without `--allow-dirty` is
    `incomplete` at verify with the source named in the reason, and no family stamp is
    written; under the override the same family is accepted and the stamp records the dirt
    beside the waiver. Without this a caller that reaches `verify_family` around the preflight
    (or a future second launcher) archives `source.dirty: true` beside `allow_dirty: false` —
    the exact record O5 says must never exist."""
    base, _src = T.runs_base(tmp_path)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]

    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-dirty-source-unwaived")
    report = _cli().verify_family(ep, dirs, source=T.provenance_record(dirty=True))
    assert report["outcome"] == "incomplete"
    assert "source" in report["reason"], report["reason"]
    assert "dirty=True" in report["reason"], report["reason"]
    assert not (ep / "provenance.json").exists()

    ok = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-dirty-source-waived")
    report = _cli().verify_family(ok, dirs, source=T.provenance_record(dirty=True),
                                  allow_dirty=True)
    assert report["outcome"] == "accepted"
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["source"]["dirty"] is True
    assert stamp["allow_dirty"] is True


def test_976_two_problems_are_reported_at_once_never_waivable_first_and_without_the_flag(
        tmp_path):
    """§7 FORK-8 at the anchor: a dirty source AND a live tree at another commit are one
    refusal naming both, the commit mismatch first — and the flag is NOT offered, because
    passing it would not let the launch through. The live tree was still captured (once), so
    the second problem is known on the first launch. Without this the waivable fault fired
    first, named `--allow-dirty`, and the operator met the never-waivable one only after
    passing a flag that could not help."""
    launch = _prepare(tmp_path, capture=T.source_capture(commit="0ther"))
    T.source_stamp(launch.src, dirty=True)
    message = _refused_before_spending(launch)
    _never_waivable(message, "live tree is at commit '0ther'", "not certified clean",
                    "dirty=True")
    assert message.index("is at commit") < message.index("not certified clean"), message
    assert launch.capture.calls == 1
    # Under the override the dirt is waived and the commit alone remains — still refused.
    waived = _prepare(tmp_path, capture=T.source_capture(commit="0ther"))
    T.source_stamp(waived.src, dirty=True)
    message = _refused_before_spending(waived, "--allow-dirty")
    _never_waivable(message, "live tree is at commit '0ther'")
    assert "not certified clean" not in message, message


def test_976_a_verify_reason_the_override_cannot_reach_never_names_the_flag(tmp_path):
    """The recorded `episode.reason` holds to the same message rule as a preflight refusal:
    `--allow-dirty` appears exactly when passing it would let the family through. A dirty
    sibling beside a commit mismatch, a silent sibling, and siblings off the source's commit
    are each never-waivable families, and none of their archived reasons names the flag; a
    family whose only fault is dirt does. Without this `review.yaml` sends the operator at a
    knob that does not turn (adversary H1, surviving at the tier whose messages are archived)."""
    base, _src = T.runs_base(tmp_path)
    never = {
        "dirty-and-drifted": [T.sibling_run_dir(base / "dd", w, commit="cafe1", dirty=(w == "b"))
                              for w in T.WORLDS],
        "silent": [T.sibling_run_dir(base / "s", w, **({"commit": None, "dirty": None,
                                                        "unavailable": T.GIT_UNAVAILABLE}
                                                       if w == "b" else {}))
                   for w in T.WORLDS],
        "drifted": [T.sibling_run_dir(base / "d", w, commit="cafe1") for w in T.WORLDS],
    }
    for name, dirs in never.items():
        ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-{name}")
        report = _cli().verify_family(ep, dirs, source=T.provenance_record())
        assert report["outcome"] == "incomplete", name
        reason = T.review_doc(ep)["episode"]["reason"]
        assert "allow-dirty" not in reason, (name, reason)
    only_dirt = [T.sibling_run_dir(base / "od", w, dirty=(w == "b")) for w in T.WORLDS]
    ep = T.episode(tmp_path, episode_id=f"{T.EPISODE_ID}-only-dirt")
    report = _cli().verify_family(ep, only_dirt, source=T.provenance_record())
    assert report["outcome"] == "incomplete"
    assert "allow-dirty" in T.review_doc(ep)["episode"]["reason"]


# ---------------------------------------------------------------------------------------
# O5 — the archive says what it was anchored to
# ---------------------------------------------------------------------------------------


def test_976_the_accepted_family_stamp_carries_the_sources_whole_record(tmp_path):
    """O5/M4: the accepted family stamp's `source` is the SOURCE's own stamp, field by field —
    not the launcher-moment capture (which here carries no model, as a real `capture_tree`
    never does) and not the siblings' agreement. Paired with the clean reading: `source.dirty`
    is False and `allow_dirty` is False. Without this a reader of the archive could not tell
    which code the family was anchored to, or would read the launcher's own capture as it."""
    launch = _prepare(tmp_path, capture=T.source_capture(model=None))
    stamp = _accepted(launch)
    expected = T.provenance_record()
    for name in ("commit", "dirty", "scope", "model", "dirty_paths", "dirty_path_count",
                 "unavailable"):
        assert stamp["source"][name] == expected[name], name
    assert stamp["source"]["model"] == "m-1", "the source's model, not the capture's None"
    assert stamp["source"]["dirty"] is False
    assert stamp["allow_dirty"] is False
    assert set(stamp) == {"agreed", "allow_dirty", "source"}


# ---------------------------------------------------------------------------------------
# M5 — threading: no caller keeps the unanchored behaviour
# ---------------------------------------------------------------------------------------


def test_976_verify_family_requires_the_source_anchor(tmp_path):
    """M5: `verify_family` without `source=` is a `TypeError` — the anchor is keyword-required
    with no default, so no call site can keep the unanchored comparison by omission. Without
    this a default of `None` would let the launcher (or a future caller) skip M3 silently."""
    base, _src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    with pytest.raises(TypeError):
        _cli().verify_family(ep, dirs)
    assert not (ep / "provenance.json").exists()


# ---------------------------------------------------------------------------------------
# M0 — the source's stamp is read through the one guarded reader
# ---------------------------------------------------------------------------------------


def test_976_a_link_planted_at_the_sources_stamp_name_is_refused_as_no_stamp(tmp_path):
    """M0: the source run dir is a prior box's rw bind, so `provenance.json` there may be an
    alias a model planted. Read through `_provenance.read` (alias-refusing), a real symlink
    at that name — even one pointing at a perfectly matching record — is "no stamp", and the
    launch refuses before the questioner is paid. The positive control is the same bytes as a
    plain file (`test_976_a_clean_matching_source_and_live_tree_launch_and_archive`). Without
    this a hand-rolled `read_text` would follow the link and anchor to whatever it named."""
    launch = _prepare(tmp_path)
    real = tmp_path / "elsewhere.json"
    real.write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    (launch.src / "provenance.json").unlink()
    (launch.src / "provenance.json").symlink_to(real)
    message = _refused_before_spending(launch)
    assert "source" in message, message
    assert "provenance" in message, message


def test_976_a_forged_source_commit_is_refused_at_preflight_not_raised_out_of_the_launcher(
        tmp_path):
    """M0: a source stamp whose `commit` is a list — the forgery the sibling reader was already
    hardened against — is refused as the launcher's own `LauncherRefused`, never a `TypeError`
    out of a string comparison or a set build, and before the questioner is paid. Without this
    one planted file in the source run dir crashes the launcher instead of refusing it."""
    launch = _prepare(tmp_path)
    (launch.src / "provenance.json").write_text(
        json.dumps({"commit": ["x"], "dirty": False, "scope": "repo", "model": "m-1"}),
        encoding="utf-8")
    message = _refused_before_spending(launch)
    assert "source" in message, message


# ---------------------------------------------------------------------------------------
# C13 — the source commit is never spent in argv or shown to a model
# ---------------------------------------------------------------------------------------


def test_976_the_source_commit_reaches_only_comparisons_and_the_family_stamp(tmp_path):
    """C13: the source's commit string is read at preflight and verify and lands in the family
    stamp's JSON — and NOWHERE ELSE: not in any sibling's argv or env, not in the questioner's
    or the comparator's prompts. A distinctive commit on the source, the live capture and the
    siblings makes the launch accepted (the positive half: the stamp carries it), and the sweep
    over every outbound payload is the negative. Without this a forged source commit would be
    a string an operator's shell or a model gets to see."""
    launch = _prepare(tmp_path, capture=T.source_capture(commit=ANCHOR), siblings_at=ANCHOR)
    T.source_stamp(launch.src, commit=ANCHOR)
    stamp = _accepted(launch)
    assert stamp["source"]["commit"] == ANCHOR
    assert stamp["agreed"]["commit"] == ANCHOR
    assert launch.spawn.launches, "no sibling was launched — the argv sweep below is vacuous"
    for launched in launch.spawn.launches:
        assert all(ANCHOR not in arg for arg in launched["argv"]), launched["argv"]
        assert all(ANCHOR not in value for value in launched["env"].values()), launched["env"]
    # The questioner is prompted three times per family; the comparator only when the review
    # has a captured row to replay, which this family (no `rows`) does not — so the control is
    # on the questioner and the comparator's sweep is over whatever it was handed.
    assert launch.questioner.prompts, "the questioner was never prompted — the sweep is vacuous"
    assert all(ANCHOR not in prompt for prompt in launch.questioner.prompts)
    assert all(ANCHOR not in prompt for prompt in launch.invoke.prompts)
