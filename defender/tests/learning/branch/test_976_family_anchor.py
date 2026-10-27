"""#976 — the family is anchored to its source's commit (detect-and-refuse)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.records._episode_handle import Episode
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.shared._fixture_uuid import fixture_uuid


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots inside `tmp_path`, as every launcher suite sets them."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def _cli():
    return T.mod("learning.branch.cli")


def _entry():
    """The command entry, whose `main` supplies the real preflight and page renderer."""
    return T.mod("cli.learning.branch")


def _tenant_paths():
    """#1078: the tenant `T.runs_base` (or `d9_tenant`) already created."""
    return T.current_tenant()


def _verify(ep: Path, plant: Any = T.arm_run_dir, **kw: Any) -> dict:
    """`cli.verify_family` over episode `ep`'s arms (#1105 PR 2): `plant(ep, world)` makes each
    world's finished arm in `ep`'s own container (default `T.arm_run_dir(ep, world)`), and each
    is opened by id through the episode's view (`T.family_arms`). The scene takes its explicit
    RUNS step first (`T.plant_roster`): the planter reads the roster and never writes one
    (review-3 F33)."""
    if not (ep / T.ROSTER_NAME).exists():  # once per episode (a loop may re-verify one)
        T.plant_roster(ep)
    for world in T.WORLDS:
        plant(ep, world)
    with Episode.open(ep) as episode:
        return _cli().verify_family(episode, T.family_arms(episode, T.WORLDS), **kw)


#: A commit no fixture, no message and no argv could carry by accident — C13's sweep needs a
#: value whose absence from every launch payload is a fact about the launcher, not about luck.
ANCHOR = "c0ffee976anchor"

#: The source run's one captured call and its answer (the live estate answers it the same).
QUERY = S.query_params("user:alice")
BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                  "ts": "2026-07-28T15:00:00Z"}]}


@dataclass
class Launch:
    """One launch's fakes, built BEFORE `main` runs so a refusal can still be asked what it
    cost: the questioner's calls, the capture's call count, and the role preflights that ran
    are all readable after `run()` has raised."""

    src: Path
    #: Every episode under any tenant of the data root before the launch (#1187: the launcher
    #: mints the episode's id, so `episode_dir` is the one new folder after it).
    episodes_before: frozenset
    spawn: Any
    questioner: Any
    live_tree: Any
    #: The fixture tenant's estate (#1224): pre-flight replays the source's one captured call
    #: through it, under the tenant's own gather grant.
    estate: Any
    oracle: Any = field(default_factory=lambda: S.oracle(then=S.submit(BASE, S.EMPTY_CLAIM)))
    verifier: Any = field(default_factory=S.passing_verifier)
    #: The judge's model seam, scripted: an ACCEPTED family is graded at the tail of the
    #: launch, and left to its production value that grade is a real model call.
    judge: Any = field(default_factory=lambda: J.FakeJudge(
        default=J.as_reply_text(J.reply_doc(bucket="none", systems=[]))))
    roles: list = field(default_factory=list)
    rc: int | None = None

    def run(self, *argv_extra: str) -> int:
        # #1105 PR 2 (declared change 1): the tenant and the source run by id.
        self.rc = _entry().main(
            ["--tenant", self.src.parent.parent.name, self.src.name, str(T.BRANCH_MESSAGE_ID),
             *T.retired_continuation_argv(), *argv_extra],
            spawn=self.spawn, questioner=self.questioner, judge=self.judge,
            preflight=lambda model, **_kw: self.roles.append(model) or 0,
            live_tree=self.live_tree, roster=self.estate.roster(), oracle=self.oracle.model,
            verifier=self.verifier.model)
        return self.rc

    @property
    def episode_dir(self) -> Path:
        """The episode this launch made: the one new folder under `<data root>/<T>/episodes/`
        (#1187 Layout A). A launch that made none answers a path that does not exist."""
        made = sorted(_episodes_now() - self.episodes_before)
        assert len(made) <= 1, f"one launch made {made}"
        return made[0] if made else Path(os.environ["DEFENDER_DATA_ROOT"]) / "<no episode made>"

    @property
    def family_stamp(self) -> dict:
        return json.loads((self.episode_dir / "provenance.json").read_text(encoding="utf-8"))


def _prepare(tmp_path, *, live_tree=None, siblings_at: str | None = "deadbee",
             spawn=None) -> Launch:
    """A source run under the configured runs base plus every fake a launch needs."""
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=[S.Call("idp", "query", QUERY, BASE)])
    return Launch(
        src=src, episodes_before=frozenset(_episodes_now()), estate=est,
        spawn=J.FakeSibling(commit=siblings_at) if spawn is None else spawn,
        questioner=S.questioner_for(),
        live_tree=T.source_capture() if live_tree is None else live_tree)


def _episodes_now() -> set[Path]:
    """Every episode under any tenant of this test's data root (`<root>/<T>/episodes/*`)."""
    return set(Path(os.environ["DEFENDER_DATA_ROOT"]).glob("*/episodes/*"))


def _restamp(src: Path, **overrides: Any) -> Path:
    """`T.source_stamp` for `_prepare`'s source run, whose tenant is the fixture tenant's."""
    overrides.setdefault("tenant_id", S.FIXTURE_TENANT)
    return T.source_stamp(src, **overrides)


def _refused_before_spending(launch: Launch, *argv_extra: str) -> str:
    """Run the launch, require the preflight's own refusal class, and require that NOTHING was spent"""
    with pytest.raises(_cli().LauncherRefused) as refusal:
        launch.run(*argv_extra)
    assert launch.questioner.calls == 0, "the questioner was paid before the refusal"
    assert launch.roles == [], "the paid role preflight ran before the anchor was judged"
    assert launch.estate.calls() == [], "the tenant was read before the anchor was judged"
    assert launch.oracle.requests == 0, "an oracle turn was spent before the anchor was judged"
    assert launch.verifier.requests == 0, "a verifier pass was spent before the refusal"
    assert launch.spawn.launches == [], "a sibling started after the refusal"
    assert not launch.episode_dir.exists(), "an episode directory was claimed for a refused launch"
    return str(refusal.value)


def _outcome(episode_dir: Path) -> dict:
    """Pre-flight's outcome record (`outcome.yaml`), read through the production reader."""
    from defender._io import bind
    from defender.learning.branch.outcome import read_outcome

    with bind(Path(episode_dir)) as bound:
        return read_outcome(bound)


def _withheld_reason(caplog: Any) -> str:
    """The reason the launcher logged when verify withheld the family stamp (#1224: verify's
    verdict is no longer written into the outcome record)."""
    withheld = [r.getMessage() for r in caplog.records
                if "the family stamp is withheld" in r.getMessage()]
    assert len(withheld) == 1, [r.getMessage() for r in caplog.records]
    return withheld[0]


def _never_waivable(message: str, *phrases: str) -> None:
    """A refusal the override does not reach NAMES ITS OWN SHAPE and does not offer the flag."""
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
    assert _outcome(launch.episode_dir)["outcome"] == "accepted"
    return launch.family_stamp


# O2 — a source that cannot anchor the family is refused before the questioner is paid


def test_976_a_source_with_no_stamp_is_refused_before_the_questioner_and_never_waived(tmp_path):
    """O2/M1: a source run carrying no `provenance.json` refuses at preflight — no questioner call, no oracle turn, no episode dir — and `--allow-dirty`..."""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path)
        (launch.src / "provenance.json").unlink()
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "source", "no usable provenance stamp")


def test_976_a_source_whose_git_could_not_be_asked_is_refused_and_never_waived(tmp_path):
    """O2/M1: a source stamped with no commit at all (`git unavailable`, the build-stamp-less shape) cannot anchor anything — there is no sha to hold the..."""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path)
        _restamp(launch.src, commit=None, dirty=None, unavailable=T.GIT_UNAVAILABLE)
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "source", "names no commit", T.GIT_UNAVAILABLE)
        assert launch.live_tree.calls == 0, "the live tree was captured for a source with no anchor"


def test_976_a_dirty_source_is_refused_without_the_override_and_proceeds_with_it(tmp_path):
    """O2/O4/M1: a source whose tree was dirty when it ran refuses at preflight without `--allow-dirty` (the message names the dirt and the override),..."""
    launch = _prepare(tmp_path)
    _restamp(launch.src, dirty=True)
    message = _refused_before_spending(launch)
    _waivable(message, "source", "not certified clean", "dirty=True")

    waived = _prepare(tmp_path)
    _restamp(waived.src, dirty=True)
    stamp = _accepted(waived, "--allow-dirty")
    assert stamp["source"]["dirty"] is True
    assert stamp["allow_dirty"] is True


def test_976_a_clean_matching_source_and_live_tree_launch_and_archive(tmp_path):
    """The positive control for both preflight tiers"""
    launch = _prepare(tmp_path)
    stamp = _accepted(launch)
    assert launch.live_tree.calls == 1
    assert stamp["source"]["commit"] == "deadbee"
    assert stamp["agreed"]["commit"] == "deadbee"


# O3 — a live tree that does not match the source refuses before anything is spent


def test_976_a_live_tree_at_another_commit_is_refused_and_never_waived(tmp_path):
    """O3/O4/M2: the launcher's checkout is at a different commit from the source's — the family would run code the source did not — so the preflight..."""
    for argv, live in (((), "0ther"), (("--allow-dirty",), "0ther"), ((), "deadbee0"),
                       ((), "deadbe")):
        # `deadbee0` and `deadbe` are the abbreviated-sha shapes: a prefix comparison in either
        # direction reads them as the source's `deadbee` (adversary H2). Equality is the rule.
        launch = _prepare(tmp_path, live_tree=T.source_capture(commit=live))
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "live tree is at commit", repr(live), "'deadbee'")
        assert "scope" not in message, ("a commit mismatch is not a scope mismatch", message)
        assert launch.live_tree.calls == 1, "the live tree was captured other than once"


def test_976_a_dirty_live_tree_is_refused_without_the_override_and_proceeds_with_it(tmp_path):
    """O3/O4/M2: the live tree is at the source's commit but dirty — refused without `--allow-dirty`, proceeds with it (the override's one legitimate use..."""
    launch = _prepare(tmp_path, live_tree=T.source_capture(dirty=True))
    message = _refused_before_spending(launch)
    _waivable(message, "live tree", "not certified clean", "dirty=True")

    waived = _prepare(tmp_path, live_tree=T.source_capture(dirty=True))
    stamp = _accepted(waived, "--allow-dirty")
    assert waived.live_tree.calls == 1
    assert stamp["allow_dirty"] is True


def test_976_a_live_scope_differing_from_the_sources_is_refused_and_never_waived(tmp_path):
    """O3/O4/M2: the source's stamp says its `dirty` was measured over scope `repo`"""
    for argv in ((), ("--allow-dirty",)):
        launch = _prepare(tmp_path, live_tree=T.source_capture(scope="defender"))
        message = _refused_before_spending(launch, *argv)
        _never_waivable(message, "measured over scope", "'defender'", "'repo'")
        assert "''" not in message, ("a possessive on a quoted label doubles the quote", message)


def test_976_a_source_stamped_before_scope_existed_is_compared_on_commit_alone(tmp_path):
    """Non-obligation, settled at preflight (design finding 2)"""
    launch = _prepare(tmp_path)
    _restamp(launch.src, scope=None)
    stamp = _accepted(launch)
    assert stamp["source"]["scope"] is None
    assert stamp["agreed"]["scope"] == "repo"


# O1 — the verify tier holds the siblings to the source (M3), through the named unit seam


def test_976_siblings_agreeing_at_a_commit_the_source_did_not_run_are_incomplete(tmp_path):
    """O1/M3, C5 closed: three siblings that agree with each other at `cafe1` while the source ran `deadbee` are NOT a comparable family — `incomplete`,..."""
    location_path(T.runs_base)(tmp_path)

    def dirs(ep, w):
        return T.arm_run_dir(ep, w, commit="cafe1")

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-drifted"))
    report = _verify(ep, dirs, source=T.provenance_record(commit="deadbee"))
    assert report["comparable"] is False
    assert "source" in report["reason"], report["reason"]
    assert "commit" in report["reason"], report["reason"]
    assert not (ep / "provenance.json").exists()
    assert sorted(p.name for p in (ep / "worlds").iterdir()) == sorted(T.world_id(ep, label) for label in T.WORLDS)
    assert not (ep / "outcome.yaml").exists(), "verify wrote the outcome pre-flight owns"

    # EQUALITY, NOT PREFIX (adversary H2): siblings at `cafe10` and at `cafe` are not siblings
    # of a `cafe1` source, whichever side an abbreviated sha would be read as extending.
    for extended in ("cafe10", "cafe"):
        def near(ep, w, extended=extended):
            return T.arm_run_dir(ep, w, commit=extended)

        ep = T.episode(tmp_path, episode_id=fixture_uuid(f"976-{extended}"))
        report = _verify(ep, near, source=T.provenance_record(commit="cafe1"))
        assert report["comparable"] is False, extended
        assert "commit" in report["reason"], report["reason"]
        assert not (ep / "provenance.json").exists()

    ok = T.episode(tmp_path, episode_id=fixture_uuid("976-anchored"))
    report = _verify(ok, dirs, source=T.provenance_record(commit="cafe1"))
    assert report["comparable"] is True
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["commit"] == "cafe1"
    assert stamp["source"]["commit"] == "cafe1"


def test_976_siblings_whose_scope_differs_from_the_sources_are_incomplete(tmp_path):
    """O1/M3: siblings measured over scope `repo` against a source measured over `defender` are `incomplete` on scope even at one commit"""
    location_path(T.runs_base)(tmp_path)

    # WITH AND WITHOUT THE OVERRIDE (adversary H3): a scope mismatch is not dirt, so
    # `--allow-dirty` does not reach it at this tier any more than at preflight.
    for allow_dirty in (False, True):
        ep = T.episode(tmp_path, episode_id=fixture_uuid(f"976-scoped-{str(allow_dirty).lower()}"))
        report = _verify(ep, source=T.provenance_record(scope="defender"),
                         allow_dirty=allow_dirty)
        assert report["comparable"] is False, allow_dirty
        assert "scope" in report["reason"], report["reason"]
        # The sibling label is quoted (`sibling 'b'`), so a possessive built onto it renders
        # `'b''s` in the archived reason.
        assert "''" not in report["reason"], report["reason"]
        assert not (ep / "provenance.json").exists()

    ok = T.episode(tmp_path, episode_id=fixture_uuid("976-unscoped"))
    report = _verify(ok, source=T.provenance_record(scope=None))
    assert report["comparable"] is True
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["source"]["scope"] is None


def test_976_a_dirty_source_under_the_override_is_still_held_to_its_commit(tmp_path):
    """O4/M3: under `--allow-dirty` a dirty source is compared on the fields it carries, as a dirty sibling is — siblings at the source's commit are..."""
    location_path(T.runs_base)(tmp_path)

    def elsewhere(ep, w):
        return T.arm_run_dir(ep, w, commit="cafe1")

    ok = T.episode(tmp_path, episode_id=fixture_uuid("976-dirty-anchored"))
    report = _verify(ok, source=T.provenance_record(dirty=True), allow_dirty=True)
    assert report["comparable"] is True
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["source"]["dirty"] is True
    assert stamp["allow_dirty"] is True

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-dirty-drifted"))
    report = _verify(ep, elsewhere, source=T.provenance_record(dirty=True), allow_dirty=True)
    assert report["comparable"] is False
    assert "commit" in report["reason"], report["reason"]
    assert not (ep / "provenance.json").exists()


def test_976_a_launch_whose_siblings_ran_another_commit_ends_incomplete_end_to_end(
        tmp_path, caplog):
    """O1/M3/M5 through the real launcher"""
    launch = _prepare(tmp_path, siblings_at="cafe1")
    assert launch.run() == 0, "the exit is about the launch; the outcome is about the family"
    assert launch.questioner.calls > 0, "the launch was refused at preflight instead"
    assert sorted(launch.spawn.worlds) == list(T.WORLDS)
    # #1224: the outcome record is pre-flight's (written once, before any sibling started);
    # verify's verdict is the withheld stamp and the reason it logs.
    assert _outcome(launch.episode_dir)["outcome"] == "accepted"
    withheld = _withheld_reason(caplog)
    assert "commit" in withheld, withheld
    assert not (launch.episode_dir / "provenance.json").exists()


def test_976_the_override_does_not_waive_a_sibling_commit_mismatch_end_to_end(
        tmp_path, caplog):
    launch = _prepare(tmp_path, siblings_at="cafe1")
    assert launch.run("--allow-dirty") == 0
    assert launch.questioner.calls > 0
    assert "commit" in _withheld_reason(caplog)
    assert not (launch.episode_dir / "provenance.json").exists()


# O4 — the override waives dirt and only dirt, end to end


def test_976_the_override_waives_dirt_on_both_sides_and_the_family_is_accepted(tmp_path):
    """O4's positive control (and O5's dirty case)"""
    launch = _prepare(tmp_path, live_tree=T.source_capture(dirty=True))
    _restamp(launch.src, dirty=True)
    stamp = _accepted(launch, "--allow-dirty")
    assert stamp["source"]["dirty"] is True
    assert stamp["source"]["dirty_paths"] == ["defender/investigation/driver/__init__.py"]
    assert stamp["source"]["dirty_path_count"] == 1
    assert stamp["allow_dirty"] is True
    assert stamp["agreed"]["commit"] == stamp["source"]["commit"] == "deadbee"


# ONE JUDGEMENT AT BOTH TIERS — the properties the shape guarantees, not the sites remember


def test_976_the_authority_judges_the_sources_own_dirt_not_only_the_siblings(tmp_path):
    """The verify tier is the authority, so it asks everything the preflight asks — including whether the SOURCE's tree was certified clean."""
    location_path(T.runs_base)(tmp_path)

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-dirty-source-unwaived"))
    report = _verify(ep, source=T.provenance_record(dirty=True))
    assert report["comparable"] is False
    assert "source" in report["reason"], report["reason"]
    assert "dirty=True" in report["reason"], report["reason"]
    assert not (ep / "provenance.json").exists()

    ok = T.episode(tmp_path, episode_id=fixture_uuid("976-dirty-source-waived"))
    report = _verify(ok, source=T.provenance_record(dirty=True), allow_dirty=True)
    assert report["comparable"] is True
    stamp = json.loads((ok / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["source"]["dirty"] is True
    assert stamp["allow_dirty"] is True


def test_976_two_problems_are_reported_at_once_never_waivable_first_and_without_the_flag(
        tmp_path):
    """§7 FORK-8 at the anchor"""
    launch = _prepare(tmp_path, live_tree=T.source_capture(commit="0ther"))
    _restamp(launch.src, dirty=True)
    message = _refused_before_spending(launch)
    _never_waivable(message, "live tree is at commit '0ther'", "not certified clean",
                    "dirty=True")
    assert message.index("is at commit") < message.index("not certified clean"), message
    assert launch.live_tree.calls == 1
    # Under the override the dirt is waived and the commit alone remains — still refused.
    waived = _prepare(tmp_path, live_tree=T.source_capture(commit="0ther"))
    _restamp(waived.src, dirty=True)
    message = _refused_before_spending(waived, "--allow-dirty")
    _never_waivable(message, "live tree is at commit '0ther'")
    assert "not certified clean" not in message, message


def test_976_a_verify_reason_the_override_cannot_reach_never_names_the_flag(tmp_path):
    """The recorded `episode.reason` holds to the same message rule as a preflight refusal"""
    location_path(T.runs_base)(tmp_path)
    never = {
        "dirty-and-drifted": lambda ep, w: T.arm_run_dir(ep, w, commit="cafe1",
                                                         dirty=(w == "b")),
        "silent": lambda ep, w: T.arm_run_dir(ep, w, **({"commit": None, "dirty": None,
                                                         "unavailable": T.GIT_UNAVAILABLE}
                                                        if w == "b" else {})),
        "drifted": lambda ep, w: T.arm_run_dir(ep, w, commit="cafe1"),
    }
    for name, dirs in never.items():
        ep = T.episode(tmp_path, episode_id=fixture_uuid(f"976-{name}"))
        report = _verify(ep, dirs, source=T.provenance_record())
        assert report["comparable"] is False, name
        reason = report["reason"]
        assert "allow-dirty" not in reason, (name, reason)

    def only_dirt(ep, w):
        return T.arm_run_dir(ep, w, dirty=(w == "b"))

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-only-dirt"))
    report = _verify(ep, only_dirt, source=T.provenance_record())
    assert report["comparable"] is False
    assert "allow-dirty" in report["reason"]


def test_976_siblings_off_the_anchor_are_named_against_the_source_once_each(tmp_path):
    """An archived reason tells each fact once."""
    location_path(T.runs_base)(tmp_path)

    def two_commits(ep, w):
        return T.arm_run_dir(ep, w, commit=f"c-{w}")

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-two-commits"))
    report = _verify(ep, two_commits, source=T.provenance_record(commit="s"))
    assert report["comparable"] is False
    reason = report["reason"]
    assert reason.count("while the source run it continues ran at") == len(T.WORLDS), reason
    assert "siblings disagree on commit" not in reason, reason
    assert "siblings disagree on scope" not in reason, reason

    def two_scopes(ep, w):
        arm = T.arm_run_dir(ep, w)
        if w == T.WORLDS[1]:
            T.source_stamp(arm, scope="defender")
        return arm

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-two-scopes"))
    report = _verify(ep, two_scopes, source=T.provenance_record(scope=None))
    assert report["comparable"] is False
    assert "siblings disagree on scope" in report["reason"], report["reason"]
    assert "measured over scope" not in report["reason"], report["reason"]

    # And a model split is the agreement loop's own fact, never the anchor's — told once.
    def two_models(ep, w):
        return T.arm_run_dir(ep, w, model=("m-2" if w == "b" else "m-1"))

    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-two-models"))
    report = _verify(ep, two_models, source=T.provenance_record())
    assert report["comparable"] is False
    assert report["reason"].count("siblings disagree on model") == 1, report["reason"]


def test_976_a_family_of_no_siblings_is_incomplete_not_a_crash(tmp_path):
    """`verify_family` over NO run dirs, against a clean source, is not comparable with a
    reason — not comparable with an agreed record of nobody, and not a `StopIteration` out of
    the family-stamp writer after the archive directory was made. The launcher never gets here
    (a manifest always has a base world), so this is the public entry's own answer."""
    ep = T.episode(tmp_path, episode_id=fixture_uuid("976-nobody"))
    with Episode.open(ep) as episode:
        report = _cli().verify_family(episode, {}, source=T.provenance_record())
    assert report["comparable"] is False
    assert "no sibling" in report["reason"], report["reason"]
    assert report["worlds"] == []
    assert not (ep / "provenance.json").exists()
    assert (ep / "worlds").is_dir()
    assert not (ep / "outcome.yaml").exists(), "verify wrote the outcome pre-flight owns"


# O5 — the archive says what it was anchored to


def test_976_the_accepted_family_stamp_carries_the_sources_whole_record(tmp_path):
    """O5/M4: the accepted family stamp's `source` is the SOURCE's own stamp, field by field — not the launcher-moment capture (which here carries no..."""
    launch = _prepare(tmp_path, live_tree=T.source_capture(model=None))
    stamp = _accepted(launch)
    expected = T.provenance_record()
    for name in ("commit", "dirty", "scope", "model", "dirty_paths", "dirty_path_count",
                 "unavailable"):
        assert stamp["source"][name] == expected[name], name
    assert stamp["source"]["model"] == "m-1", "the source's model, not the capture's None"
    assert stamp["source"]["dirty"] is False
    assert stamp["allow_dirty"] is False
    # #1204: `waived` names the fault kinds the override waived — none, for a clean family.
    # #1187 declared change 11 (R1b): the family stamp drops `base_world_id` — `_tenant.json`,
    # its only home, is retired, and no reader of the value existed.
    assert set(stamp) == {"agreed", "allow_dirty", "source", "waived"}
    assert stamp["waived"] == []


# M5 — threading: no caller keeps the unanchored behaviour


# M0 — the source's stamp is read through the one guarded reader


def test_976_a_link_planted_at_the_sources_stamp_name_is_refused_as_no_stamp(tmp_path):
    """M0: the source run dir is a prior box's rw bind, so `provenance.json` there may be an alias a model planted."""
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
    """M0: a source stamp whose `commit` is a list — the forgery the sibling reader was already hardened against — is refused as the launcher's own..."""
    launch = _prepare(tmp_path)
    (launch.src / "provenance.json").write_text(
        json.dumps({"commit": ["x"], "dirty": False, "scope": "repo", "model": "m-1"}),
        encoding="utf-8")
    message = _refused_before_spending(launch)
    assert "source" in message, message


# C13 — the source commit is never spent in argv or shown to a model
