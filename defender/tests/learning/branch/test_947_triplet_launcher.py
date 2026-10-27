"""#947 — the launcher: what it checks, what it starts, what it refuses (preflight, `Step.RUNS`, `Step.VERIFY`"""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid


import json
import re
from pathlib import Path

import pytest

from defender.records._episode_handle import Episode
from defender._io import bind
from defender.records import RunPaths
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots point inside `tmp_path` for every scenario in this file."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def _cli():
    return T.mod("learning.branch.cli")


def _verify_family(ep_dir, plant=T.arm_run_dir, **kw):
    """`cli.verify_family` over an `Episode` opened on `ep_dir`"""
    if not (ep_dir / T.ROSTER_NAME).exists():  # once per episode (a loop may re-verify one)
        T.plant_roster(ep_dir)
    for world in T.WORLDS:
        plant(ep_dir, world)
    with Episode.open(ep_dir) as episode:
        return _cli().verify_family(episode, T.family_arms(episode, T.WORLDS), **kw)


def _tenant_paths():
    """#1078: the tenant `T.runs_base` (or `d9_tenant`) already created."""
    return T.current_tenant()


#: The one answer every captured call of `_launch`'s source run carries, so a single scripted
#: oracle submission (`_PASSING`) serves every call unchanged and every fact world calibrates.
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                   "ts": "2026-07-28T15:00:00Z"}]}


def _calls() -> list:
    """The source run's captured calls: two pre-branch reads over `_spec1224`'s fixture tenant."""
    return [S.Call("idp", "query", S.query_params("user:alice"), _BASE),
            S.Call("edr", "query", S.query_params("host:db-1"), _BASE)]


def _launch(tmp_path, *, spawn=None, argv_extra=(), oracle=None, verifier=None, **seams):
    """Drive one episode through the real launcher over `_spec1224`'s fixture tenant (#1224)."""
    run = S.launch(
        tmp_path, S.estate(tmp_path), calls=_calls(), spawn=spawn, argv_extra=argv_extra,
        oracle=oracle if oracle is not None else S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)),
        verifier=verifier if verifier is not None else S.passing_verifier(), **seams)
    return run.rc, run.spawn, run.ep, run.message


# preflight — what is checked before anything is spent


def test_947_launcher_returns_episode_dir_and_status(tmp_path):
    rc, _spawn, ep, _message = _launch(tmp_path)
    assert rc == 0
    assert (ep / "family.yaml").is_file()
    assert (ep / "outcome.yaml").is_file()
    assert (ep / "worlds").is_dir()


def test_947_un_nameable_episode_token_is_refused_before_the_questioner_runs(tmp_path):
    """An episode whose token cannot be rendered nameable is refused before the questioner is
    called at all: the refusal costs no model call and no primed capture."""
    base, src = location_path(T.runs_base)(tmp_path, source_run_id="fresh-case")
    invalid = src.with_name("FRESH CASE")
    src.rename(invalid)
    src = invalid
    agent = T.FakeAgent()
    with pytest.raises(SystemExit):
        _cli().main(["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
                     *T.retired_continuation_argv()],
                    spawn=T.FakeSpawn(), questioner=agent,
                    preflight=S.no_preflight, live_tree=T.source_capture())
    assert agent.calls == 0


def test_world_identities_are_independent_of_episode_and_label(tmp_path):
    fam = T.mod("records._family")
    authored = T.declaration(S.family_v2())
    first, _ = fam.accept_family(authored)
    second, _ = fam.accept_family(authored)
    ids = [world["world_id"] for doc in (first, second) for world in doc["worlds"]]
    assert len(set(ids)) == len(ids)
    assert all(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", wid)
               for wid in ids)
    assert [world["label"] for world in first["worlds"]] == list(T.WORLDS)


def test_947_step_one_preflight_checks_every_precondition_before_spending(tmp_path):
    """Preflight checks every precondition in ONE block before anything is spent, and EACH of them refuses before the questioner is called"""
    base, src = location_path(T.runs_base)(tmp_path, published=True)  # #1108 P4: a branch launch needs a published tenant (flow 7 pins its commit)

    def refuses(argv_extra, *, prepare=lambda: None):
        agent = T.FakeAgent()
        prepare()
        with pytest.raises(SystemExit):
            _cli().main(["--tenant", src.parent.parent.name, src.name, *argv_extra,
                         *T.retired_continuation_argv()],
                        spawn=T.FakeSpawn(), questioner=agent,
                        preflight=S.no_preflight, live_tree=T.source_capture())
        assert agent.calls == 0, "the questioner was paid for before the preflight refused"

    for out_of_range in ("-1", str(10 ** 9)):
        refuses([out_of_range])
    # the alert is PRESENT — the launcher reads it for the questioner's own prompt
    refuses([str(T.BRANCH_MESSAGE_ID)], prepare=lambda: RunPaths(src).alert.unlink())


def test_947_the_launcher_screens_the_source_alert_before_the_questioner_reads_it(tmp_path):
    """The launcher screens the source run's `alert.json` before it reaches the questioner's prompt"""
    base, src = location_path(T.runs_base)(tmp_path, published=True)  # #1108 P4: a branch launch needs a published tenant (flow 7 pins its commit)
    secret = tmp_path / "root-private-key"
    secret.write_text("ROOT-PRIVATE-KEY", encoding="utf-8")
    RunPaths(src).alert.unlink()
    RunPaths(src).alert.symlink_to(secret)
    agent = T.FakeAgent(T.declaration(T.family_doc()), T.declaration(T.world_doc("b")), T.declaration(T.world_doc("c")))
    with pytest.raises(T.refusals()) as refusal:
        _cli().main(["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
                     *T.retired_continuation_argv()],
                    spawn=T.FakeSpawn(), questioner=agent,
                    preflight=S.no_preflight, live_tree=T.source_capture())
    assert "alert" in str(refusal.value)
    assert agent.prompts == [], "the planted link reached the questioner's prompt"
    assert "ROOT-PRIVATE-KEY" not in str(refusal.value)


def test_947_the_step_one_command_line_needs_only_the_source_and_the_branch_point(tmp_path):
    base, src = location_path(T.runs_base)(tmp_path)
    request = _cli().parse_branch_args(["--tenant", src.parent.parent.name, src.name,
                                        str(T.BRANCH_MESSAGE_ID)])
    assert request.branch_message_id == T.BRANCH_MESSAGE_ID
    assert not hasattr(request, "episode_id"), (
        "the episode id is an operator argument again; the design derives it")


def test_947_all_siblings_in_one_family_are_launched_from_one_manifest_and_no_prompt(tmp_path):
    import yaml

    rc, spawn, ep, _message = _launch(tmp_path)
    manifest = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert manifest["base_story"], "the manifest was not the family's"
    assert manifest["worlds"], "the manifest was not the family's"
    assert "continuation_prompt" not in manifest
    assert len(spawn.launches) >= 2
    for la in spawn.launches:
        assert not any("continuation" in str(arg) for arg in la["argv"]), la["argv"]
    # #1105 PR 2 (declared change 6): a sibling names its episode by id, `--episode <ep>`.
    seen = {la["argv"][la["argv"].index("--episode") + 1] for la in spawn.launches}
    assert len(seen) == 1, "the siblings were launched from different manifests"


# `Step.PREFLIGHT` / `Step.RUNS` — an unaccepted episode, and starting the family


def test_947_accepted_siblings_are_started_together_as_processes(tmp_path):
    """The accepted siblings are started TOGETHER as child processes"""
    slow = T.FakeSpawn(fault=T.Fault(delay=0.25))
    rc, spawn, ep, _message = _launch(tmp_path, spawn=slow)
    assert sorted(spawn.worlds) == ["a", "b", "c"]
    for launch in spawn.launches:
        # #1105 PR 2 (declared change 6): `run.py --tenant T --episode <ep> --world L`.
        assert "--episode" in launch["argv"]
        assert any(arg.endswith("run.py") for arg in launch["argv"])
    assert spawn.overlap, "the siblings ran serially; nothing was started together"


def test_947_the_launcher_globs_and_passes_its_own_questioner_lessons(tmp_path):
    """#1007 M8/O7, wired end to end through the REAL launcher, not `author_family` called directly"""
    import yaml

    lessons_dir = tmp_path / "lessons-questioner"
    lessons_dir.mkdir(parents=True)
    body = "QUESTIONER-LAUNCHER-LESSON-BODY"
    meta = {"name": "l1", "systems": ["idp"]}
    (lessons_dir / "l1.md").write_text(
        "---\n" + yaml.safe_dump(meta, sort_keys=False) + "---\n" + body + "\n",
        encoding="utf-8")

    questioner = S.questioner_for()
    rc, _spawn, _ep, _message = _launch(tmp_path, questioner=questioner, lessons_dir=lessons_dir)

    assert rc == 0, "the episode did not complete cleanly"
    assert questioner.prompts, "the questioner was never called"
    assert body in questioner.prompts[0], (
        "the lesson never reached call 1's prompt — the launcher's own glob/pass-through is "
        "not wired, even though author_family's own selection logic is correct")


def _bare_family() -> dict:
    """A family no world of which carries a fact: pre-flight has nothing to calibrate."""
    return S.family_v2(worlds=[S.control_world("a"), S.world_v2("b", facts=[]),
                               S.world_v2("c", role="C", facts=[])])


@pytest.mark.parametrize("outcome", ["refused", "unusable"])
def test_947_an_unaccepted_episode_starts_no_sibling_and_its_record_archives(
        tmp_path, monkeypatch, outcome):
    """An episode pre-flight does not accept ends the EPISODE"""
    import yaml

    monkeypatch.setenv("ORACLE_RETRY_CAP", "1")
    seams = ({"questioner": S.questioner_for(_bare_family())} if outcome == "refused" else
             {"oracle": S.oracle(then=S.text_only("no served answer fits this world"))})
    rc, spawn, ep, _message = _launch(tmp_path, **seams)
    assert rc != 0
    assert spawn.launches == [], "a sibling started"
    record = yaml.safe_load((ep / "outcome.yaml").read_text(encoding="utf-8"))
    assert record["outcome"] == outcome
    assert record["reason"]
    assert (ep / "family.yaml").read_text(encoding="utf-8").strip()


def test_947_any_failure_in_steps_two_to_four_aborts_the_episode(tmp_path):
    """ONE rule, not a taxonomy"""
    spawn = T.FakeSpawn()
    rc, spawn, _ep, message = _launch(
        tmp_path, spawn=spawn,
        questioner=T.FakeAgent(T.declaration(S.family_v2()), fault=T.Fault(raise_after=1)))
    assert rc != 0
    assert message, "the abort was not reported as a refusal"
    assert spawn.launches == [], "a sibling started after the abort"


# `Step.VERIFY` — verification, the family stamp and withheld comparability


def test_947_launcher_verifies_each_siblings_scrub_verdict(tmp_path):
    """The launcher verifies each sibling's scrub verdict after the processes exit, reading the
    verdict at its sidecar path beside the run dir rather than inside the tree it judges."""
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)
    report = _verify_family(ep, source=T.provenance_record())
    assert report["scrub_verified"] == [T.world_id(ep, label) for label in T.WORLDS]


def test_947_a_sibling_without_a_ran_true_scrub_marks_the_episode_incomplete(tmp_path):
    """A sibling whose scrub verdict is absent, or present but not recording a completed walk, is never archived and the reason names it."""
    location_path(T.runs_base)(tmp_path)
    for scrub_ran, world in ((None, "b"), (False, "c")):
        ep = T.episode(tmp_path / world)

        def dirs(ep, w, world=world, scrub_ran=scrub_ran):
            return T.arm_run_dir(ep, w, scrub_ran=True if w != world else scrub_ran)

        report = _verify_family(ep, dirs, source=T.provenance_record())
        assert world in report["reason"]
        assert T.world_id(ep, world) not in report["archived"]
        assert report["comparable"] is True, report
        assert report["not_comparable"] == ""
        assert (ep / "provenance.json").exists()


def test_a_finished_sibling_without_a_scrub_verdict_gets_its_own_not_archived_record(tmp_path):
    outcome = T.mod("learning.branch.outcome")
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)

    def dirs(ep, w):
        return T.arm_run_dir(ep, w, scrub_ran=None if w == "b" else True)

    report = _verify_family(ep, dirs, source=T.provenance_record())

    assert T.world_id(ep, "b") not in report["archived"]
    with bind(Path(ep)) as bound:
        failed = outcome.failed_worlds(bound, {}, family=T.sym("records._family", "parse_family")(T.family_doc()))
    assert sorted(failed) == ["b"]
    assert failed["b"]["reason"] == outcome.NOT_ARCHIVED


def test_947_agreeing_sibling_stamps_write_the_family_stamp(tmp_path):
    """Sibling stamps that agree write the family stamp"""
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)
    _verify_family(ep, lambda ep, w: T.arm_run_dir(ep, w, commit="cafe1"),
                   source=T.provenance_record(commit="cafe1"))
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["commit"] == "cafe1"


def test_947_family_stamp_carries_agreed_and_override_as_disjoint_roles(tmp_path):
    """The family stamp carries its three roles disjointly"""
    ep = T.episode(tmp_path)
    _verify_family(ep, source=T.provenance_record())
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    # #1204: `waived` names the fault kinds the override waived — none, for a clean family.
    assert set(stamp) == {"agreed", "allow_dirty", "source", "waived"}
    assert stamp["waived"] == []
    assert "allow_dirty" not in stamp["agreed"]
    assert "allow_dirty" not in stamp["source"]
    assert stamp["allow_dirty"] is False
    assert stamp["source"]["commit"] == "deadbee"


def test_947_disagreeing_sibling_stamps_mark_the_episode_incomplete_with_a_reason(tmp_path):
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)

    def dirs(ep, w):
        return T.arm_run_dir(ep, w, commit=("cafe1" if w == "a" else "cafe2"))

    report = _verify_family(ep, dirs, source=T.provenance_record(commit="cafe1"))
    assert report["comparable"] is False
    assert "commit" in report["reason"]
    assert not (ep / "provenance.json").exists()


def test_947_an_absent_or_unreadable_sibling_stamp_marks_the_episode_incomplete(tmp_path):
    location_path(T.runs_base)(tmp_path)
    for mutate in ("absent", "truncated"):
        ep = T.episode(tmp_path)

        def dirs(ep, w, mutate=mutate):
            arm = T.arm_run_dir(ep, w, stamp=(w != "b"))
            if mutate == "truncated" and w == "b":
                (arm / "provenance.json").write_text('{"commit": "cafe', encoding="utf-8")
            return arm

        report = _verify_family(ep, dirs, source=T.provenance_record())
        assert report["comparable"] is False
        assert not (ep / "provenance.json").exists()


def test_947_the_family_stamp_carries_the_resolved_model_per_sibling(tmp_path):
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)
    _verify_family(ep, lambda ep, w: T.arm_run_dir(ep, w, model="m-1"),
                   source=T.provenance_record())
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["agreed"]["model"] == "m-1"


def test_947_a_cross_model_family_refuses_rather_than_agreeing(tmp_path):
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)

    def dirs(ep, w):
        return T.arm_run_dir(ep, w, model=("m-1" if w == "a" else "m-2"))

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is False
    assert "model" in report["reason"]
    assert not (ep / "provenance.json").exists()


def test_947_a_dirty_sibling_tree_is_refused_without_the_override(tmp_path):
    """EVERY non-clean stamp outcome refuses absent the override, and there are three a capture can produce"""
    location_path(T.runs_base)(tmp_path)
    waivable = {
        "dirty": {"dirty": True},
        "git-failed": {"dirty": None, "unavailable": T.GIT_STATUS_FAILED},
    }
    for name, stamp in waivable.items():
        ep = T.episode(tmp_path, episode_id=fixture_uuid(f"947-launcher-{name}"))

        def dirs(ep, w, stamp=stamp):
            return T.arm_run_dir(ep, w, **(stamp if w == "b" else {}))

        report = _verify_family(ep, dirs, source=T.provenance_record())
        assert report["comparable"] is False, name
        assert "b" in report["reason"], (name, report["reason"])
        assert not (ep / "provenance.json").exists(), name
        ok = T.episode(tmp_path, episode_id=fixture_uuid(f"947-launcher-{name}-ok"))
        waived = _verify_family(ok, dirs, source=T.provenance_record(), allow_dirty=True)
        assert waived["comparable"] is True, name
        assert (ok / "provenance.json").is_file(), name
    silent = {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE}

    def silent_dirs(ep, w):
        return T.arm_run_dir(ep, w, **(silent if w == "b" else {}))

    for allow_dirty in (False, True):
        # #1187 declared change 1: an episode id is a canonical lowercase uuid4 text.
        ep = T.episode(tmp_path,
                       episode_id=fixture_uuid(f"947-launcher-silent-{str(allow_dirty).lower()}"))
        report = _verify_family(ep, silent_dirs, source=T.provenance_record(),
                                allow_dirty=allow_dirty)
        assert report["comparable"] is False, f"allow_dirty={allow_dirty}"
        assert "b" in report["reason"], (allow_dirty, report["reason"])
        assert not (ep / "provenance.json").exists(), (
            f"allow_dirty={allow_dirty}: a family with a silent arm was stamped as comparable")


def test_947_the_dirty_override_is_named_in_the_family_stamp(tmp_path):
    """When the dirty override is given it is NAMED in the family stamp: a reader of the archive
    can tell an agreed clean family from one that was waved through."""
    location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path)
    _verify_family(ep, lambda ep, w: T.arm_run_dir(ep, w, dirty=(w == "b")),
                   source=T.provenance_record(), allow_dirty=True)
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert stamp["allow_dirty"] is True


# §7 FORK-1 — a family that fails verification withholds comparability


def test_947_an_incomplete_family_archives_per_world_and_withholds_comparability(tmp_path):
    """A family that fails verification archives each individually clean sibling."""
    location_path(T.runs_base)(tmp_path)
    # A per-world fault: c is not archived and the reason names it; the stamp is written.
    ep = T.episode(tmp_path / "per-world")
    report = _verify_family(ep, lambda ep, w: T.arm_run_dir(ep, w, scrub_ran=(w != "c")),
                            source=T.provenance_record())
    assert sorted(p.name for p in (ep / "worlds").iterdir()) == sorted(T.world_id(ep, label) for label in ("a", "b"))
    assert (ep / "provenance.json").exists()
    assert not (ep / "not_comparable.yaml").exists()
    assert report["comparable"] is True
    assert "c" in report["reason"]
    assert not (ep / "outcome.yaml").exists(), "verification wrote pre-flight's outcome record"

    # A comparability fault: the clean worlds are still on disk, the stamp is not, and the
    # recorded reason names the fault.
    ep = T.episode(tmp_path / "comparability")

    def dirs(ep, w):
        return T.arm_run_dir(ep, w, commit="cafef00" if w == "b" else "deadbee")

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert sorted(p.name for p in (ep / "worlds").iterdir()) == sorted(T.world_id(ep, label) for label in T.WORLDS)
    assert not (ep / "provenance.json").exists()
    assert report["comparable"] is False
    assert "cafef00" in report["not_comparable"]
    assert "cafef00" in (ep / "not_comparable.yaml").read_text(encoding="utf-8")
    assert not (ep / "outcome.yaml").exists(), "verification wrote pre-flight's outcome record"


# §7 FORK-2 — relaunching after a death


def test_947_two_launchers_on_one_episode_cannot_both_prime_it(tmp_path):
    """The episode directory's creation is an exclusive create, not a check-then-act"""
    import os
    import threading

    from defender.tests.storage.ids_1187 import _spec1187 as S

    location_path(T.runs_base)(tmp_path)
    tenant = _tenant_paths()
    results: list = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        try:
            with tenant.runs_repository().create_episode() as view:
                results.append(view.episode_id)
        except Exception as e:  # noqa: BLE001 — the refusal is the observation
            results.append(e)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not any(isinstance(r, Exception) for r in results), results
    assert len(set(results)) == 2, f"two launchers claimed one episode: {results}"
    episodes = S.episodes_dir(location_path(tenant.data_root), str(tenant.id))
    assert sorted(os.listdir(episodes)) == sorted(results), sorted(os.listdir(episodes))
    for episode_id in results:
        assert S.is_canonical_uuid(episode_id), f"{episode_id!r} is not a canonical uuid"
        assert (episodes / episode_id).is_dir(), episode_id
        assert not (episodes / episode_id).is_symlink(), episode_id


# the one shared mutable resource D1 newly contends


def test_947_concurrent_sibling_forks_into_one_source_store_all_land(tmp_path):
    store_mod = T.mod("records.session_store")
    import threading

    from defender.tests.support.storage import _session_store_705 as S

    from defender.records import SessionPaths

    base, src = location_path(T.runs_base)(tmp_path)
    # #1105 fork S(b): the layout owner hands the store its paths.
    with store_mod.open_store(case_id="case-947",
                              sessions=SessionPaths(fixture_runs_base(base))) as handle:
        sid = handle.new_session(agent_id="main")
        at = handle.append(sid, [S.user_request("investigate the alert"), *S.complete_pair()],
                           agent_id="main")[-1]
    made: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(3)

    def fork():
        barrier.wait()
        with store_mod.open_store(case_id="case-947",
                                  sessions=SessionPaths(fixture_runs_base(base))) as h:
            child = h.fork(sid, at_message_id=at)
        with lock:
            made.append(child)

    threads = [threading.Thread(target=fork) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(made) == 3
    assert len(set(made)) == 3


def test_947_concurrent_siblings_take_distinct_container_names(tmp_path):
    """Concurrent siblings take distinct container names: each name is derived from that
    sibling's own run id, so no two children of one family can contend for one container."""
    docker = T.mod("box._docker")
    names = {docker.container_name(f"{T.EPISODE_ID}-{w}") for w in T.WORLDS}
    assert len(names) == len(T.WORLDS)
    assert all(name.startswith("defender-run-") for name in names)
