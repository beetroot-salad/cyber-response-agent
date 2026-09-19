"""#773 — M1's deletion, M2's per-channel wiring, O7's untouched sibling, O10's fatal config.

RED AGAINST HEAD BY CONSTRUCTION: the tool, its config class and its bucket are all still
here. This module is where the SUBTRACTION is pinned — and a subtraction is the easiest
thing in a spec to certify by accident, so every removal demand below is paired with the
positive control that proves the surrounding mechanism still works.
"""
from __future__ import annotations

import inspect

import pytest

from defender.learning.core.config import FatalConfigError
from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"
QLESSON = "defender/lessons-questioner/w1.md"


# ---------------------------------------------------------------------------
# M1 — the curator writes, never checks
# ---------------------------------------------------------------------------


def test_the_corpus_author_grants_no_forward_check_tool_773(tmp_path):
    """The corpus author's toolset no longer carries `forward_check`, and the registration
    function is gone with it.

    Positive control on the same address: the grants the role DOES keep — bash, write,
    lesson_read — are untouched, so "the tool is absent" cannot pass on a role that lost
    every tool."""
    from defender.learning.author import curator_engine
    from defender.learning.author.verify_forward import tool as forward_tool

    tools = curator_engine.CORPUS_AUTHOR_DEF.tools
    assert not hasattr(tools, "forward_check")
    assert not hasattr(forward_tool, "register_forward_check_tool")
    assert tools.bash is True
    assert tools.write is True
    assert tools.lesson_read is True


def test_a_tool_the_registry_can_no_longer_be_asked_for_773(tmp_path):
    """`ToolSet.forward_check` and its `_register_deferred_tools` branch are removed with the
    tool: nothing anywhere sets the flag, and the registry has no branch for it.

    RF-5: the dead-code gate fires otherwise, which is why the field's removal is a demand
    and not a tidy-up. Driven over the real registry module's source, not over a copy."""
    from defender.runtime import tools as runtime_tools
    from defender.runtime.agent_definition import ToolSet

    assert "forward_check" not in {f.name for f in _fields(ToolSet)}
    assert "forward_check" not in inspect.getsource(runtime_tools)


def test_the_batch_ids_a_curator_spawn_can_still_name_in_a_check_773(tmp_path):
    """There are none: no `forward_check` tool is registered for the corpus author, and
    `register_forward_check_tool`, `Pair`, `ForwardCheckConfig` and `no_forward_check` are
    gone — a spawn naming the tool finds nothing.

    The whole point of the delta: the verdict is no longer a fact the writer self-reports."""
    from defender.learning.author import curator_engine
    from defender.learning.author.verify_forward import tool as forward_tool

    for gone in ("register_forward_check_tool", "Pair"):
        assert not hasattr(forward_tool, gone), gone
    for gone in ("ForwardCheckConfig", "no_forward_check"):
        assert not hasattr(curator_engine, gone), gone


def test_the_family_exemptions_written_record_after_the_tool_is_deleted_773(tmp_path):
    """The family rule's new home is `cfg.exempt` — `skips_forward_check` on the lessons
    channel, `lambda r: True` on the questioner's (M2) — and the three orphaned id helpers
    that fed the deleted config go with it.

    RF-5: `forward_checkable_ids`, `forward_exempt_ids` and `questioner_exempt_ids` exist
    only to build a `ForwardCheckConfig`; left behind they are dead code the vulture gate
    fires on. GL1 grounds what survives: `skips_forward_check` is exactly
    `row.get("direction") == "family"`, and it is now read by the drain."""
    from defender.learning.author.lessons import run as lessons_run
    from defender.learning.author.questioner import run as questioner_run

    for gone in ("forward_checkable_ids", "forward_exempt_ids"):
        assert not hasattr(lessons_run, gone), gone
    assert not hasattr(questioner_run, "questioner_exempt_ids")
    assert S.skips_forward_check({"direction": "family"}) is True
    assert S.skips_forward_check({"direction": "adversarial"}) is False


def test_the_curator_partitions_the_batch_into_committed_and_consumed_skip_only_773(tmp_path):
    """`FINDINGS_BUCKETS` declares exactly `committed` and `consumed_skip`; the
    `held_forward_bad` bucket and its `forward_bad_reason` field are gone.

    A lesson the check refuses is no longer a bucket the curator reports into — it is a
    verdict the drain computes. Positive control: both surviving buckets still route a row
    to its own disposition."""
    from defender.learning.author.lessons import run as lessons_run

    assert [b.name for b in lessons_run.FINDINGS_BUCKETS] == ["committed", "consumed_skip"]
    assert all(b.reason_field != "forward_bad_reason" for b in lessons_run.FINDINGS_BUCKETS)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("ok", run_id="ok"), S.finding_row("skip", run_id="skip")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("ok")},
            committed=["ok"],
            consumed_skip=[{"finding_id": "skip", "reason": "dup"}],
        ),
    )
    assert sc.run() == 0
    assert sc.category_of("ok") == "consumed_committed"
    assert sc.category_of("skip") == "consumed_skip"


def test_author_result_carries_an_unrecognized_bucket_key_773(tmp_path):
    """An AUTHOR_RESULT carrying ANY key outside `{committed, consumed_skip}` fails partition
    validation explicitly — including the removed `held_forward_bad`, and including a key
    that was never recognised at all.

    §7 FK-29, the human's decision, on a fact the probe established:
    `validate_agent_result_partition` (`shared.py:205-229`) is an ALLOW-LIST — it reads only
    recognised buckets and never flags an unrecognised key — so once M1 drops
    `held_forward_bad` from `FINDINGS_BUCKETS`, a curator still emitting it would NOT be
    caught. The demand it sharpens was green for the wrong reason."""
    for stray in ("held_forward_bad", "some_key_nobody_declared"):
        sc = S.build_scene(
            tmp_path / stray,
            rows=[S.finding_row("f1", run_id="f1")],
            curator=S.FakeCurator(
                writes={"l1.md": S.lesson("f1")},
                extra_result={stray: [{"finding_id": "f1", "reason": "r"}]},
            ),
        )
        assert sc.run() == 2, stray
        assert sc.head_files() == [], stray


def test_author_result_consumed_skip_bucket_is_missing_773(tmp_path):
    """A MISSING bucket key is an empty list, not a violation: a curator that committed
    everything and skipped nothing need not spell the empty bucket.

    §7 FK-29's other half, and the positive control the strictness demand needs — a closed
    schema that also rejects absence would fault every ordinary tick."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            result={"committed": ["f1"], "commit_message": "one finding"},
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.category_of("f1") == "consumed_committed"


def test_the_curator_spawn_carries_no_tool_config_773(tmp_path):
    """The `tool_config` slot stays on the base `AgentDeps` and is left UNPOPULATED by this
    role: the accessor properties `CuratorDeps` carried over it are gone with the tool.

    M1 keeps the field — it belongs to `runtime/tools/_deps.py`, not to this role — and
    removes only this role's use of it. The field's survival is the positive control."""
    from defender.learning.author import curator_engine
    from defender.runtime.tools import AgentDeps

    assert "tool_config" in {f.name for f in _fields(AgentDeps)}
    assert not hasattr(curator_engine.CuratorDeps, "check")
    assert "tool_config=" not in inspect.getsource(curator_engine.CuratorDeps)


def test_the_curator_prompt_and_deny_reason_no_longer_teach_the_forward_check_773(tmp_path):
    """Every reader of the removed mechanism agrees with its removal: the curator prompt's
    gate section and its `Held back (forward BAD):` block are gone, and
    `_CORPUS_AUTHOR_DENY_REASON`'s last sentence no longer describes a tool the role does
    not have.

    A COHERENCE demand, bound per reader: a demand at the tool's own altitude is green when
    two of its three readers moved, which is the bug."""
    from defender.learning.author import curator_engine
    from defender.learning.core.config import DEFAULT_PATHS

    prompt = (DEFAULT_PATHS.learning_dir / "author" / "lessons" / "prompt.md").read_text(
        encoding="utf-8"
    )
    assert "forward_check" not in prompt
    assert "forward BAD" not in prompt
    assert "forward_check" not in curator_engine._CORPUS_AUTHOR_DENY_REASON


def test_the_curator_prompts_account_of_a_mixed_file_after_the_change_773(tmp_path):
    """M3.4 INVERTS `prompt.md:177`'s "keep the GOOD edit": a file is approved only if EVERY
    pair is GOOD or EXEMPT, so the prompt line must be rewritten rather than left standing.

    The inversion is pinned, not assumed: the prompt must not still tell the curator that a
    mixed file keeps its good half, and the drain's own behaviour on a mixed file is the
    control."""
    from defender.learning.core.config import DEFAULT_PATHS

    prompt = (DEFAULT_PATHS.learning_dir / "author" / "lessons" / "prompt.md").read_text(
        encoding="utf-8"
    )
    assert "keep the GOOD edit" not in prompt

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a", "b")}, committed=["a", "b"]),
        verifier=S.FakeVerifier(verdicts={"b": "BAD"}),
    )
    assert sc.run() == 0
    assert sc.head_files() == []


def test_every_reference_to_the_deleted_check_in_prose_and_in_docstrings_773(tmp_path):
    """After the change NO non-test surface names the forward check as something the curator
    calls — including `prompt.md:5` and `questioner/run.py:12-13`, both OUTSIDE M1's stated
    150-177 / 199-200 ranges.

    CE8/F14/R4: the stale-reference gate fires on a name the diff removed, and the two
    references the design's own line ranges miss are exactly the ones a line-range-driven
    deletion leaves behind."""
    from defender.learning.author.questioner import run as questioner_run
    from defender.learning.core.config import DEFAULT_PATHS

    prompt = (DEFAULT_PATHS.learning_dir / "author" / "lessons" / "prompt.md").read_text(
        encoding="utf-8"
    )
    assert "forward" not in prompt.lower()
    assert "forward check" not in (questioner_run.__doc__ or "").lower()
    assert "forward_check" not in inspect.getsource(questioner_run)


def test_no_tool_grant_reaches_the_corpus_author_that_selects_a_runs_dir_path_773(tmp_path):
    """A NEGATIVE demand: no tool grant reaches the corpus author that would let a
    MODEL-EMITTED string select a path under the runs dir.

    M1 removes the "api" access route structurally — the tool that took a model-supplied
    `source_id` is deleted — so no code path exists post-delta that could exercise it. The
    positive control is the surviving route: the drain itself still reads
    `runs_dir/<run_id>` for ids taken from queue ROWS (S3), which the verdict suite drives."""
    from defender.learning.author import curator_engine

    source = inspect.getsource(curator_engine)
    assert "runs_dir" not in source or "ForwardCheckConfig" not in source
    assert not hasattr(curator_engine.CORPUS_AUTHOR_DEF.tools, "forward_check")


def test_the_author_result_still_carries_observability_gaps_773(tmp_path):
    """N3: the curator's `observability_gaps` field stays exactly as it is — unread by code
    (C5) and untouched by this delta.

    The gap ledger here is the forward check's; merging the two is a follow-up. A tick whose
    result carries the field behaves identically to one that does not."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("f1")},
            extra_result={"observability_gaps": ["the ticket adapter was slow"]},
        ),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.category_of("f1") == "consumed_committed"


def test_a_citation_of_an_earlier_batch_finding_is_not_verified_773(tmp_path):
    """N1: findings from EARLIER batches cited by a folded file are not re-verified. Only
    this batch's rows carry a live direction and ground truth.

    The file cites one this-batch id and one earlier-batch id; exactly one pair is minted.
    Corpus-wide regression is `evals/held_out.py`'s job, not this delta's."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("now", run_id="now")],
        seed_corpus={"old.md": S.lesson("earlier-batch-id")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("now", "earlier-batch-id")}),
    )
    assert sc.run() == 0
    assert sc.verifier.pairs_seen == [("l1.md", "now")]


# ---------------------------------------------------------------------------
# O7 — the questioner channel keeps today's behaviour
# ---------------------------------------------------------------------------


def test_a_questioner_tick_runs_vouching_and_no_verdict_step_773(tmp_path):
    """The questioner channel vouches every changed corpus file and runs NO verdict step:
    `forward_check` is `None` there, so M3.3-4 and M4 are skipped while M3.2, the
    explicit-list commit and the tree-derived `committed` all still apply.

    A PARITY demand: the constraint enforced on the lessons channel's access to the corpus
    is enforced on the questioner's too, minus the step M2 says it skips."""
    from defender.learning.author.questioner import run as questioner_run

    real = questioner_run.build_questioner_config(S.make_paths(tmp_path / "real"))
    assert real.forward_check is None
    assert real.exempt({"direction": "anything at all"}) is True

    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
    )
    assert sc.run() == 0
    assert sc.verifier.call_count == 0
    assert sc.head_files() == [QLESSON]


def test_the_questioner_channel_still_refuses_an_unvouched_file_773(tmp_path):
    """The questioner channel still refuses an unvouched file: its `lambda r: True` exempt
    predicate governs the VERDICT step only, never vouching.

    O7 names the #852 vouching gate explicitly, and this is the arm a channel with every row
    exempt would lose if `exempt` were read one step too early. Positive control: a properly
    cited file on the same channel does commit."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"stray.md": S.lesson("not-this-batch")},
                              committed=["w1"]),
    )
    assert sc.run() == 2
    assert sc.head_files() == []

    control = S.build_questioner_scene(
        tmp_path / "control",
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
    )
    assert control.run() == 0
    assert control.head_files() == [QLESSON]


def test_a_questioner_tick_with_a_changed_file_citing_no_batch_finding_773(tmp_path):
    """Unvouched → `AuthorError`, the SAME disposition as on the lessons channel.

    The parity is the point: the questioner's exempt predicate is about the verdict step,
    and its vouching is the lessons channel's vouching."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"orphan.md": S.lesson("someone-else")},
                              committed=["w1"]),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []


def test_a_questioner_tick_whose_curator_committed_nothing_773(tmp_path):
    """Vouching is now REACHED on a questioner tick that committed nothing — today it is
    skipped, because the #852 gate sits inside `if committed:` (G13) — and it has no work,
    so the observable outcome is unchanged: nothing committed, nothing refused.

    The behaviour delta is invisible from outside on this tick, which is exactly why the
    demand is written against a tick where it IS visible (the previous test) as well."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={}, committed=[],
                              consumed_skip=[{"finding_id": "w1", "reason": "nothing to say"}]),
    )
    assert sc.run() == 0
    assert sc.head_files() == []
    assert sc.category_of("w1") == "consumed_skip"


def test_the_questioner_tick_skips_only_the_verdict_stage_not_the_surrounding_ordering_773(
    tmp_path,
):
    """`forward_check=None` skips M3.3-4 and M4 ONLY: vouching, the explicit-list commit and
    the tree-derived `committed` all still run, in the same relative order as the lessons
    channel.

    Observed as the ordering's consequences rather than as the order itself: the commit
    names exactly the vouched file, and the consumption is keyed on that commit."""
    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1"), S.world_row("w2")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}, committed=["w1", "w2"]),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]
    assert sc.category_of("w1") == "consumed_committed"
    assert sc.category_of("w2") is None


# ---------------------------------------------------------------------------
# O10 — the fatal-config path, and where the preflight sits
# ---------------------------------------------------------------------------


def test_an_unset_verifier_key_ends_the_tick_before_the_first_curator_spawn_773(tmp_path):
    """A failed verifier-key preflight ends the tick with NO curator spawn at all: the
    preflight now sits in the drain, ahead of the first spawn.

    O10. Today it sits inside `run_curator_stage`, AFTER the spawn has been paid for
    (C16) — so a keyless host spends a full curator spawn inside the repo lock before
    discovering it cannot check anything.

    The control runs FIRST and drives the same drive edge to completion: with the key
    present, `author_and_rotate` really does spawn the curator on this scene. Without it,
    "no spawn happened" is also true of a drain that never spawns at all."""
    from defender.learning.core import config as core_config

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert control.run() == 0
    spawned_rows = [r["finding_id"] for r in control.curator.calls[0]["rows"]]
    assert spawned_rows == ["f1"]
    assert control.head_files() == [LESSON]

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        keys=S.FakeKeySource(missing=(core_config.verifier_model(),)),
    )
    with pytest.raises(FatalConfigError):
        sc.run()
    assert sc.curator.calls == []
    assert sc.head_files() == []


def test_preflight_runs_once_before_any_curator_spawn_this_tick_773(tmp_path):
    """The preflight runs ONCE per tick, before any curator spawn — not once per pair and
    not once per spawn.

    Asserted on the captured inbound calls to the key source: the verifier's model is
    sourced exactly once even on a tick that runs two spawns and two verdict passes."""
    from defender.learning.core import config as core_config

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="tried")}),
    )
    assert sc.run() == 0
    verifier_model = core_config.verifier_model()
    assert sc.keys.models.count(verifier_model) == 1
    assert sc.keys.models.index(verifier_model) == 0


def test_a_configuration_fault_tick_writes_no_gap_record_773(tmp_path):
    """A NEGATIVE demand: a tick that ends on a fatal configuration fault writes NO gap
    record — a config fault is never converted into per-finding BAD verdicts.

    O10's own failing-by line. Its positive control is on the same address under the
    complementary condition: with the key present, the same BAD-verdict tick DOES write
    one, so "no record" cannot pass on a drain that writes none."""
    from defender.learning.core import config as core_config

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        keys=S.FakeKeySource(missing=(core_config.verifier_model(),)),
    )
    with pytest.raises(FatalConfigError):
        sc.run()
    assert sc.gap_records() == []
    assert sc.pending_by_id()["f1"] == sc.rows[0]

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
    )
    assert control.run() == 0
    assert len(control.gap_records()) == 1


def test_a_channel_with_no_forward_check_on_a_host_with_no_verifier_key_773(tmp_path):
    """The MANDATORY negative control for O10's preflight: a questioner-channel tick on a
    host with no verifier key drains normally, unaffected.

    §7 FK-27: the drain-side preflight is gated on `cfg.forward_check is not None` (and
    keeps the pre-existing differing-`api_key_var` condition). Any reading where it runs
    unconditionally violates O7 outright — a channel that never wanted a forward check would
    meet a verifier-key requirement it never had. Without this control the preflight demand
    would happily certify that regression."""
    from defender.learning.core import config as core_config

    sc = S.build_questioner_scene(
        tmp_path,
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
        keys=S.FakeKeySource(missing=(core_config.verifier_model(),)),
    )
    assert sc.run() == 0
    assert sc.head_files() == [QLESSON]
    assert core_config.verifier_model() not in sc.keys.models


def test_preflight_ordering_when_author_and_verifier_share_a_provider_773(tmp_path):
    """The verifier-key preflight sources its key UNCONDITIONALLY — not gated on whether the
    author and verifier share a provider — because the curator spawn it would otherwise ride
    behind is `cfg.invoke_agent`, an injection seam the drain does not control the internals
    of (`_verifier_key_preflight`'s own comment). Gating on provider match here would just
    reintroduce "not checked before the first spawn" on exactly the shared-provider host this
    test used to special-case, so the key is sourced once regardless of `author_var` vs
    `verifier_var`.

    §7 FK-27's second half — moving the preflight must not also widen it. It still must not
    source the key TWICE (once here, once inside a spawn that reaches for it again)."""
    from defender.learning.core import config as core_config

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    # The tick must actually have reached the verdict step, or "the key was not sourced" is
    # green on a drain with no preflight at all — which is HEAD's state.
    assert sc.verifier.call_count == 1
    assert sc.keys.models.count(core_config.verifier_model()) == 1


def test_a_lessons_tick_that_ends_on_a_configuration_fault_while_the_sibling_channel_has_work_773(
    tmp_path,
):
    """O10's "the tick" means THIS CHANNEL's drain pass: a lessons-channel configuration
    fault does not take the questioner channel's tick down with it.

    §7 FK-26, settled by probe at `core/drains.py:314-318` / `_drain_one_curator:245-294`:
    the two channels are sibling, independent invocations, and everything but `RETIRE_SET`
    members and `KeyboardInterrupt` is caught, logged to that channel's own stuck report,
    and the sibling runs regardless. O7 obliges exactly this — a shared-fate reading would
    cost a questioner channel its drain over a verifier key it does not use."""
    from defender.learning.core import config as core_config

    keyless = S.FakeKeySource(missing=(core_config.verifier_model(),))
    lessons = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        keys=keyless,
    )
    with pytest.raises(FatalConfigError):
        lessons.run()

    sibling = S.build_questioner_scene(
        tmp_path / "sibling",
        rows=[S.world_row("w1")],
        curator=S.FakeCurator(writes={"w1.md": S.lesson("w1")}),
        keys=S.FakeKeySource(missing=(core_config.verifier_model(),)),
    )
    assert sibling.run() == 0
    assert sibling.head_files() == [QLESSON]


def _fields(cls):
    import dataclasses

    return dataclasses.fields(cls)
