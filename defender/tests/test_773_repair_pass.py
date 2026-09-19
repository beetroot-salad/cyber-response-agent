"""#773 — the one bounded repair pass (M4 / D1), its second verdict pass, and the undo.

RED AGAINST HEAD BY CONSTRUCTION. `_spec773.py` carries the seam contract; the repair
spawn enters through `cfg.invoke_repair` and the restricted toolset is a fixed fact about
`CORPUS_REPAIR_DEF` (§7 F8), never a per-spawn override.
"""
from __future__ import annotations

import pytest

from defender.learning.core.config import FatalConfigError
from defender.tests import _spec773 as S

LESSON = "defender/lessons/l1.md"
LESSON2 = "defender/lessons/l2.md"


# ---------------------------------------------------------------------------
# M4 — one spawn, its grant, its payload
# ---------------------------------------------------------------------------


def test_at_most_one_repair_spawn_runs_per_tick_773(tmp_path):
    """D1 is ONE bounded attempt: however many pairs go BAD, the repair curator is spawned
    at most once in a tick, and a pair still BAD after it is terminal rather than repaired
    again.

    The bound is what makes the worst-case lock hold "two passes plus one extra spawn"."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("a"), "l2.md": S.lesson("b")}, committed=["a", "b"]
        ),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("a", body="tried")}),
    )
    assert sc.run() == 0
    assert sc.repair.spawned == 1


def test_a_tick_with_no_refused_pair_at_all_773(tmp_path):
    """M4's conditional does not fire when nothing is BAD: no repair spawn, no second pass,
    a single M3 pass.

    The positive control for the spawn count — without it "at most one" is also satisfied
    by a drain that never spawns."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.repair.spawned == 0
    assert sc.verifier.call_count == 1
    assert sc.head_files() == [LESSON]


def test_the_repair_spawn_gets_a_write_tool_and_no_bash_773(tmp_path):
    """The repair role's toolset is write + lesson_read and NO bash: no `rm`, no `grep`.

    §7 F8 settled the architecture — a fixed, separate `CORPUS_REPAIR_DEF`, never a
    per-spawn `ToolSet` override on the curator role — so this is a build-time fact about
    the definition and not a runtime choice a future caller could forget to apply. C19
    records what the FIRST spawn gets, which is the contrast: an unscoped `grep` and a
    corpus-wide `rm`."""
    from defender.learning.author.curator_engine import CORPUS_REPAIR_DEF

    tools = CORPUS_REPAIR_DEF.tools
    assert tools.write is True
    assert tools.lesson_read is True
    assert tools.bash is False


def test_corpus_repair_def_grants_the_write_tool_773(tmp_path):
    """`CORPUS_REPAIR_DEF.tools` grants `write` at its own per-cell address — the repair
    spawn's ONLY permitted move is to rewrite the lesson file.

    Sharpens the boundary-grain assertion above to the per-member grain (R4 obligation g4):
    a test over the whole toolset is green while `write` is the member that went missing."""
    from defender.learning.author.curator_engine import CORPUS_REPAIR_DEF

    assert CORPUS_REPAIR_DEF.tools.write is True


def test_corpus_repair_def_grants_lesson_read_773(tmp_path):
    """`CORPUS_REPAIR_DEF.tools` grants `lesson_read` at its own per-cell address — the
    repair spawn can read the corpus it is rewriting into.

    Companion to g4, same sharpening for the second granted tool (R4 obligation g5)."""
    from defender.learning.author.curator_engine import CORPUS_REPAIR_DEF

    assert CORPUS_REPAIR_DEF.tools.lesson_read is True


def test_curators_own_write_shape_grants_are_unaffected_by_the_repair_spawns_narrower_grant_773(
    tmp_path,
):
    """The FIRST curator spawn's own write shapes are unchanged by M4 narrowing the repair
    role: driven at the unmoved reader's own edge, the curator still writes a corpus `*.md`
    and still keeps its bash grants.

    R7 obligation g9: a coherence demand belongs at each reader's edge, not at the source —
    a demand at the definition's altitude is green when only one of two readers moved."""
    from defender.learning.author.curator_engine import CORPUS_AUTHOR_DEF

    assert CORPUS_AUTHOR_DEF.tools.bash is True
    assert CORPUS_AUTHOR_DEF.tools.write is True

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]


def test_the_repair_prompt_carries_the_row_the_text_and_the_reasoning_wrapped_as_untrusted_773(
    tmp_path,
):
    """The repair spawn's user turn carries, per BAD pair, the finding ROW, the file's
    CURRENT text and the verifier's REASONING — each inside its own `wrap()` envelope on
    the message's own salt.

    S4: all three are model-authored, so all three are untrusted stage input. Asserted on
    the payload the builder actually produces, against the envelope's literal frame."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", body="over-broad")}),
        verifier=S.FakeVerifier(default="BAD", reasoning="it would flip case f1"),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="narrowed")}),
    )
    assert sc.run() == 0
    [call] = sc.repair.calls
    [pair] = call["pairs"]
    prompt = S.drain.build_repair_user_prompt([pair], sc.cfg, salt="SALT")
    assert "<run-SALT-" in prompt
    for fragment in ("f1", "over-broad", "it would flip case f1"):
        assert fragment in prompt
    for fragment in ("over-broad", "it would flip case f1"):
        head = prompt.index(fragment)
        assert prompt.rindex("<run-SALT-", 0, head) > prompt.rindex("</run-SALT-", 0, head) - 1


def test_repair_prompt_none_uses_the_shipped_default_at_spawn_773(tmp_path):
    """`cfg.repair_prompt = None` is a distinguished member of its own domain, exercised
    directly: the tick still completes and the BAD pair still reaches a disposition rather
    than the spawn crashing on a `None` path.

    R4 obligation g1. The complementary member — a populated path — is every other test in
    this module, so the two arms are both driven."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair_prompt=None,
    )
    assert sc.run() == 0
    assert sc.category_of("f1") == "consumed_forward_bad"


def test_repair_prompt_resource_is_missing_or_unreadable_at_spawn_time_773(tmp_path):
    """A repair prompt that is CONFIGURED but missing is O10's fatal-config path: the tick
    ends loudly, before any gap record is written, and nothing is consumed.

    §7 FK-28: the quiet reading — skip the repair, mark every BAD pair terminal — silently
    deletes D1 on a deployment mistake no report names. Distinguished from `None` above,
    which is the design's own "no repair prompt configured" member."""
    missing = tmp_path / "nowhere" / "repair.md"
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair_prompt=missing,
    )
    with pytest.raises(FatalConfigError):
        sc.run()
    assert sc.gap_records() == []
    assert sc.category_of("f1") is None


# ---------------------------------------------------------------------------
# M4 — the second pass and its routing
# ---------------------------------------------------------------------------


def test_a_pass_one_bad_pair_is_terminal_unless_pass_two_approves_its_file_773(tmp_path):
    """Routing is keyed on PAIR VERDICTS, not on file survival: a pair BAD in pass 1 is
    terminal unless pass 2 shows it GOOD/EXEMPT on an approved file.

    Both arms, on one address: the repaired file's pair clears and commits; the
    unrepaired file's pair stays BAD and is consumed as `consumed_forward_bad`."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("fix", run_id="fix"), S.finding_row("keep", run_id="keep")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("fix"), "l2.md": S.lesson("keep")},
            committed=["fix", "keep"],
        ),
        verifier=S.FakeVerifier(
            # PHASE F REPAIR: was a content-sniffing `on_call` hook inspecting
            # `ctx.lesson_text` for "narrowed" — a fake deciding a verdict from payload
            # content, not returning a pre-declared one (rules.md: fakes inject faults,
            # never policy). A per-attempt SCHEDULE says the same thing declaratively:
            # pass 1 = BAD, pass 2 (after the repair spawn) = GOOD.
            verdicts={("l1.md", "fix"): ["BAD", "GOOD"], ("l2.md", "keep"): "BAD"},
            faults={},
        ),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("fix", body="narrowed")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON]
    assert sc.category_of("fix") == "consumed_committed"
    assert sc.category_of("keep") == "consumed_forward_bad"


def test_pass_two_re_checks_only_the_files_the_repair_spawn_changed_773(tmp_path):
    """Pass 2 re-verdicts only files whose bytes changed between the tick-start snapshot and
    the point pass 2 runs — i.e. the files the repair spawn actually wrote. A pass-1 verdict
    on a file the repair spawn never touched carries forward unchanged and is not
    re-submitted to the verifier.

    §7 FK-7 (dissolved): this is not a tiebreak policy — an unedited file's pass-1 verdict is
    simply never re-evaluated, so verifier noise can neither launder a refusal nor destroy an
    innocent batch-mate. It still catches the drive-by edit S6 was written for, which the
    next test drives."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("bad", body="narrowed")}),
    )
    assert sc.run() == 0
    assert len(sc.verifier.calls_for("l2.md")) == 1
    assert len(sc.verifier.calls_for("l1.md")) == 2


def test_repair_spawn_touches_a_file_beyond_the_bad_pairs_it_was_given_773(tmp_path):
    """A file the repair spawn newly wrote or edited — one it was never asked about — enters
    pass 2 and gets a full vouch plus verdict under M3.4, with no pass-1 baseline required.

    S6's actual concern: a repair-spawn drive-by edit to an unrelated file. Under §7 FK-7's
    narrowing, ANY file the repair spawn touches is re-verdicted, so nothing it writes
    escapes a verdict. Positive control: the drive-by file's BAD keeps it out of HEAD."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("side", run_id="side")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("side")},
            committed=["bad", "side"],
        ),
        verifier=S.FakeVerifier(
            verdicts={
                "l1.md": "BAD",
                # PHASE F REPAIR: was a content-sniffing `on_call` hook (see the sibling
                # repair above). Per-attempt schedule: pass 1 = GOOD (before the repair
                # spawn's drive-by edit), pass 2 = BAD (the drive-by write is refused).
                ("l2.md", "side"): ["GOOD", "BAD"],
            },
        ),
        repair=S.FakeRepair(
            writes={
                "l1.md": S.lesson("bad", body="narrowed"),
                "l2.md": S.lesson("side", body="drive-by rewrite"),
            }
        ),
    )
    assert sc.run() == 0
    assert len(sc.verifier.calls_for("l2.md")) == 2
    assert LESSON2 not in sc.head_files()


def test_repair_spawn_produces_no_edit_for_a_bad_pair_773(tmp_path):
    """A BAD pair the repair spawn left byte-for-byte untouched keeps its pass-1 BAD: it is
    not re-submitted, so no second verdict exists to overturn it, and the finding is
    terminal.

    §7 FK-7 corrects the reading RF-6 flagged — the file IS in the changed set, because the
    FIRST spawn dirtied it — so what stops a non-deterministic re-clear is the bytes-changed
    test, not the changed-set membership."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    assert len(sc.verifier.calls_for("l1.md")) == 1
    assert sc.category_of("f1") == "consumed_forward_bad"


def test_repair_spawns_output_is_byte_identical_to_the_pre_repair_file_773(tmp_path):
    """A repair spawn that rewrites the file with the SAME bytes changes nothing: the file's
    bytes did not change, so pass 2 does not re-verdict it and the pass-1 BAD stands.

    Same §7 FK-7 rule reached through the other door — a write that is a no-op must be
    treated as the no-op it is, or verifier noise gets a free second roll."""
    text = S.lesson("f1", body="unchanged")
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": text}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l1.md": text}),
    )
    assert sc.run() == 0
    assert len(sc.verifier.calls_for("l1.md")) == 1
    assert LESSON not in sc.head_files()


def test_pair_verdict_flips_between_passes_on_an_untouched_file_773(tmp_path):
    """A NEGATIVE demand: a pass-2 verdict never reaches an untouched file at all, so a
    pass-1 GOOD on a file nobody edited cannot be overturned by verifier noise, and a
    pass-1 BAD on one cannot be laundered into a commit.

    Both directions on the same address. The fake here would answer the OPPOSITE verdict on
    any second look; the assertion is that no second look happens."""
    flipped: list[str] = []

    def flip(ctx):
        if ctx.lesson_path.name in flipped:
            sc.verifier.verdicts[ctx.lesson_path.name] = "BAD"
        flipped.append(ctx.lesson_path.name)

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}, on_call=flip),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("bad", body="narrowed")}),
    )
    assert sc.run() == 0
    assert LESSON2 in sc.head_files()
    assert len(sc.verifier.calls_for("l2.md")) == 1


def test_pass_two_re_runs_verify_agent_state_and_re_checks_every_changed_file_773(tmp_path):
    """Between the two passes M4 re-runs `verify_agent_state`, so a repair spawn that writes
    outside the corpus is refused before its edits can reach a verdict or a commit.

    The out-of-scope guard is the reason the re-run exists; the rest of pass 2's scope is
    §7 FK-7's, tested above."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(outside={"defender/skills/elastic/SKILL.md": "rewritten"}),
    )
    assert sc.run() == 2
    assert sc.head_files() == []


def test_a_repair_spawn_that_writes_outside_the_corpus_773(tmp_path):
    """`verify_agent_state` re-runs after the repair spawn and refuses the out-of-scope
    write: the tick unwinds, the stray is reverted, and nothing commits.

    This is exactly the guard M4 re-runs it for."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(outside={"defender/scripts/adapters/elastic_adapter.py": "X"}),
    )
    assert sc.run() == 2
    assert (
        sc.repo / "defender/scripts/adapters/elastic_adapter.py"
    ).read_text(encoding="utf-8") == "VERBS = {}\n"


def test_a_repair_spawn_that_attempts_a_deletion_773(tmp_path):
    """No deletion lands from the repair spawn: its tool set is write-only with no `rm`
    (M4/S6/N6), so nothing can slip past pass 2 by being deleted — C17's `D`-drop means a
    deleted file is invisible to the second verdict pass.

    Driven at the grant, because the drain cannot observe a move the role cannot make."""
    from defender.learning.author.curator_engine import CORPUS_REPAIR_DEF

    assert CORPUS_REPAIR_DEF.tools.bash is False
    assert not getattr(CORPUS_REPAIR_DEF, "bash_shapes", ())


def test_the_repair_spawn_cannot_delete_a_corpus_file_773(tmp_path):
    """A NEGATIVE demand at the corpus: a pre-existing lesson the repair role might target
    is still in HEAD after a tick that ran a repair pass.

    Positive control on the same address, under the complementary condition: the FIRST
    spawn's `rm` IS granted (C19), and a deletion it makes does land in HEAD."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(deletes=("old.md",)),
    )
    sc.run()
    assert sc.head_text("defender/lessons/old.md") is not None

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}, deletes=("old.md",)),
    )
    assert control.run() == 0
    assert control.head_text("defender/lessons/old.md") is None


def test_a_repair_spawn_that_addresses_only_some_of_the_bad_pairs_in_one_file_773(tmp_path):
    """Approval is per file across all of its pairs: one still-BAD pair keeps the file
    unapproved even though its sibling pair is now GOOD. Routing stays per pair, so only the
    unfixed finding is terminal.

    The GOOD sibling is not lost — it is deferred, having no approved file left to cite."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a", "b")}, committed=["a", "b"]),
        verifier=S.FakeVerifier(
            # PHASE F REPAIR: was a content-sniffing `on_call` hook keyed on
            # `ctx.lesson_text`/`ctx.source_id`. Per-attempt schedule: "a" clears on its
            # second (pass-2) call; "b" stays BAD every attempt (a scalar).
            verdicts={"a": ["BAD", "GOOD"], "b": "BAD"}
        ),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("a", "b", body="half-fixed")}),
    )
    assert sc.run() == 0
    assert LESSON not in sc.head_files()
    assert sc.category_of("b") == "consumed_forward_bad"


def test_repair_spawn_creates_a_brand_new_file_773(tmp_path):
    """A file the repair spawn creates is on the same footing as any other changed file:
    `git status` reports it (untracked included, G1), pass 2 vouches and verdicts it, and if
    approved it is named in M5's explicit path list."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("a", "b")}, committed=["a", "b"]),
        verifier=S.FakeVerifier(verdicts={("l1.md", "b"): "BAD"}),
        repair=S.FakeRepair(
            writes={"l1.md": S.lesson("a", body="split"), "l2.md": S.lesson("b", body="split")}
        ),
    )
    assert sc.run() == 0
    assert ("l2.md", "b") in sc.verifier.pairs_seen
    assert LESSON2 in sc.head_files()


def test_repair_prompts_reasoning_text_for_a_pair_is_empty_773(tmp_path):
    """An empty reasoning string is carried into the repair prompt as-is and recorded
    verbatim in the ledger: M4 and O3 state no non-emptiness requirement, so only the
    FIELD'S PRESENCE is asserted, never its content.

    §7 FK-12: substituting a placeholder would be the drain inventing testimony."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD", reasoning=""),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    [record] = sc.gap_records()
    assert "reasoning" in record["verdicts"][0]
    assert record["verdicts"][0]["reasoning"] == ""


def test_pass_one_reasoning_unavailable_because_its_trace_write_failed_773(tmp_path):
    """The reasoning the repair prompt carries is the IN-MEMORY second element of
    `ForwardCheck.run`'s `(verdict, reasoning)` tuple, never re-read from the verifier trace
    file — so a failed or overwritten trace write does not change what the repair spawn
    receives.

    The fake writes no trace at all, and the reasoning still arrives."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD", reasoning="in-memory only"),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    [pair] = sc.repair.last_pairs
    assert pair.reasoning == "in-memory only"


# ---------------------------------------------------------------------------
# M4 — terminal files, restores, faults
# ---------------------------------------------------------------------------


def test_a_terminal_file_is_unlinked_if_new_and_restored_to_its_bytes_if_it_existed_773(
    tmp_path,
):
    """Terminal files are restored per file from `_snapshot_corpus`: unlinked when the tick
    created them, restored to their pre-tick bytes when they already existed.

    C6 grounds the snapshot's shape. Both arms in one tick, so neither can pass on the
    other's mechanism."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("new", run_id="new"), S.finding_row("old", run_id="old")],
        seed_corpus={"old.md": S.lesson("older")},
        curator=S.FakeCurator(
            writes={"new.md": S.lesson("new"), "old.md": S.lesson("older", "old")},
            committed=["new", "old"],
        ),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    assert not (sc.corpus / "new.md").exists()
    assert (sc.corpus / "old.md").read_text(encoding="utf-8") == S.lesson("older")


def test_a_terminal_file_edited_across_both_passes_restores_to_its_pre_tick_snapshot_773(
    tmp_path,
):
    """The restore lands on the TICK-START snapshot bytes, never on an intermediate state
    between the two spawns: `_snapshot_corpus` is taken once, before the first spawn (C6).

    A file edited by the curator and again by the repair spawn returns to what HEAD had."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"l1.md": S.lesson("older", body="original")},
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("older", "f1", body="first edit")}, committed=["f1"]
        ),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("older", "f1", body="second edit")}),
    )
    assert sc.run() == 0
    assert (sc.corpus / "l1.md").read_text(encoding="utf-8") == S.lesson(
        "older", body="original"
    )


def test_restoring_a_file_the_first_spawn_created_and_the_repair_spawn_further_edited_773(
    tmp_path,
):
    """The restore rule keys on ABSENCE from the tick-start snapshot, not on which spawn
    wrote last: a file the first spawn created and the repair spawn then edited is unlinked.

    A rule keyed on "last writer" would leave the repair spawn's version on disk, which the
    next tick's `git status` reads as ordinary dirt with valid citations."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1", body="created")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="edited again")}),
    )
    assert sc.run() == 0
    assert not (sc.corpus / "l1.md").exists()
    assert sc.corpus_files() == []


def test_restore_corpus_joins_repo_relative_and_corpus_relative_paths_correctly_773(tmp_path):
    """The per-file restore joins `_changed_corpus_records`' REPO-relative paths against
    `_snapshot_corpus`' CORPUS-relative keys and resolves to the right file — including for
    a lesson in a SUBDIRECTORY, where the two spellings differ by more than a prefix.

    R8 obligation g11 / RF-3: every bug of this class is on the READ side, so the assertion
    is that the restore actually happened, not that either side's shape is correct. A join
    that silently misses restores nothing and leaves the refused lesson on disk."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        seed_corpus={"nested/deep/l1.md": S.lesson("older", body="original")},
        curator=S.FakeCurator(
            writes={"nested/deep/l1.md": S.lesson("older", "f1", body="edited")},
            committed=["f1"],
        ),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={}),
    )
    assert sc.run() == 0
    assert (sc.corpus / "nested/deep/l1.md").read_text(encoding="utf-8") == S.lesson(
        "older", body="original"
    )


def test_snapshot_restore_cannot_read_back_a_terminal_files_original_bytes_773(tmp_path):
    """A restore that cannot complete is FATAL and loud: the tick aborts before any commit
    or rotation, a stuck record lands, and nothing is consumed.

    §7 FK-21. A partially-restored corpus is the one state that can put a refused lesson in
    HEAD on the NEXT tick, because that tick's `git status` reads it as ordinary dirt with
    valid citations — O1's failure mode arriving one tick late. Terminal files are therefore
    restored BEFORE the approved list is computed, so a restore failure can never coexist
    with a commit."""
    def break_the_corpus_dir(pairs, batch_id, cfg):
        (cfg.corpus_dir / "l1.md").unlink()
        (cfg.corpus_dir / "l1.md").mkdir()

    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
        repair=S.FakeRepair(also=break_the_corpus_dir),
    )
    with pytest.raises(IsADirectoryError):
        sc.run()
    assert sc.commit_count() == 1
    assert sc.consumed() == []


def test_a_faulting_repair_spawn_unwinds_and_the_batch_is_re_authored_under_attempts_773(
    tmp_path,
):
    """N8: a repair spawn that faults with a `RETIRE_SET` member unwinds through
    `_undo_agent_edits`, bumps `attempts`, and leaves the batch queued to be re-authored and
    repaired on a later tick.

    GL2 grounds the membership — `AuthorError` is one of the three, declared once at
    `drain.py:73`. D1 is per tick, so the finding gets a fresh repair budget next time."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(raises=S.author_error("repair spawn failed")),
    )
    assert sc.run() == 2
    assert sc.pending_by_id()["f1"]["attempts"] == 1
    assert sc.corpus_files() == []
    assert sc.gap_records() == []


def test_repair_spawn_model_call_fails_transiently_773(tmp_path):
    """A transient repair-spawn model failure surfacing as a `RETIRE_SET` member unwinds the
    tick, bumps `attempts`, and re-authors the batch on a later tick (N8).

    A retry INSIDE the model layer is not separately observable here — what the spec pins is
    the disposition of the failure that escapes it. GL2 grounds `ModelRetry`'s membership."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(raises=S.model_retry("transient")),
    )
    assert sc.run() == 2
    assert sc.pending_by_id()["f1"]["attempts"] == 1


def test_repair_spawn_faults_for_a_dependency_reason_distinct_from_a_box_violation_773(
    tmp_path,
):
    """N8 is CAUSE-BLIND: any `RETIRE_SET` member from the repair spawn unwinds and re-queues
    identically, whether it came from an out-of-scope write (`AuthorError`) or a failing tool
    call (`GitError`).

    Both members driven on one address, so a handler that learned to tell them apart fails."""
    for fault in (S.author_error("out of scope"), S.git_error("tool call failed")):
        sc = S.build_scene(
            tmp_path / type(fault).__name__,
            rows=[S.finding_row("f1", run_id="f1")],
            curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
            verifier=S.FakeVerifier(default="BAD"),
            repair=S.FakeRepair(raises=fault),
        )
        assert sc.run() == 2
        assert sc.pending_by_id()["f1"]["attempts"] == 1


def test_a_faulting_repair_spawn_lands_in_the_same_ordering_slot_as_a_faulting_first_spawn_773(
    tmp_path,
):
    """A faulting repair spawn lands in the same ordering slot as a faulting first spawn:
    undo, `attempts` bump, re-queue. D1's one-attempt framing changes nothing about the
    sequence.

    Both spawns driven with the same fault, and the two ticks' observable residue compared."""
    first = S.build_scene(
        tmp_path / "first",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(raises=S.author_error("boom")),
    )
    second = S.build_scene(
        tmp_path / "second",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(raises=S.author_error("boom")),
    )
    assert first.run() == second.run() == 2
    assert first.pending_by_id()["f1"]["attempts"] == 1
    assert second.pending_by_id()["f1"]["attempts"] == 1
    assert first.corpus_files() == second.corpus_files() == []


def test_a_repair_spawn_that_faults_after_editing_some_of_its_files_773(tmp_path):
    """The whole tick unwinds against the tick-start `_snapshot_corpus`: partial repair
    rewrites revert with everything else, and no partial-commit path exists.

    The fake writes one file and then raises, which is the shape a spawn killed mid-work
    leaves behind."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("a", run_id="a"), S.finding_row("b", run_id="b")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("a"), "l2.md": S.lesson("b")}, committed=["a", "b"]
        ),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(
            writes={"l1.md": S.lesson("a", body="half")},
            raises=S.author_error("killed mid-work"),
            raise_after_writes=True,
        ),
    )
    assert sc.run() == 2
    assert sc.corpus_files() == []
    assert sc.commit_count() == 1


def test_repair_spawn_underlying_transport_timeout_not_wrapped_as_a_known_fault_773(tmp_path):
    """ANY exception out of the repair spawn runs `_undo_agent_edits` before re-raising —
    `RETIRE_SET` membership decides only whether `attempts` is bumped and the batch
    re-queued, never whether the corpus is restored.

    §7 FK-34: the undo is a safety property and must not be conditional on exception
    classification. A raw transport timeout is none of GL2's three members, and the corpus
    still comes back. Positive control: a member fault DOES bump `attempts`."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(
            writes={"l1.md": S.lesson("f1", body="half")},
            raises=S.call_never_completed("transport timeout"),
            raise_after_writes=True,
        ),
    )
    with pytest.raises(ConnectionError):
        sc.run()
    assert sc.corpus_files() == []
    assert "attempts" not in sc.pending_by_id()["f1"]


# ---------------------------------------------------------------------------
# §7 FK-6 — a repair-caused unvouch is terminal for its own finding, not the tick
# ---------------------------------------------------------------------------


def test_a_repair_caused_unvouch_is_terminal_for_its_own_finding_only_773(tmp_path):
    """A file the REPAIR spawn leaves unvouched routes through the same terminal-file path
    as a repair-spawn BAD verdict — terminal for its own finding, restored per file — and
    never through `AuthorError`. Its already-cleared batch-mates still commit.

    §7 FK-6 (dissolved): the vouch-error-unwinds-everything rule stays exactly as-is for the
    FIRST spawn, where an unvouched file means an agent wrote something nobody asked for.
    After the repair spawn the drain already knows which findings the file owns, so it can
    refuse the file without refusing the batch — which is what O6 and D1 oblige."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson(body="citations dropped")}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON2]
    assert sc.category_of("ok") == "consumed_committed"
    assert sc.category_of("bad") == "consumed_forward_bad"


def test_a_repair_rewrite_that_drops_its_citations_is_refused_773(tmp_path):
    """The repair spawn's "keep the citations" instruction is a prompt-level instruction, so
    the drain enforces it mechanically: a rewrite that drops them does not commit.

    Positive control on the same address: a rewrite that KEEPS its citations and clears its
    verdict does commit."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        verifier=S.FakeVerifier(default="BAD"),
        repair=S.FakeRepair(writes={"l1.md": S.lesson(body="no citations at all")}),
    )
    assert sc.run() == 0
    assert LESSON not in sc.head_files()

    control = S.build_scene(
        tmp_path / "control",
        rows=[S.finding_row("f1", run_id="f1")],
        curator=S.FakeCurator(writes={"l1.md": S.lesson("f1")}),
        # PHASE F REPAIR: was a content-sniffing `on_call` hook set after construction;
        # replaced with a declarative per-attempt schedule (pass 1 = BAD, pass 2 = GOOD).
        verifier=S.FakeVerifier(verdicts={"l1.md": ["BAD", "GOOD"]}),
        repair=S.FakeRepair(writes={"l1.md": S.lesson("f1", body="narrowed")}),
    )
    assert control.run() == 0
    assert LESSON in control.head_files()


def test_repair_spawns_rewrite_leaves_the_files_frontmatter_unparseable_773(tmp_path):
    """An unparseable rewrite reads exactly like a dropped citation — `_cited_ids` returns
    `set()` for malformed frontmatter — and takes the same per-file terminal path, not the
    tick-wide one.

    The malformed bytes are written by the test and run through the real
    `split_frontmatter`, so the taxonomy is re-probed on every run rather than pinned."""
    sc = S.build_scene(
        tmp_path,
        rows=[S.finding_row("bad", run_id="bad"), S.finding_row("ok", run_id="ok")],
        curator=S.FakeCurator(
            writes={"l1.md": S.lesson("bad"), "l2.md": S.lesson("ok")},
            committed=["bad", "ok"],
        ),
        verifier=S.FakeVerifier(verdicts={"l1.md": "BAD"}),
        repair=S.FakeRepair(writes={"l1.md": S.malformed_lesson()}),
    )
    assert sc.run() == 0
    assert sc.head_files() == [LESSON2]
    assert sc.category_of("bad") == "consumed_forward_bad"
