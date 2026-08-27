"""Executable spec (written BEFORE the code) for design #647 — the DRIVEN-RUN half.

The demand list, structure, claims and gate live in `spec-flow/specs/spec_graph_647.yaml`;
the sweep/relocation half lives in `test_meta_json_retirement_647.py` beside it. One
test per `form: test` demand, named by its `discharged_by`, with the demand's
observable-outcome prose in the test's docstring.

**AMENDED BY #875.** This module's original obligation was the salt's ORIGIN: the run has ONE
trust token, minted by the production builder, and every salted surface carries that same one.
#875 F-1 found what that shape cost — a token shared across a run is a token the gather
subagent reads in plaintext on every payload view it is handed, and can therefore echo to
close the frame its own summary arrives in and keep writing in MAIN's host-text region.

So the origin obligation is retired rather than repaired: `wrap_fresh` mints each frame's
delimiter AFTER its content is in hand, and there is no run-scoped salt left to originate.
The four tests below state the successor obligations — the builder mints nothing, every frame
carries its own delimiter, no frame's salt occurs in its own body, and gather is bound with
none. Two of them assert the INVERSE of what this file used to require; each says so, and
says what the old reasoning got wrong.

**The second new pin** is message 0's run-dir listing. `orient` inlines the workspace map
into MAIN's first model request, and the map enumerates the run dir's children. Nothing
pinned that listing before, which is why three review passes and a cold review all missed
that deleting a file out of the run dir changes MAIN's prompt.

The machinery is the real replay harness: `drive()` runs the REAL `driver.run_investigation`
with a `FunctionModel`, so the salted wrappers observed here are exactly what the model sees.
Both fakeable boundaries — the model and the data-source verb registry — enter by INJECTION,
never by patching a module attribute.

Placed in `defender/tests/` rather than `defender/tests/e2e/` — beside the spec graph, as the
artifact rule requires, since `check_binds` scans only the graph's own directory for the
`discharged_by` docstrings. The `e2e` marker still routes it with the rest of the replay
suite.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from defender import run_common
from defender._run_paths import RunPaths
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

DEFENDER = Path(__file__).resolve().parents[1]
LEAD = "l-001"

ANY_RUN_TAG = re.compile(r"</?run-([0-9a-zA-Z]*)-([a-z-]+)>")
RUN_DIR_SECTION = re.compile(r"^## Run dir — .*$((?:\n- .*)*)", re.M)

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
    {"@timestamp": "2026-01-01T00:05:00Z", "user.name": "dev.dana", "event.action": "sudo"},
]




def build(tmp_path, monkeypatch, golden: Path = GOLDEN, run_id: str = "origin-647"):
    """Materialize a run dir with the REAL production builder.

    The runs base is redirected into `tmp_path` through the env var the builder itself
    resolves; everything else — the directory layout, the alert copy — is production code.

    Returned a `(run_dir, salt)` pair until #875. The builder no longer mints a token at all:
    `wrap_fresh` mints each frame's delimiter after its content is in hand, so there is no
    run-scoped salt for a builder to originate."""
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "runs"))
    return run_common.materialize_run_dir(golden / "alert.json", run_id)


def tokens(*transcripts: str) -> set[str]:
    """Every distinct salt token appearing inside a run-scoped delimiter across `transcripts`."""
    found: set[str] = set()
    for text in transcripts:
        found.update(m.group(1) for m in ANY_RUN_TAG.finditer(text))
    return found


def elastic_ok(rec: VerbRecorder) -> FakeVerbs:
    """A one-verb registry whose signature IS the param contract the real tool validates."""

    def query(ctx, *, native_query: str, limit: int = 10) -> list[dict]:
        rec.record("query", ctx, {"native_query": native_query, "limit": limit})
        return PAYLOAD

    return FakeVerbs({"elastic": {"query": query}})


def gather_scenario(run_dir: Path, *, run_id: str):
    """Drive a run that exercises all three salted vias in one run: orient's inlined raw alert
    and the gather return (api), a read of the alert file (fs), and the gather subagent's query
    against an injected registry (bash). Returns the two replay models."""
    rec = VerbRecorder()
    main = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("query", {
            "system": "elastic", "verb": "query",
            "params": {"native_query": "FROM logs | LIMIT 2"},
        })]),
        Turn(text="Summary: measured the lead."),
    ])
    drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=elastic_ok(rec))
    return main, gather, rec


def run_dir_listing(message_zero: str) -> list[str]:
    """The child names the workspace map enumerated into message 0's `## Run dir` section."""
    m = RUN_DIR_SECTION.search(message_zero)
    assert m, "message 0 carries no `## Run dir` section — the workspace map is missing"
    return [line[2:].split(" ")[0] for line in m.group(1).splitlines() if line.startswith("- ")]



def test_materialize_run_dir_returns_only_the_run_dir(tmp_path, monkeypatch):
    """The builder hands back the one thing it still owns: the run directory it created.

    AMENDED FROM `..._returns_run_dir_then_salt_on_the_success_lane` (#875). #647's obligation
    was that the run's ONE trust token has a single origin — the production builder — so that
    no surface could obtain a delimiter the others did not share. That obligation is discharged
    now by construction rather than by provenance: `wrap_fresh` mints each frame's salt AFTER
    its content is in hand, so there is no run-scoped token for anything to originate, share,
    or diverge from. A builder that returned one would be handing out the very object #875 F-1
    removed."""
    run_dir = build(tmp_path, monkeypatch)

    assert isinstance(run_dir, Path), "the builder no longer returns a bare run dir"
    assert run_dir.is_dir(), "the builder's returned run dir is not a real directory"
    assert run_dir.name == "origin-647"
    assert (run_dir / "alert.json").is_file()
    assert (run_dir / "gather_raw").is_dir()

    src = (DEFENDER / "run_common.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    builder = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "materialize_run_dir"
    )
    mints = [
        n for n in ast.walk(builder)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "secrets"
    ]
    assert not mints, (
        "materialize_run_dir still mints a run-scoped token — #875 removed the run salt; a "
        "token minted here can only be threaded to a party the frames it delimits are shown to"
    )


def test_every_frame_in_one_model_context_carries_its_own_salt(tmp_path, monkeypatch):
    """Every frame the model is shown carries a DISTINCT delimiter.

    THE INVERSE of #647's `..._carries_the_minted_token` and of #545's coherence canary, and
    deliberately so. Those pinned "exactly one distinct salt across the run", on the reasoning
    that a second token would leave the agent unable to match a delimiter it had been told
    about. #875 F-1 is what that reasoning cost: one token shared across a run is one token the
    gather subagent reads in plaintext on every payload view, and can therefore echo to close
    the frame its own summary arrives in.

    Nothing was actually resting on coherence. Both SKILL.md contracts ship a literal `{salt}`
    placeholder — neither MAIN nor GATHER is ever told a value — so both already read frames
    structurally, by matching open/close pairs. What replaces coherence is the property below,
    which coherence could never have given: no framed party holds its own delimiter."""
    run_dir = build(tmp_path, monkeypatch, golden=GOLDEN_AB3, run_id="per-frame-647")
    main, gather, rec = gather_scenario(run_dir, run_id=run_dir.name)

    main_seen, gather_seen = "\n".join(main.seen), "\n".join(gather.seen)
    seen = tokens(main_seen, gather_seen)
    assert seen, "no run-scoped delimiter was emitted at all — the sweep is vacuous"
    assert len(seen) > 1, (
        "every frame in the run shares one delimiter — the #875 F-1 shape is back: a framed "
        f"party that sees one frame can close another. tokens={sorted(seen)}"
    )
    for token in seen:
        assert re.fullmatch(r"[0-9a-f]+", token), f"a delimiter is not lowercase hex: {token!r}"


def test_no_frames_salt_occurs_inside_the_content_it_delimits(tmp_path, monkeypatch):
    """A frame's delimiter never appears in that frame's own body.

    This is the guarantee `wrap_fresh`'s re-mint loop buys, and the one the old per-run token
    could not: the salt is drawn AFTER the content is in hand and re-drawn while it collides,
    so the body cannot contain the delimiter — by construction, not by improbability."""
    run_dir = build(tmp_path, monkeypatch, golden=GOLDEN_AB3, run_id="no-echo-647")
    main, gather, rec = gather_scenario(run_dir, run_id=run_dir.name)

    checked = 0
    for transcript in ("\n".join(main.seen), "\n".join(gather.seen)):
        for m in re.finditer(r"<run-([0-9a-f]+)-([a-z_-]+)>\n(.*?)\n</run-\1-\2>", transcript, re.S):
            salt, body = m.group(1), m.group(3)
            assert salt not in body, (
                f"a frame's own salt {salt!r} occurs inside the content it delimits — the "
                "framed party can close its own frame"
            )
            checked += 1
    assert checked, "no complete frame was found to check — the sweep is vacuous"


def test_the_gather_subagent_is_bound_with_no_salt_at_all(tmp_path, monkeypatch):
    """The gather subagent inherits NO token, because there is none to inherit.

    AMENDED PREMISE (#875 F-1). This test used to require the opposite — that gather
    INHERITS the parent run's token — reasoning that a fresh token on gather's side "would wrap
    the returned summary in a delimiter MAIN was never told about, quarantine failing open at
    exactly the boundary it exists to guard."

    That reasoning inverts the direction of the threat. `_run_gather` re-wraps gather's output
    unconditionally before it reaches MAIN, so a foreign inner tag is inert TEXT inside MAIN's
    frame — it cannot close anything. Inheritance is what fails open: it hands the subagent
    whose output MAIN frames the very delimiter MAIN frames it with. MAIN was never "told" any
    delimiter in the first place — `defender/SKILL.md` ships a literal `{salt}` placeholder."""
    run_dir = build(tmp_path, monkeypatch, golden=GOLDEN_AB3, run_id="no-inherit-647")
    main, gather, rec = gather_scenario(run_dir, run_id=run_dir.name)

    main_seen, gather_seen = "\n".join(main.seen), "\n".join(gather.seen)
    gather_tokens, main_tokens = tokens(gather_seen), tokens(main_seen)
    assert gather_tokens, "the subagent's own surfaces carry no delimiter at all"
    assert main_tokens, "MAIN's surfaces carry no delimiter at all"
    assert not (gather_tokens & main_tokens), (
        "a delimiter is shared between the gather subagent and MAIN — gather can close the "
        f"frame its own summary returns inside (#875 F-1): {sorted(gather_tokens & main_tokens)}"
    )

    src = (DEFENDER / "runtime" / "tools_gather.py").read_text(encoding="utf-8")
    assert not re.search(r"bind\(\s*GATHER_DEF[^)]*salt\s*=", src), \
        "the gather dispatch passes a salt into bind(GATHER_DEF, …)"


def test_a_driven_run_leaves_no_meta_json_in_the_run_dir(tmp_path, monkeypatch):
    """A driven run leaves no run-dir metadata file behind. The builder never writes one, and
    nothing downstream recreates it: after a full driven run the directory holds no such file
    at any depth. No completion marker replaces it — the file was the last unconditional write
    and so incidentally marked 'materialization finished', but nothing ever consumed that
    property and none is owed."""
    run_dir = build(tmp_path, monkeypatch, run_id="no-meta-647")
    assert run_dir.is_dir(), "the builder materialized no run dir to inspect"
    assert not (run_dir / "meta.json").exists(), "the builder still writes the metadata file"

    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_dir.name, main=replay)

    assert not list(run_dir.rglob("meta.json")), (
        f"a metadata file reappeared: {[str(p) for p in run_dir.rglob('meta.json')]}"
    )


def test_run_dir_still_carries_every_investigation_artifact_after_the_removal(
    tmp_path, monkeypatch
):
    """Removing the metadata file costs the run dir nothing an operator or the learning loop
    reads. A driven run still produces the copied alert, the raw-payload subdir, the
    investigation log and the report the loop's normalizer parses, plus the live request log
    and its projected tool trace. The narrowed obligation is exactly this: the same
    investigation artifacts and the same salted surfaces — not the same directory listing."""
    run_dir = build(tmp_path, monkeypatch, golden=GOLDEN, run_id="artifacts-647")
    assert (run_dir / "alert.json").is_file(), (
        "the builder did not materialize the copied alert it owns"
    )
    assert (run_dir / "gather_raw").is_dir(), (
        "the builder did not materialize the raw-payload subdir it owns"
    )
    inv_text = (GOLDEN / "investigation.md").read_text(encoding="utf-8")

    # #774/R1: report.md left the model's write allow-list — the golden's own disposition
    # (inconclusive) commits straight through the close tool with no gate work, so no
    # review_stages injection is needed here either.
    # #810: investigation.md is landed by `append_block` — onto a run dir the builder seeded
    # without it, so the append is the create and the golden still reconstructs whole.
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": inv_text})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_dir.name, main=replay)

    for name in ("alert.json", "investigation.md", "report.md", "tool_trace.jsonl"):
        assert (run_dir / name).is_file(), f"{name} is missing from the run dir"
    # Named through `RunPaths` and not joined onto the root: the wire log sits under
    # `wire_logs/`, which is what keeps it outside every reader's run-dir read shape.
    assert RunPaths(run_dir).wire_log.is_file(), "the wire log is missing from the run dir"
    assert (run_dir / "gather_raw").is_dir()
    assert (run_dir / "investigation.md").read_text(encoding="utf-8") == inv_text
    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(encoding="utf-8"), re.M)
    assert m, "the report's disposition frontmatter no longer parses"




def test_message_zero_orientation_lists_exactly_the_materialized_run_dir_children(
    tmp_path, monkeypatch
):
    """MAIN's first model request enumerates the run dir's REAL children, and the removed file
    is not among them. The orientation inlines a workspace map whose run-dir section lists one
    line per child, skipping only the subagent-only raw-payload subdir; every name it lists
    exists on disk, and every artifact the builder materialized appears. This listing was
    unpinned before this change, which is precisely why removing a file that gets listed —
    and therefore altering MAIN's prompt — went unnoticed through three review passes. The
    listing legitimately loses that one line; the section itself stays."""
    run_dir = build(tmp_path, monkeypatch, run_id="msg0-647")
    assert run_dir.is_dir(), (
        "there is no materialized run dir for the orientation to enumerate"
    )
    materialized = {p.name for p in run_dir.iterdir()}
    assert "meta.json" not in materialized

    replay = ReplayFn([Turn(text="Done.")])
    drive(run_dir, run_id=run_dir.name, main=replay)

    listed = run_dir_listing(replay.seen[0])
    assert listed == sorted(listed), "the listing is not in sorted order"
    assert "meta.json" not in listed, "message 0 still advertises the removed file to MAIN"
    assert "gather_raw" not in listed, "the subagent-only raw tree leaked into the orientation"

    on_disk = {p.name for p in run_dir.iterdir()}
    assert set(listed) <= on_disk, (
        f"message 0 lists names that do not exist in the run dir: {set(listed) - on_disk}"
    )
    # `provenance.json` joins `gather_raw` in the exclusion for the reason `_UNLISTED` gives:
    # the map IS the model's directory view, and the run's record of the commit it was built
    # from is infrastructure the OPERATOR reads. Listing it would invite MAIN to reason about
    # its own build, which is not a fact about the case in front of it.
    unlisted = {"gather_raw", "provenance.json"}
    assert (materialized - unlisted) <= set(listed), (
        f"a materialized artifact is missing from message 0: "
        f"{(materialized - unlisted) - set(listed)}"
    )
    assert "provenance.json" not in listed, (
        "the run's own provenance stamp leaked into MAIN's directory view"
    )


def test_replayed_message_zero_listing_matches_the_production_run_dir_file_set(
    tmp_path, monkeypatch
):
    """The replayed orientation shifts with the harness's own builder, so the harness must drop
    the metadata write too. Deleting that write is NOT a pure deletion: the harness's run dir
    is what the replayed message 0 enumerates, so a harness still writing the file would keep
    advertising it to the model long after production stopped producing it — a suite green on
    pass/fail while pinning a prompt production can no longer emit. The listing a replayed run
    shows must name only files a production run would have."""
    harness_dir = materialize(tmp_path / "h", GOLDEN)
    assert not (harness_dir / "meta.json").exists(), (
        "the replay harness still writes the metadata file into its run dir"
    )

    prod_dir = build(tmp_path, monkeypatch, run_id="replay-msg0-647-prod")
    assert prod_dir.is_dir(), (
        "there is no production run dir to compare the replayed listing against"
    )

    replay = ReplayFn([Turn(text="Done.")])
    drive(harness_dir, run_id="replay-msg0-647", main=replay)
    listed = run_dir_listing(replay.seen[0])

    assert "meta.json" not in listed, "the replayed message 0 still advertises the removed file"
    production_names = {p.name for p in prod_dir.iterdir()}
    # `production_names` is `materialize_run_dir`'s snapshot, taken BEFORE
    # `run_investigation` starts; `tool_trace.jsonl` and (#705)
    # `session_store_pointer.json` are both written by `run_investigation` itself, between
    # that snapshot and message 0 — present in a real run by the time the model sees the
    # listing, just not in this earlier snapshot. The wire log is written in that window too
    # but is NOT allowed for here: it lands under `wire_logs/`, which the map suppresses along
    # with `gather_raw/` because the read gate refuses both.
    assert set(listed) <= production_names | {
        "tool_trace.jsonl", "session_store_pointer.json",
    }, (
        f"the replayed listing names files a production run dir never has: "
        f"{set(listed) - production_names}"
    )


def test_replay_harness_run_dir_and_production_run_dir_present_the_same_file_set(
    tmp_path, monkeypatch
):
    """The two run-dir builders present the same file set FOR A FIXTURE THAT CARRIES NO
    SIBLING `ground_truth.yaml` — the scope of this parity claim, stated rather than implied.
    The harness keeps its own divergent signature — it takes the token as a parameter and
    hands back a bare path — and convergence on that signature is not owed; what IS owed is
    that a run dir a scenario drives looks like a run dir an operator gets, because the change
    edits the two builders separately and their file sets can otherwise drift silently.
    Immediately after materialization, before anything is driven, both hold exactly the copied
    alert and the raw-payload subdir.

    The scope is not decoration: the production builder conditionally copies a sibling
    `ground_truth.yaml` into the run dir (`run_common.py:69-71`) and the replay harness has NO
    such branch, so on a ground-truth-carrying fixture the two builders PROVABLY diverge by
    exactly that file. That axis is out of this change's scope — neither builder's ground-truth
    handling is edited here — so rather than assert a parity that does not hold, this pin
    checks its own precondition (the driven golden carries no sibling ground truth) and claims
    nothing about the other column."""
    assert not (GOLDEN / "ground_truth.yaml").exists(), (
        "this parity claim is scoped to fixtures WITHOUT a sibling ground_truth.yaml, and the "
        "golden now carries one — the production builder would copy it and the harness would "
        "not, so the scope condition no longer holds and the claim must be re-derived"
    )
    prod_dir = build(tmp_path, monkeypatch, run_id="parity-647")
    assert prod_dir.is_dir(), (
        "the production builder produced no run dir to compare file sets with"
    )
    harness_dir = materialize(tmp_path / "h", GOLDEN)

    prod_names = {p.name for p in prod_dir.iterdir()}
    harness_names = {p.name for p in harness_dir.iterdir()}
    assert prod_names == harness_names, (
        f"the two builders' run dirs diverge: production={sorted(prod_names)} "
        f"harness={sorted(harness_names)}"
    )
    assert prod_names == {"alert.json", "gather_raw", "provenance.json"}
