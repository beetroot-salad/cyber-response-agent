"""Executable spec (written BEFORE the code) for design #647 — the DRIVEN-RUN half.

The demand list, structure, claims and gate live in `defender/tests/spec_graph_647.yaml`;
the sweep/relocation half lives in `test_meta_json_retirement_647.py` beside it. One
test per `form: test` demand, named by its `discharged_by`, with the demand's
observable-outcome prose in the test's docstring.

**What is new here.** The run's central obligation is the salt's ORIGIN, not its coherence
downstream. The existing coherence canary (`test_salt_coherence_545.py`) injects a hardcoded
token at BOTH ends — into the harness's fixture builder and into `drive()` — so it never
crosses the seam this change creates. Every test below that touches the salt calls the REAL
production builder, `run_common.materialize_run_dir`, and follows the value it RETURNS
through the real driver to the surfaces the model sees. Nothing here hardcodes a salt.

**The second new pin** is message 0's run-dir listing. `orient` inlines the workspace map
into MAIN's first model request, and the map enumerates the run dir's children. Nothing
pinned that listing before, which is why three review passes and a cold review all missed
that deleting a file out of the run dir changes MAIN's prompt.

RED AGAINST HEAD IS THE EXPECTED STATE: `materialize_run_dir` still returns a bare `Path`,
so every tuple unpack below raises today. That is the contract, not a skeleton to grow.

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

# Any run-scoped delimiter, whatever its tag — the sweep must be able to SEE a foreign token,
# not just confirm the expected one is present.
ANY_RUN_TAG = re.compile(r"</?run-([0-9a-zA-Z]*)-([a-z-]+)>")
RUN_DIR_SECTION = re.compile(r"^## Run dir — .*$((?:\n- .*)*)", re.M)

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
    {"@timestamp": "2026-01-01T00:05:00Z", "user.name": "dev.dana", "event.action": "sudo"},
]


# ── production-builder scenario plumbing ─────────────────────────────────────


def build(tmp_path, monkeypatch, golden: Path = GOLDEN, run_id: str = "origin-647"):
    """Materialize a run dir with the REAL production builder and return `(run_dir, salt)`.

    This is the seam under test: the runs base is redirected into `tmp_path` through the env
    var the builder itself resolves, and everything else — the directory layout, the alert
    copy, the token mint — is production code. No salt is supplied; the builder's is the only
    one in play.
    """
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "runs"))
    run_dir, salt = run_common.materialize_run_dir(golden / "alert.json", run_id)
    return run_dir, salt


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


def gather_scenario(run_dir: Path, salt: str, *, run_id: str):
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
    drive(run_dir, run_id=run_id, salt=salt, main=main, gather=gather, verbs=elastic_ok(rec))
    return main, gather, rec


def run_dir_listing(message_zero: str) -> list[str]:
    """The child names the workspace map enumerated into message 0's `## Run dir` section."""
    m = RUN_DIR_SECTION.search(message_zero)
    assert m, "message 0 carries no `## Run dir` section — the workspace map is missing"
    return [line[2:].split(" ")[0] for line in m.group(1).splitlines() if line.startswith("- ")]


# ═════════════════════════════════════════════════════════════════════════════
# The return contract
# ═════════════════════════════════════════════════════════════════════════════


def test_materialize_run_dir_returns_run_dir_then_salt_on_the_success_lane(tmp_path, monkeypatch):
    """On the success lane the builder hands back BOTH things it owns, in order: the run
    directory it created, then the per-run trust token it minted. The run dir is a real
    directory carrying the copied alert and the raw-payload subdir; the token is a real
    non-empty string. The builder itself writes the token nowhere: the metadata file that
    used to hold a second, readable copy is gone, and no consumer reads one back off disk.
    What this does NOT claim is that the token has no on-disk presence at all — a DRIVEN run
    still streams every model message into `llm_requests.jsonl` (runtime/observe.py's request
    logger), and those messages contain the delimiter verbatim, so the token lands there.
    That copy is pre-existing, out of scope for this change, and not a regression; the change
    removes one of the two on-disk copies. The design's own non-obligation says the same:
    "This is not hardening. The change denies no principal access to the salt.\""""
    run_dir, salt = build(tmp_path, monkeypatch)

    assert isinstance(run_dir, Path), "the builder did not return a Path for the run dir"
    assert run_dir.is_dir(), "the builder's returned run dir is not a real directory"
    assert run_dir.name == "origin-647"
    assert (run_dir / "alert.json").is_file()
    assert (run_dir / "gather_raw").is_dir()

    assert isinstance(salt, str), "the builder returned a trust token that is not a string"
    assert salt, "the builder returned no trust token"

    # Two builds mint independent tokens — the value is per-run, not a constant.
    other_dir, other_salt = build(tmp_path, monkeypatch, run_id="origin-647-b")
    assert other_salt != salt, "two runs share a trust token"
    assert other_dir != run_dir


def test_builder_early_exit_lanes_fire_before_any_salt_is_minted(tmp_path, monkeypatch):
    """The pair is promised on the success lane ONLY. Both guard lanes above the mint exit the
    process outright — a missing alert file, and a run id whose directory already exists — so
    neither returns a run dir, a token, or anything at all. A caller that unpacks the pair can
    therefore never receive a half-built one, and the exclusive run-dir key survives: a second
    build on the same id exits rather than adopting the first's directory."""
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / "runs"))

    missing = tmp_path / "does-not-exist.json"
    assert not missing.exists()
    with pytest.raises(SystemExit) as exc:
        run_common.materialize_run_dir(missing, "early-exit-647")
    assert "alert not found" in str(exc.value)
    assert not (tmp_path / "runs" / "early-exit-647").exists(), (
        "the missing-alert lane created a run dir before exiting"
    )

    run_dir, salt = build(tmp_path, monkeypatch, run_id="collision-647")
    with pytest.raises(SystemExit) as exc:
        run_common.materialize_run_dir(GOLDEN / "alert.json", "collision-647")
    assert "already exists" in str(exc.value)
    # The colliding call minted nothing: the first run's directory is untouched.
    assert sorted(p.name for p in run_dir.iterdir()) == ["alert.json", "gather_raw"]
    assert salt


# ═════════════════════════════════════════════════════════════════════════════
# The origin pin — the obligation this change actually creates
# ═════════════════════════════════════════════════════════════════════════════


def test_salt_returned_by_the_builder_is_the_salt_that_reaches_run_investigation(
    tmp_path, monkeypatch
):
    """The token the builder RETURNS is the token that reaches the investigation and shows up
    on the surfaces the model sees. This crosses the seam the change creates: the value is not
    supplied by the test, it is minted by production code and followed through — the run dir
    the builder produced is the run dir driven, and the delimiter wrapped around the raw alert
    in MAIN's first model request carries that same minted value and no other. A builder that
    returned one token while the run used another would leave every quarantine delimiter
    forgeable, and no existing pin crosses this seam: the coherence canary injects a hardcoded
    token at both ends and never calls the builder at all."""
    run_dir, salt = build(tmp_path, monkeypatch)
    assert run_dir.is_dir(), (
        "there is no run dir to follow the minted token through: the builder returned "
        f"{run_dir}"
    )
    assert salt, (
        "there is no minted token to follow: the builder returned "
        f"{salt!r} for {run_dir}"
    )
    replay = ReplayFn([Turn(text="Done.")])
    drive(run_dir, run_id=run_dir.name, salt=salt, main=replay)

    message_zero = replay.seen[0]
    assert f"<run-{salt}-untrusted>" in message_zero, (
        "the raw alert in message 0 is not wrapped with the token the builder returned"
    )
    assert f"</run-{salt}-untrusted>" in message_zero
    assert tokens(*replay.seen) == {salt}, (
        f"a token other than the builder's reached the run: {tokens(*replay.seen)}"
    )


def test_every_salted_surface_in_one_model_context_carries_the_minted_token(
    tmp_path, monkeypatch
):
    """Every salted surface feeding the model carries the SAME token — the one the builder
    minted — across all three access vias in a single driven run: the raw alert inlined into
    the orientation and the gather subagent's returned summary (the api lane), the read of the
    alert file (the fs lane), and the query output the gather subagent pulls from a data source
    (the bash lane). A constraint pinned on one surface and absent on its sibling is the
    canonical fail-open: a fresh token per wrap lets the model forge a closing delimiter."""
    run_dir, salt = build(tmp_path, monkeypatch, golden=GOLDEN_AB3, run_id="coherence-647")
    assert run_dir.is_dir(), (
        f"no run dir to carry the salted surfaces: builder returned {run_dir}"
    )
    assert salt, (
        f"no token to carry across the salted surfaces: builder returned {salt!r}"
    )
    main, gather, rec = gather_scenario(run_dir, salt, run_id=run_dir.name)

    main_seen = "\n".join(main.seen)
    gather_seen = "\n".join(gather.seen)

    # api — the orientation's raw alert, and the gather return riding back into MAIN.
    assert f"<run-{salt}-untrusted>" in main.seen[0], "the orient alert wrap is missing"
    assert main.seen[-1].count(f"<run-{salt}-untrusted>") >= 2, (
        "the gather return did not come back untrusted-wrapped with the run's token"
    )
    # fs — the read of the alert file.
    assert f"<run-{salt}-untrusted>" in main.seen[1], "the read_file result is not salt-wrapped"
    # bash — the data-source payload the gather subagent saw.
    assert rec.calls, "the injected verb never ran — the bash lane was not exercised"
    assert f"<run-{salt}-untrusted>" in gather_seen, "the query return is not salt-wrapped"

    assert tokens(main_seen, gather_seen) == {salt}, (
        f"more than one token across the run's salted surfaces: {tokens(main_seen, gather_seen)}"
    )


def test_gather_subagent_is_bound_with_the_parent_token_not_a_fresh_mint(tmp_path, monkeypatch):
    """The gather subagent INHERITS the parent run's token rather than minting its own. It runs
    concurrently over the same run dir and returns the primary untrusted channel into the main
    loop, so a fresh token on its side would wrap the returned summary in a delimiter MAIN was
    never told about — quarantine failing open at exactly the boundary it exists to guard."""
    run_dir, salt = build(tmp_path, monkeypatch, golden=GOLDEN_AB3, run_id="inherit-647")
    assert run_dir.is_dir(), (
        f"no parent run dir for the subagent to run over: builder returned {run_dir}"
    )
    assert salt, (
        f"no parent token for the subagent to inherit: builder returned {salt!r}"
    )
    main, gather, rec = gather_scenario(run_dir, salt, run_id=run_dir.name)

    gather_seen = "\n".join(gather.seen)
    assert f"<run-{salt}-" in gather_seen, "the subagent's own surfaces carry no token at all"
    assert tokens(gather_seen) == {salt}, (
        f"the gather subagent used a token the parent never minted: {tokens(gather_seen)}"
    )
    # The summary crosses back into MAIN under the same token.
    assert f"<run-{salt}-untrusted>" in main.seen[-1]


def test_no_surface_on_the_run_lane_obtains_a_salt_from_a_source_no_other_surface_knows(
    tmp_path, monkeypatch
):
    """No surface on the run lane obtains its token from a source the other surfaces do not
    share. Sweeping every run-scoped delimiter emitted anywhere in a driven run — both model
    contexts, every via — yields exactly one distinct token, and it is the one the builder
    returned. The sweep matches ANY token shape, so a foreign one would be seen rather than
    silently skipped; that a second, independently minted token is genuinely constructible in
    this system is the paired positive control on the curator leg."""
    run_dir, salt = build(tmp_path, monkeypatch, golden=GOLDEN_AB3, run_id="one-token-647")
    assert run_dir.is_dir(), (
        f"no run dir whose surfaces could be swept: builder returned {run_dir}"
    )
    assert salt, (
        f"no known token to compare the run's surfaces against: builder returned {salt!r}"
    )
    main, gather, rec = gather_scenario(run_dir, salt, run_id=run_dir.name)

    seen = tokens("\n".join(main.seen), "\n".join(gather.seen))
    assert seen, "no run-scoped delimiter was emitted at all — the sweep is vacuous"
    assert seen == {salt}, f"a surface used an unshared token: {sorted(seen - {salt})}"


def test_fail_open_fresh_mint_is_not_reachable_from_run_py_through_the_driver(
    tmp_path, monkeypatch
):
    """The fail-open fresh mint is unreachable from the run lane. The deleted resolver answered
    an unresolvable run dir with a brand-new token — a caller taking that answer would wrap
    with something no other surface knew — and nothing reintroduces that shape. On the run lane
    the token comes straight from the builder, so every delimiter emitted in a driven run
    carries the builder's 16-character token and never the 32-character shape the fresh-mint
    fallback produces."""
    from defender.hooks import _run_dir as hooks_run_dir

    assert not hasattr(hooks_run_dir, "read_meta_salt"), (
        "the fail-open salt reader survives on the run lane's import graph"
    )

    run_dir, salt = build(tmp_path, monkeypatch, run_id="no-failopen-647")
    assert run_dir.is_dir(), (
        f"the run lane has no builder-supplied run dir at all: builder returned {run_dir}"
    )
    assert salt, (
        f"the run lane has no builder-supplied token at all: builder returned {salt!r}"
    )
    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_dir.name, salt=salt, main=replay)

    seen = tokens(*replay.seen)
    assert seen == {salt}
    assert all(len(t) == 16 for t in seen), (
        f"a token of fallback shape reached the run lane: {sorted(seen)}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# The salt's domain
# ═════════════════════════════════════════════════════════════════════════════


def test_empty_string_salt_is_not_constructible_once_the_disk_read_is_gone(
    tmp_path, monkeypatch
):
    """An empty token is not constructible on the run lane. It used to be: the salt was read
    back out of a JSON file with an empty-string default, so any blob missing the key yielded
    one — and an empty token collapses the delimiter to a frame with no token between the
    dashes, which the binding seam passes through unresolved because it keys its fallback on
    the value being absent rather than falsy. With the value coming straight from the mint,
    that lane is gone: even with a stale metadata blob planted in the run dir carrying no
    token at all, the run's delimiters carry the builder's real token."""
    run_dir, salt = build(tmp_path, monkeypatch, run_id="no-empty-647")
    assert salt != "", "the builder returned an empty token"

    # The real fault, induced through the real filesystem: a leftover blob with no salt key,
    # exactly the shape the deleted read would have turned into an empty token.
    (run_dir / "meta.json").write_text('{"run_id": "no-empty-647"}', encoding="utf-8")

    replay = ReplayFn([Turn(text="Done.")])
    drive(run_dir, run_id=run_dir.name, salt=salt, main=replay)

    message_zero = replay.seen[0]
    assert "<run--untrusted>" not in message_zero, (
        "a degenerate token-less delimiter reached the model"
    )
    assert f"<run-{salt}-untrusted>" in message_zero
    assert tokens(*replay.seen) == {salt}


def test_minted_salt_is_sixteen_lowercase_hex_characters(tmp_path, monkeypatch):
    """The shipped token is sixteen lowercase hexadecimal characters, drawn from the
    cryptographic generator — the distinguished default column of the token's domain, and the
    positive control for the empty-token negative. Its alphabet is what keeps the rendered
    delimiter frame free of anything the surrounding markup could reinterpret, and its
    unguessability is what a payload author, who writes text before wrapping and never sees the
    run dir, cannot defeat."""
    seen = set()
    for i in range(3):
        _run_dir, salt = build(tmp_path, monkeypatch, run_id=f"shape-647-{i}")
        assert re.fullmatch(r"[0-9a-f]{16}", salt), f"token shape drifted: {salt!r}"
        seen.add(salt)
    assert len(seen) == 3, "the mint is not per-run"


def test_minted_salt_is_independent_of_the_run_id_and_drawn_from_secrets(tmp_path, monkeypatch):
    """The token's value is INDEPENDENT of the run id — it is drawn from the cryptographic
    generator, not derived from anything an outsider can name. This is the token's whole
    security property, and no other pin in this suite has it: uniqueness-per-run, shape, and
    coherence are all satisfied by a seeded PRNG keyed on the run id
    (`random.Random(run_id).getrandbits(64)`), which would hand every delimiter to anyone who
    can guess the run id — and the run id is `{utc_timestamp}-{alert.stem}`, both of which a
    payload author can influence or predict. Two builds under the SAME run id therefore mint
    DIFFERENT tokens, and the builder's mint site names `secrets`, whose entropy source is the
    OS rather than a caller-visible seed."""
    salts = set()
    for i in range(3):
        monkeypatch.setenv("DEFENDER_RUNS_BASE", str(tmp_path / f"runs-{i}"))
        _run_dir, salt = run_common.materialize_run_dir(GOLDEN / "alert.json", "same-run-id-647")
        salts.add(salt)
    assert len(salts) == 3, (
        "the same run id minted the same token more than once — the mint is a function of the "
        f"run id, not of an entropy source: {sorted(salts)}"
    )

    # The mint site itself: a seeded-PRNG implementation satisfies the behavioural arm above
    # only by accident of the seed, so the generator is pinned by name too.
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
    assert mints, (
        "materialize_run_dir mints its token from something other than `secrets` — the "
        "unguessability of every quarantine delimiter rests on this generator"
    )
    seeded = [
        n for n in ast.walk(builder)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name) and n.func.value.id in {"random", "hashlib"}
    ]
    assert not seeded, "the builder derives its token from a seedable generator"


# ═════════════════════════════════════════════════════════════════════════════
# The removed file
# ═════════════════════════════════════════════════════════════════════════════


def test_a_driven_run_leaves_no_meta_json_in_the_run_dir(tmp_path, monkeypatch):
    """A driven run leaves no run-dir metadata file behind. The builder never writes one, and
    nothing downstream recreates it: after a full driven run the directory holds no such file
    at any depth. No completion marker replaces it — the file was the last unconditional write
    and so incidentally marked 'materialization finished', but nothing ever consumed that
    property and none is owed."""
    run_dir, salt = build(tmp_path, monkeypatch, run_id="no-meta-647")
    assert run_dir.is_dir(), "the builder materialized no run dir to inspect"
    assert not (run_dir / "meta.json").exists(), "the builder still writes the metadata file"

    replay = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_dir.name, salt=salt, main=replay)

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
    run_dir, salt = build(tmp_path, monkeypatch, golden=GOLDEN, run_id="artifacts-647")
    assert (run_dir / "alert.json").is_file(), (
        "the builder did not materialize the copied alert it owns"
    )
    assert (run_dir / "gather_raw").is_dir(), (
        "the builder did not materialize the raw-payload subdir it owns"
    )
    inv_text = (GOLDEN / "investigation.md").read_text(encoding="utf-8")
    rep_text = (GOLDEN / "report.md").read_text(encoding="utf-8")

    replay = ReplayFn([
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "investigation.md"),
                                         "content": inv_text})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": rep_text})]),
        Turn(text="Done."),
    ])
    drive(run_dir, run_id=run_dir.name, salt=salt, main=replay)

    for name in ("alert.json", "investigation.md", "report.md",
                 "llm_requests.jsonl", "tool_trace.jsonl"):
        assert (run_dir / name).is_file(), f"{name} is missing from the run dir"
    assert (run_dir / "gather_raw").is_dir()
    assert (run_dir / "investigation.md").read_text(encoding="utf-8") == inv_text
    m = re.search(r"^disposition:\s*(\w+)", (run_dir / "report.md").read_text(encoding="utf-8"), re.M)
    assert m, "the report's disposition frontmatter no longer parses"


# ═════════════════════════════════════════════════════════════════════════════
# The message-0 listing — pinned here for the first time
# ═════════════════════════════════════════════════════════════════════════════


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
    run_dir, salt = build(tmp_path, monkeypatch, run_id="msg0-647")
    assert run_dir.is_dir(), (
        "there is no materialized run dir for the orientation to enumerate"
    )
    assert salt, (
        "there is no minted token to drive the orientation with"
    )
    materialized = {p.name for p in run_dir.iterdir()}
    assert "meta.json" not in materialized

    replay = ReplayFn([Turn(text="Done.")])
    drive(run_dir, run_id=run_dir.name, salt=salt, main=replay)

    # SCOPE — this pin does NOT bless what the listing contains, only that it tracks the run
    # dir's real children and no longer names the removed file. In particular it does not
    # bless `ground_truth.yaml`: `workspace_map` lists that file into MAIN's message 0 whenever
    # the fixture carries a sibling one (26 tracked fixtures do, including every held-out eval
    # case), so MAIN is TOLD the answer key exists even though `permission/files.py` denies
    # reading it by filename. That is pre-existing and explicitly OUT OF SCOPE for #647 — a
    # human decision recorded in the spec graph, not an oversight of this suite. Follow-up:
    # decide whether workspace_map should skip ground_truth.yaml the way it skips gather_raw.
    # Do NOT widen the assertion below to cover it without that decision.
    listed = run_dir_listing(replay.seen[0])
    assert listed == sorted(listed), "the listing is not in sorted order"
    assert "meta.json" not in listed, "message 0 still advertises the removed file to MAIN"
    assert "gather_raw" not in listed, "the subagent-only raw tree leaked into the orientation"

    on_disk = {p.name for p in run_dir.iterdir()}
    assert set(listed) <= on_disk, (
        f"message 0 lists names that do not exist in the run dir: {set(listed) - on_disk}"
    )
    assert (materialized - {"gather_raw"}) <= set(listed), (
        f"a materialized artifact is missing from message 0: "
        f"{(materialized - {'gather_raw'}) - set(listed)}"
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

    prod_dir, prod_salt = build(tmp_path, monkeypatch, run_id="replay-msg0-647-prod")
    assert prod_dir.is_dir(), (
        "there is no production run dir to compare the replayed listing against"
    )

    replay = ReplayFn([Turn(text="Done.")])
    drive(harness_dir, run_id="replay-msg0-647", salt="0" * 16, main=replay)
    listed = run_dir_listing(replay.seen[0])

    assert "meta.json" not in listed, "the replayed message 0 still advertises the removed file"
    production_names = {p.name for p in prod_dir.iterdir()}
    assert set(listed) <= production_names | {"llm_requests.jsonl", "tool_trace.jsonl"}, (
        f"the replayed listing names files a production run dir never has: "
        f"{set(listed) - production_names}"
    )
    assert prod_salt


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
    prod_dir, salt = build(tmp_path, monkeypatch, run_id="parity-647")
    assert prod_dir.is_dir(), (
        "the production builder produced no run dir to compare file sets with"
    )
    assert salt, (
        "the production builder returned no salt to materialize the harness run dir with"
    )
    harness_dir = materialize(tmp_path / "h", GOLDEN)

    prod_names = {p.name for p in prod_dir.iterdir()}
    harness_names = {p.name for p in harness_dir.iterdir()}
    assert prod_names == harness_names, (
        f"the two builders' run dirs diverge: production={sorted(prod_names)} "
        f"harness={sorted(harness_names)}"
    )
    assert prod_names == {"alert.json", "gather_raw"}
