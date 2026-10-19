"""Every salted frame in a driven run carries its own salt, absent from the content it delimits; run-dir file set parity."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

from defender import run_common
from defender.run_repository import PROVENANCE, RunPaths
from defender.presentation.workspace_map import _unlisted
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

DEFENDER = Path(__file__).resolve().parents[2]
LEAD = "l-001"

ANY_RUN_TAG = re.compile(r"</?run-([0-9a-zA-Z]*)-([a-z-]+)>")
RUN_DIR_SECTION = re.compile(r"^## Run dir — .*$((?:\n- .*)*)", re.M)

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
    {"@timestamp": "2026-01-01T00:05:00Z", "user.name": "dev.dana", "event.action": "sudo"},
]


def build(tmp_path, monkeypatch, golden: Path = GOLDEN, run_id: str = "origin-647"):
    """Materialize a run dir with the REAL production builder.

    The data root is redirected into `tmp_path` and the tenant set up there (#1120: the
    builder is handed the accepted `Tenant`, whose runs base it builds under); everything
    else — the directory layout, the alert copy — is production code.

    Returned a `(run_dir, salt)` pair until #875. The builder no longer mints a token at all:
    `wrap_fresh` mints each frame's delimiter after its content is in hand, so there is no
    run-scoped salt for a builder to originate."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    data_root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(data_root))
    # The D9 tenant: the replay harness's `drive` runs the run under the fixture tenant it sets
    # up in this same data root, and a data root holds one tenant (O10).
    tenant = set_up_tenant(data_root)
    return run_common.materialize_run(golden / "alert.json", run_id, tenant=tenant).run_dir


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
        Turn(tool_calls=[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})]),
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


def test_every_frame_in_one_model_context_carries_its_own_salt(tmp_path, monkeypatch):
    """Every frame the model is shown carries a DISTINCT delimiter."""
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
    """A frame's delimiter never appears in that frame's own body."""
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
    """The gather subagent inherits NO token, because there is none to inherit."""
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


def test_message_zero_orientation_lists_exactly_the_materialized_run_dir_children(
    tmp_path, monkeypatch
):
    """MAIN's first model request enumerates the run dir's REAL children, and the removed file is not among them."""
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
    assert (materialized - _unlisted()) <= set(listed), (
        f"a materialized artifact is missing from message 0: "
        f"{(materialized - _unlisted()) - set(listed)}"
    )
    assert PROVENANCE not in listed, (
        "the run's own provenance stamp leaked into MAIN's directory view"
    )


def test_replay_harness_run_dir_and_production_run_dir_present_the_same_file_set(
    tmp_path, monkeypatch
):
    """The two run-dir builders present the same file set FOR A FIXTURE THAT CARRIES NO"""
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
    rp = RunPaths(prod_dir)
    assert prod_names == {rp.alert_input_dir.name, rp.gather_raw.name, rp.provenance.name}
