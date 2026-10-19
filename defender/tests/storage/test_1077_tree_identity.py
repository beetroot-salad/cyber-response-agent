"""#1077 — O3's tree observer, and the writers that share a run directory."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _writer_run_1165

from pathlib import Path

import pytest

from defender.tests.support.shared.contracts import _spec1077 as S

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e


def _replay(tmp_path: Path, run_id: str = "tree-1077") -> Path:
    """One whole replayed fixture run, driven through the real driver, ended normally."""
    run_dir = materialize(tmp_path, GOLDEN, run_id=run_id)
    replay = ReplayFn([
        Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text()})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ])
    drive(run_dir, run_id=run_id, main=replay)
    return run_dir


def _baseline_exists() -> None:
    assert S.TREE_BASELINE.is_file(), (
        "the O3 baseline does not exist. D7 step 1 captures it BEFORE step 3, on `main`, with "
        "no implementation behind it — the existing goldens are not this observer (claim C8: "
        "they compare one normalised investigation text and three iterdir() names)")


# d13 / d14 — the structural check, and the narrow content check beside it

def test_a_replayed_fixture_run_tree_carries_the_same_set_of_names(tmp_path: Path):
    _baseline_exists()
    run_dir = _replay(tmp_path)
    doc = S.load_baseline()
    assert S.structural_findings(run_dir, doc) == [], (
        "\n".join(S.structural_findings(run_dir, doc)))

    # The check is over the WHOLE tree: no name is excused, and the machinery offers no lever
    # to excuse one. Decision 21 removed `O3_EXEMPT` rather than lengthening it.
    assert not hasattr(S, "O3_EXEMPT"), (
        "an exemption list came back. Decision 21 removed it: eight files differ between two "
        "replays of UNCHANGED code, so an exemption list is a widening lever, not a contract")
    assert "exclude" not in S.snapshot.__code__.co_varnames, (
        "`snapshot` grew an `exclude` argument — the structural check admits no exemption, "
        "which is the only thing that makes 'the same set of names' worth asserting")
    names = set(S.snapshot(run_dir))
    for unstable in ("tool_trace.jsonl",):
        assert unstable in names, (
            f"{unstable} is outside the structural check. Its BYTES are not compared (it "
            "carries a clock or a per-run uuid); its NAME is, and that is the whole point of "
            "splitting the two checks rather than exempting the file")


# g04 — the writers that share one run directory

def test_every_run_dir_writer_stays_key_disjoint_at_the_composition_frame(tmp_path: Path):
    from defender.scripts.gather_tools import record_query
    run_dir = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))
    owner = S.RunPaths(run_dir)

    produced: dict[str, str] = {}

    def claim(writer: str, path: Path) -> None:
        rel = str(Path(path).relative_to(run_dir))
        assert rel not in produced, (
            f"{writer} and {produced[rel]} both write {rel} — two writers' keys collided")
        produced[rel] = writer

    for lead in ("l-aaa111", "l-bbb222"):
        for seq in (0, 1):
            claim("record_query", run_dir / record_query.persist_payload(
                _writer_run_1165(run_dir), lead, seq, "{}"))
        claim("Run(leads)", owner.lead_claim(lead))
    for turn in (0, 1, 2):
        claim("challenge_gate", owner.review_record(turn))
    for role in ("support", "ablation", "composer"):
        claim("challenge_gate", owner.review_trace(role))
    claim("_alias", run_dir / ".alias-probe-deadbeefdeadbeef-symlink")
    claim("box", owner.box_sentinel)
    # #1235: `budget` and `circuit_breaker` are no longer run records (in-memory state).
    for fixed in ("tool_trace", "executed_queries", "policy_denials", "lessons_loaded",
                  "wire_log", "provenance"):
        claim("Run", getattr(owner, fixed))

    # No key is a PREFIX of another either: a writer whose reserved space is a directory must
    # not have a second writer's file land at that directory's own name.
    for a in produced:
        for b in produced:
            if a != b:
                assert not a.startswith(f"{b}/"), f"{a} lands inside {b}, another writer's key"


# h26 — the sandbox probe fails closed

def test_the_alias_ban_probe_fails_closed_on_a_timeout_or_a_malformed_result(tmp_path: Path):
    """The sandbox alias-ban probe fails closed — a timeout or a malformed result refuses,
    exactly as a found alias would."""
    alias = S.mod("box._alias")
    run_dir = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))

    for mode in ("timeout", "malformed"):
        docker = S.ProbeDocker(S.ProbeFault(mode=mode))
        with pytest.raises(alias.AliasBanNotInForce) as excinfo:
            alias._probe_alias_ban(docker, "box-1077", run_dir, "runc")
        assert docker.argv, f"the {mode} arm never reached the probe"
        assert not issubclass(type(excinfo.value), S.mod("box._docker").BoxFault), (
            "O7 is a security obligation, so the refusal must not be a `BoxFault` the generic "
            "`except BoxFault: degrade` startup handler can swallow")

    # Positive control: a clean probe does NOT refuse, so the two faults above are the refusal
    # and not the probe refusing unconditionally.
    clean = S.ProbeDocker(S.ProbeFault(mode="clean"))
    alias._probe_alias_ban(clean, "box-1077", run_dir, "runc")
    assert clean.argv, "the clean arm never reached the probe either"
