"""Persist-stage filter — held-out runs must not feed _pending/ queues."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REAL_REPO = Path(__file__).resolve().parents[2]

from defender.learning import loop  # type: ignore[import-not-found]


class FakeSubagents:
    """In-memory Subagents double — canned per-step outputs, records call counts.

    Replaces the monkeypatch wall over invoke_actor/oracle/judge; the SDK migration
    will swap loop's real adapter the same way this swaps a fake.
    """

    def __init__(self, *, story="story body\n", story_benign="story body\n",
                 oracle="projections: []\n", judge="", judge_benign=""):
        self._story = story
        self._story_benign = story_benign
        self._oracle = oracle
        self._judge = judge
        self._judge_benign = judge_benign
        self.calls: dict[str, int] = {}

    def _bump(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    def actor(self, run_dir, learning_run_dir):
        self._bump("actor")
        return self._story

    def actor_benign(self, run_dir, learning_run_dir, alert_rule_key):
        self._bump("actor_benign")
        return self._story_benign

    def oracle(self, run_dir, actor_story_path):
        self._bump("oracle")
        return self._oracle

    def judge(self, wiring, run_dir, actor_story_path, projected_telemetry_path,
              learning_run_dir):
        # One seam method for both directions; the wiring tells them apart.
        # Compare identity against the real spec, not a magic dirname string, so the
        # fake can't silently misroute if BENIGN_WIRING's fields are renamed.
        benign = wiring is loop.BENIGN_WIRING
        self._bump("judge_benign" if benign else "judge")
        return self._judge_benign if benign else self._judge


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "20260512T120000Z-case"
    d.mkdir()
    return d


def test_is_held_out_true(run_dir: Path) -> None:
    (run_dir / "ground_truth.yaml").write_text(
        "held_out: true\ndisposition: benign\nrationale: x\n"
    )
    assert loop.is_held_out(run_dir) is True


def test_is_held_out_false_when_flag_missing(run_dir: Path) -> None:
    # ground_truth file with disposition but no held_out key — should not
    # trigger the filter; the marker is explicit.
    (run_dir / "ground_truth.yaml").write_text(
        "disposition: benign\nrationale: x\n"
    )
    assert loop.is_held_out(run_dir) is False


def test_is_held_out_false_when_no_file(run_dir: Path) -> None:
    assert loop.is_held_out(run_dir) is False


def test_read_ground_truth_rejects_non_mapping(run_dir: Path) -> None:
    (run_dir / "ground_truth.yaml").write_text("- not\n- a\n- mapping\n")
    with pytest.raises(loop.RunUnprocessable):
        loop.read_ground_truth(run_dir)


def test_read_ground_truth_rejects_malformed_yaml(run_dir: Path) -> None:
    (run_dir / "ground_truth.yaml").write_text("held_out: true\n: bad indent\n  - [\n")
    with pytest.raises(loop.RunUnprocessable, match="malformed YAML"):
        loop.read_ground_truth(run_dir)


def _complete_run_dir(tmp_path: Path, disposition: str, *, held_out: bool) -> Path:
    """A run dir with the inputs persist_run copies, plus optional held-out mark.

    The lead/query tables (gather_raw/ + executed_queries.jsonl) are the
    learning-loop inputs; persist copies them when present.
    """
    run_dir = tmp_path / "case"
    run_dir.mkdir()
    (run_dir / "alert.json").write_text(json.dumps({"rule": {"id": "5710"}}))
    (run_dir / "report.md").write_text(
        f"---\ncase_id: case\ndisposition: {disposition}\nconfidence: high\n---\nbody\n"
    )
    (run_dir / "investigation.md").write_text("stub\n")
    # Empty lead/query tables — a no-query run (joined() -> []), which the
    # stubbed oracle's empty projections match.
    (run_dir / "gather_raw").mkdir()
    (run_dir / "executed_queries.jsonl").write_text("")
    if held_out:
        (run_dir / "ground_truth.yaml").write_text(
            "held_out: true\ndisposition: benign\nrationale: x\n"
        )
    return run_dir


def test_run_one_gate_short_circuits_before_append(tmp_path: Path, monkeypatch) -> None:
    """The held-out gate fires before append: a queueable finding that would
    otherwise be queued must leave the pending file untouched on a held-out run."""
    # FakeSubagents never runs a real judge, so pin the legacy engine to keep
    # run_one's _prepare_judge_engine_for a no-op (the default pydantic_ai engine would
    # source the metered FIREWORKS_API_KEY, which CI has no reason to hold).
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", "claude_print")
    run_dir = _complete_run_dir(tmp_path, "benign", held_out=True)
    judge_yaml = (
        "outcome: survived\n"
        "defender_findings:\n"
        "  - type: lead-set\n"          # queueable — would append if not held out
        "    subject_anchor: a\n"
        "    subject_topic: t\n"
        "    finding: n\n"
        "    citations: []\n"
    )
    agents = FakeSubagents(judge=judge_yaml)
    paths = loop.LoopPaths(repo_root=tmp_path)

    rc = loop.run_one(run_dir, paths=paths, agents=agents)
    assert rc == 0
    assert agents.calls.get("judge") == 1  # adversarial leg ran end-to-end...
    assert not paths.pending_file.exists()  # ...but held-out suppressed the append


def test_malicious_dispatches_benign_not_adversarial(tmp_path: Path, monkeypatch) -> None:
    """Disposition routing: ``malicious`` runs the benign (FP) actor, never the
    adversarial one; the run is enqueued for authoring regardless of disposition
    (lead-author itself now fires later, in the serial author_drain)."""
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", "claude_print")  # FakeSubagents: keep key-sourcing a no-op
    run_dir = _complete_run_dir(tmp_path, "malicious", held_out=False)
    # Benign actor SKIPs → direction short-circuits after persist, no oracle/judge.
    agents = FakeSubagents(story_benign="SKIP: not ours\n")
    paths = loop.LoopPaths(repo_root=tmp_path)

    rc = loop.run_one(run_dir, paths=paths, agents=agents)
    assert rc == 0
    marker = paths.author_queue_dir / f"{run_dir.name}.json"
    assert marker.exists(), "run must be enqueued for authoring regardless of disposition"
    assert agents.calls.get("actor", 0) == 0, "adversarial actor must not run on malicious"
    assert agents.calls.get("actor_benign") == 1, "benign actor must run on malicious"


def test_run_one_enqueues_for_authoring_even_when_a_leg_fails(tmp_path: Path, monkeypatch) -> None:
    """A failed direction leg must still enqueue the run for the serial
    author-drainer — lead-author (catalog refinement) is leg-independent — and
    then fail loud. Enqueue happens before the re-raise, so the run isn't
    stranded with no author-work marker."""
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", "claude_print")  # FakeSubagents: keep key-sourcing a no-op
    run_dir = _complete_run_dir(tmp_path, "benign", held_out=False)
    # Malformed judge YAML → the adversarial leg raises RunUnprocessable.
    agents = FakeSubagents(judge="outcome: [unterminated\n")
    paths = loop.LoopPaths(repo_root=tmp_path)

    with pytest.raises(loop.RunUnprocessable):
        loop.run_one(run_dir, paths=paths, agents=agents)
    marker = paths.author_queue_dir / f"{run_dir.name}.json"
    assert marker.exists(), "a failed leg must still enqueue the run for authoring"


def test_directions_for_dispatch() -> None:
    assert loop._directions_for("benign") == ["adversarial"]
    assert loop._directions_for("malicious") == ["benign"]
    assert loop._directions_for("inconclusive") == ["adversarial", "benign"]
