"""Contamination boundary — a held-out eval run must never feed the learning corpora.

The gate used to live in the persist stage: `run.py` copied `ground_truth.yaml` into the
run dir and `orchestrate` suppressed queue appends when it declared `held_out`. That put
an answer key inside the agent's readable workspace to carry a fact the learning loop
needed one bit of.

The boundary is now the ENQUEUE step, and it is a path check
(`run_common.is_held_out_fixture`): a held-out fixture run is never handed to the learn
worker at all, so there is nothing downstream to suppress and no label anywhere near a
run dir. The eval path passes `--no-learn`; this is the fail-closed net for when someone
forgets, or runs a held-out alert by hand.
"""
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

    def oracle(self, run_dir, actor_story_path, learning_run_dir):
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


def _complete_run_dir(tmp_path: Path, disposition: str) -> Path:
    """A run dir with the inputs persist_run copies.

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
    return run_dir


def test_held_out_fixture_is_recognised_by_path(tmp_path: Path) -> None:
    """The net is a PATH check — it opens no label file, so it cannot be defeated by a
    missing, malformed, or absent-key ground_truth.yaml."""
    from defender import run_common

    real = run_common.HELD_OUT_FIXTURES / "m05-lsass-access" / "alert.json"
    assert run_common.is_held_out_fixture(real) is True
    assert run_common.is_held_out_fixture(tmp_path / "alert.json") is False


def test_held_out_fixture_recognised_without_any_label_file(tmp_path: Path) -> None:
    """Fail-closed: containment alone decides. A held-out fixture with its label
    deleted is still refused."""
    from defender import run_common

    fake_set = tmp_path / "held-out"
    (fake_set / "m01").mkdir(parents=True)
    alert = fake_set / "m01" / "alert.json"
    alert.write_text("{}")  # no ground_truth.yaml beside it
    assert run_common.is_held_out_fixture(alert, fake_set) is True


def test_symlink_cannot_walk_out_of_the_held_out_set(tmp_path: Path) -> None:
    """Containment is decided on the RESOLVED path, so a symlink pointing into the
    held-out set is still recognised as held-out."""
    from defender import run_common

    fake_set = tmp_path / "held-out"
    (fake_set / "m01").mkdir(parents=True)
    real = fake_set / "m01" / "alert.json"
    real.write_text("{}")
    link = tmp_path / "innocent.json"
    link.symlink_to(real)
    assert run_common.is_held_out_fixture(link, fake_set) is True


def test_enqueue_refuses_held_out_fixture(tmp_path: Path, capsys) -> None:
    """The boundary: a held-out fixture run is never handed to the learn worker, so no
    stage downstream has to know what ground truth is."""
    from defender import run_common

    run_dir = _complete_run_dir(tmp_path, "benign")
    alert = run_common.HELD_OUT_FIXTURES / "m05-lsass-access" / "alert.json"
    assert run_common.enqueue_learning(run_dir, alert) is False
    assert "held-out eval fixture" in capsys.readouterr().err


def test_net_is_narrow(tmp_path: Path) -> None:
    """Control: the refusal is scoped to the held-out set. An ordinary alert — including
    one under `fixtures/` but outside `held-out/` — is not refused, so the net cannot
    quietly starve the learning loop.

    Asserted on the predicate rather than by driving `enqueue_learning` to its enqueue
    branch: that branch writes through the import-time `DEFAULT_PATHS`, which has no
    injection seam, and faking it would mean a `monkeypatch.setattr` site this project
    ratchets against.
    """
    from defender import run_common

    assert run_common.is_held_out_fixture(tmp_path / "alert.json") is False
    ordinary = run_common.DEFENDER_DIR / "fixtures" / "gtest-01-auth" / "alert.json"
    assert ordinary.is_file(), "control must point at a real non-held-out fixture"
    assert run_common.is_held_out_fixture(ordinary) is False


def test_malicious_dispatches_benign_not_adversarial(tmp_path: Path, monkeypatch) -> None:
    """Disposition routing: ``malicious`` runs the benign (FP) actor, never the
    adversarial one; the run is enqueued for authoring regardless of disposition
    (lead-author itself now fires later, in the serial author_drain)."""
    monkeypatch.setenv("FIREWORKS_API_KEY", "test-not-used")  # FakeSubagents: satisfy up-front key-sourcing
    run_dir = _complete_run_dir(tmp_path, "malicious")
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
    monkeypatch.setenv("FIREWORKS_API_KEY", "test-not-used")  # FakeSubagents: satisfy up-front key-sourcing
    run_dir = _complete_run_dir(tmp_path, "benign")
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
