"""Contamination boundary — a held-out eval run must never feed the learning corpora.

The gate used to live in the persist stage: `run.py` copied `ground_truth.yaml` into the
run dir and the orchestrator suppressed queue appends when it declared `held_out`. That put
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

from defender import run_common  # type: ignore[import-not-found]
from defender.learning import loop  # type: ignore[import-not-found]

def _noop_start_box(request, **_kw):
    from types import SimpleNamespace

    return SimpleNamespace(name=request.name)


def _noop_stop_box(_box, **_kw):
    pass




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

    def actor(self, run_dir, learning_run_dir, *, box=None):
        self._bump("actor")
        return self._story

    def actor_benign(self, run_dir, learning_run_dir, alert_rule_key, *, box=None):
        self._bump("actor_benign")
        return self._story_benign

    def oracle(self, run_dir, actor_story_path, learning_run_dir):
        self._bump("oracle")
        return self._oracle

    def judge(self, wiring, run_dir, actor_story_path,
              learning_run_dir, *, box=None):
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
    (run_dir / "gather_raw").mkdir()
    (run_dir / "executed_queries.jsonl").write_text("")
    return run_dir


def test_held_out_fixture_is_recognised_by_path(tmp_path: Path) -> None:
    """The net is a PATH check — it opens no label file, so it cannot be defeated by a
    missing, malformed, or absent-key ground_truth.yaml."""
    real = run_common.HELD_OUT_FIXTURES / "m05-lsass-access" / "alert.json"
    assert run_common.is_held_out_fixture(real) is True
    assert run_common.is_held_out_fixture(tmp_path / "alert.json") is False


def test_held_out_fixture_recognised_without_any_label_file(tmp_path: Path) -> None:
    """Fail-closed: containment alone decides. A held-out fixture with its label
    deleted is still refused."""
    fake_set = tmp_path / "held-out"
    (fake_set / "m01").mkdir(parents=True)
    alert = fake_set / "m01" / "alert.json"
    alert.write_text("{}")
    assert run_common.is_held_out_fixture(alert, fake_set) is True


def test_symlink_cannot_walk_out_of_the_held_out_set(tmp_path: Path) -> None:
    """Containment is decided on the RESOLVED path, so a symlink pointing into the
    held-out set is still recognised as held-out."""
    fake_set = tmp_path / "held-out"
    (fake_set / "m01").mkdir(parents=True)
    real = fake_set / "m01" / "alert.json"
    real.write_text("{}")
    link = tmp_path / "innocent.json"
    link.symlink_to(real)
    assert run_common.is_held_out_fixture(link, fake_set) is True




def test_net_is_narrow(tmp_path: Path) -> None:
    """Control: the refusal is scoped to the held-out set. An ordinary alert — including
    one under `fixtures/` but outside `held-out/` — is not refused, so the net cannot
    quietly starve the learning loop.

    Asserted on the predicate rather than by driving `enqueue_learning` to its enqueue
    branch: that branch writes through the import-time `DEFAULT_PATHS`, which has no
    injection seam, and faking it would mean a `monkeypatch.setattr` site this project
    ratchets against.
    """
    assert run_common.is_held_out_fixture(tmp_path / "alert.json") is False
    ordinary = (run_common.DEFENDER_DIR / "fixtures"
                / "v2-sshd-success-after-failures" / "alert.json")
    assert ordinary.is_file(), "control must point at a real non-held-out fixture"
    assert run_common.is_held_out_fixture(ordinary) is False










