"""Unit tests for the secondary-metric harness.

Covers the pure helpers (eligibility, generation parsing, catch-rate
math, summary formatting) plus worktree idempotency on a real git
repo fixture. Avoids spawning ``claude -p`` — actor / oracle / judge
calls are out of scope here and are exercised by manual end-to-end
runs.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


_HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sec = _load("eval_secondary_t", _HERE / "secondary.py")


# ---------------------------------------------------------------------------
# Generation trailers
# ---------------------------------------------------------------------------

def test_parse_trailers_extracts_generation_and_model():
    body = (
        "defender/learning: actor lessons batch abc123\n"
        "\n"
        "New: foo, bar\n"
        "\n"
        "Generation: 3\n"
        "Actor-Model: claude-sonnet-4-6\n"
    )
    gen, model = sec.parse_trailers(body)
    assert gen == 3
    assert model == "claude-sonnet-4-6"


def test_parse_trailers_missing_returns_none():
    gen, model = sec.parse_trailers("just a regular commit\n\nno trailers here\n")
    assert gen is None
    assert model is None


# ---------------------------------------------------------------------------
# Eligibility
# ---------------------------------------------------------------------------

def _write_fixture(root: Path, slug: str, disposition: str, held_out: bool = True):
    d = root / slug
    d.mkdir(parents=True)
    (d / "alert.json").write_text("{}")
    gt = {
        "held_out": held_out,
        "disposition": disposition,
        "class_axes": {"vendor": "wazuh", "rule_class": "x"},
    }
    (d / "ground_truth.yaml").write_text(yaml.safe_dump(gt))


def test_eligible_filter_excludes_malicious_ground_truth(tmp_path: Path):
    f = tmp_path / "fx"
    _write_fixture(f, "b01-x", "benign")
    _write_fixture(f, "i01-x", "inconclusive")
    _write_fixture(f, "m01-x", "malicious")
    alerts = sec.load_held_out_fixtures(f)
    assert {a.slug for a in alerts} == {"b01-x", "i01-x", "m01-x"}
    eligible = sec.eligible_for_secondary(alerts)
    assert {a.slug for a in eligible} == {"b01-x", "i01-x"}


def test_eligible_filter_skips_non_held_out(tmp_path: Path):
    f = tmp_path / "fx"
    _write_fixture(f, "b01-x", "benign", held_out=True)
    _write_fixture(f, "b02-x", "benign", held_out=False)
    alerts = sec.load_held_out_fixtures(f)
    assert {a.slug for a in alerts} == {"b01-x"}


# ---------------------------------------------------------------------------
# Catch-rate math (denominator excludes skip-passthrough + not_executed)
# ---------------------------------------------------------------------------

def _result(slug, status, outcome=None, gt="benign", err=None):
    return sec.AlertResult(
        slug=slug, ground_truth=gt, status=status,
        judge_outcome=outcome, error=err,
    )


def test_catch_rate_excludes_skip_passthrough_and_not_executed():
    s = sec.SecondarySummary(
        current_generation=4, pinned_generation=1, pinned_sha="abc" * 14,
        pinned_model="claude-sonnet-4-6", k=3, eligible=8,
    )
    s.results = [
        _result("a", "executed", "caught"),
        _result("b", "executed", "caught"),
        _result("c", "executed", "survived"),
        _result("d", "executed", "incoherent"),
        _result("e", "executed", "undecidable"),
        _result("f", "executed", "skip-passthrough"),
        _result("g", "not_executed"),
        _result("h", "failed", err="oracle YAML invalid"),
    ]
    counts = s.outcome_counts
    assert counts["caught"] == 2
    assert counts["survived"] == 1
    assert counts["incoherent"] == 1
    assert counts["undecidable"] == 1
    assert counts["skip-passthrough"] == 1
    caught, denom = s.catch_rate()
    # Denominator: caught+survived+incoherent+undecidable = 5
    # Skip and not_executed and failed are *not* in the denominator
    assert caught == 2
    assert denom == 5


def test_catch_rate_denom_zero_when_all_skip_or_not_executed():
    s = sec.SecondarySummary(
        current_generation=4, pinned_generation=1, pinned_sha="x",
        pinned_model="m", k=3, eligible=3,
    )
    s.results = [
        _result("a", "executed", "skip-passthrough"),
        _result("b", "not_executed"),
        _result("c", "failed", err="x"),
    ]
    caught, denom = s.catch_rate()
    assert (caught, denom) == (0, 0)


# ---------------------------------------------------------------------------
# Summary formatting
# ---------------------------------------------------------------------------

def test_summary_md_replay_incompatible_short_form():
    s = sec.SecondarySummary(
        current_generation=2, pinned_generation=None, pinned_sha=None,
        pinned_model=None, k=3,
        replay_incompatible_reason="have 2 commits, need 3",
    )
    md = sec.format_summary_md(s)
    assert "replay-incompatible" in md
    assert "have 2 commits, need 3" in md
    # No catch-rate section when incompatible
    assert "catch rate" not in md


def test_summary_md_renders_executed_breakdown():
    s = sec.SecondarySummary(
        current_generation=4, pinned_generation=1, pinned_sha="a" * 40,
        pinned_model="claude-sonnet-4-6", k=3, eligible=2,
    )
    s.results = [
        _result("alpha", "executed", "caught"),
        _result("beta", "executed", "survived"),
    ]
    md = sec.format_summary_md(s)
    assert "catch rate (executed, ex-skip): 1/2 = 50.0%" in md
    assert "pinned generation: 1" in md
    assert "alpha" in md
    assert "beta" in md


# ---------------------------------------------------------------------------
# Worktree idempotency on a real git repo
# ---------------------------------------------------------------------------

def _git(repo: Path, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )


def _init_repo_with_actor_commits(tmp_path: Path, n: int, model_name: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    _git(repo, "commit", "--allow-empty", "-m", "initial")
    for i in range(1, n + 1):
        msg = f"actor batch {i}\n\nGeneration: {i}\nActor-Model: {model_name}\n"
        _git(repo, "commit", "--allow-empty", "-m", msg)
    return repo


def test_list_actor_commits_returns_all_generations(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=4, model_name="claude-sonnet-4-6")
    commits = sec.list_actor_commits(repo)
    assert sorted(c.generation for c in commits) == [1, 2, 3, 4]
    for c in commits:
        assert c.actor_model == "claude-sonnet-4-6"
        assert len(c.sha) == 40


def test_resolve_target_pin_returns_none_when_history_too_short(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=2, model_name="m")
    # k=3 with only 2 commits → target gen = -1 → None
    assert sec.resolve_target_pin(repo, k=3) is None


def test_resolve_target_pin_picks_correct_generation(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=5, model_name="m")
    pin = sec.resolve_target_pin(repo, k=3)
    assert pin is not None
    assert pin.generation == 2  # 5 - 3
    assert pin.actor_model == "m"


def test_ensure_worktree_idempotent(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=4, model_name="m")
    pin = sec.resolve_target_pin(repo, k=3)
    assert pin is not None

    p1 = sec.ensure_worktree(pin, repo, worktrees_dir=tmp_path / "wts")
    assert p1.is_dir()
    assert (p1 / ".git").exists()
    # Second call is a no-op (no exception, same path).
    p2 = sec.ensure_worktree(pin, repo, worktrees_dir=tmp_path / "wts")
    assert p2 == p1
    assert sec._worktree_head_sha(p2) == pin.sha


def test_ensure_worktree_recreates_when_head_mismatch(tmp_path: Path):
    """Reused worktree at the wrong SHA gets removed and rebuilt at pin.sha.

    Simulates: a prior harness run on a different branch left a
    worktree at this path checked out to a different commit. Without
    recreation, the frozen actor would run with the wrong tree but
    the summary would still claim ``pin.sha`` — silently
    misattributing the catch rate to the wrong generation.
    """
    repo = _init_repo_with_actor_commits(tmp_path, n=4, model_name="m")
    worktrees_dir = tmp_path / "wts"
    pin = sec.resolve_target_pin(repo, k=3)  # gen 1 (4-3)
    assert pin is not None

    # Build the worktree pointing at gen 4 (a different SHA than the
    # one resolve_target_pin returns).
    all_commits = sec.list_actor_commits(repo)
    other = next(c for c in all_commits if c.generation == 4)
    assert other.sha != pin.sha
    wrong_path = sec.worktree_path_for(pin, worktrees_dir=worktrees_dir)
    wrong_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(wrong_path), other.sha],
        cwd=repo, check=True, capture_output=True, text=True,
    )
    assert sec._worktree_head_sha(wrong_path) == other.sha

    rebuilt = sec.ensure_worktree(pin, repo, worktrees_dir=worktrees_dir)
    assert rebuilt == wrong_path
    assert sec._worktree_head_sha(rebuilt) == pin.sha


# ---------------------------------------------------------------------------
# write_summary side effects
# ---------------------------------------------------------------------------

def test_write_summary_emits_md_per_alert_json_and_index_jsonl(tmp_path: Path):
    s = sec.SecondarySummary(
        current_generation=7, pinned_generation=4, pinned_sha="f" * 40,
        pinned_model="claude-sonnet-4-6", k=3, eligible=2,
    )
    s.results = [
        _result("alpha", "executed", "caught"),
        _result("beta", "not_executed"),
    ]
    out = tmp_path / "eval-out"
    md_path = sec.write_summary(s, out)
    assert md_path.is_file()
    assert "gen-7.summary.md" in str(md_path)
    detail_dir = out / "gen-7"
    assert (detail_dir / "alpha.json").is_file()
    alpha = json.loads((detail_dir / "alpha.json").read_text())
    assert alpha["judge_outcome"] == "caught"
    assert (out / "index.jsonl").is_file()
    rows = [json.loads(line) for line in (out / "index.jsonl").read_text().splitlines() if line.strip()]
    assert len(rows) == 1
    assert rows[0]["current_generation"] == 7
    assert rows[0]["pinned_generation"] == 4
    assert rows[0]["caught"] == 1
    assert rows[0]["catch_denominator"] == 1
    assert rows[0]["catch_rate"] == 1.0


def test_replay_actor_uses_stable_case_id_for_seed(tmp_path: Path):
    """Stable --case-id keeps actor seed constant across attempt-suffixed staging dirs.

    Loads ``replay_actor.py`` directly, stubs out the heavy bits
    (loop.invoke_actor and the lead_repository actor_view it projects
    from), and asserts that the seed captured during the invoke_actor
    call corresponds to the ``--case-id`` value rather than
    ``staging.name``. This is the invariant that protects catch rate
    from per-attempt noise.
    """
    replay = _load("replay_actor_t", _HERE.parent / "learning" / "ops" / "replay_actor.py")

    captured: dict = {}

    class FakeLoop:
        ACTOR_MODEL = "claude-sonnet-4-6"  # replay sources the metered key for sub.ACTOR_MODEL

        class RunUnprocessable(Exception):
            pass

        @staticmethod
        def _actor_seed(run_id):
            return f"seed-of-{run_id}"

        @staticmethod
        def invoke_actor(alert_path, actor_input_path, learning_run_dir):
            # Mirrors the real signature; record what the seed
            # function returns under the active override so the test
            # can assert it's the *case_id* version, not staging.name.
            captured["seed"] = fake_loop._actor_seed(learning_run_dir.name)
            captured["learning_run_dir"] = str(learning_run_dir)
            return "STORY\n"

    fake_loop = FakeLoop()

    class FakeLR:
        @staticmethod
        def actor_view(staging):
            return {"case_id": "ignored", "alert_ref": "alert.json", "leads": []}

    def fake_load_sibling(name, path):
        if name.endswith("subagents_replay"):
            return fake_loop
        if name.endswith("lead_repository_replay"):
            return FakeLR()
        raise AssertionError(f"unexpected sibling load: {name}")

    staging = tmp_path / "stage-with-attempt-aaaaaaaa"
    staging.mkdir()
    (staging / "alert.json").write_text("{}")
    (staging / "gather_raw").mkdir()  # the leads table (required replay input)

    import unittest.mock as mock
    with mock.patch.object(replay, "_load_sibling", side_effect=fake_load_sibling), \
         mock.patch.object(replay, "source_first_party_key", return_value=None):
        # Neutralize metered-key sourcing: the actor now runs in-process, so replay.main
        # sources the first-party key; this hermetic seed test must not require a real .env key.
        rc = replay.main([str(staging), "--case-id", "sec-eval-gen4-b01"])

    assert rc == 0
    assert (staging / "actor_story.md").read_text() == "STORY\n"
    # The seed must reflect the stable case_id, NOT the attempt-suffixed
    # staging dir name. (Real invoke_actor seeds from
    # learning_run_dir.name; the override in replay_actor.py reroutes
    # that to case_id, so the seed string passed to the captured
    # invoke_actor matches the stable id.)
    assert captured["seed"] == "seed-of-sec-eval-gen4-b01"


def test_module_import_does_not_reexec():
    """Importing eval_secondary as a library must not os.execv.

    The pytest invocation imports this module under the venv's
    ``python`` console script (no ``3`` suffix). A strict-equality
    re-exec guard at module top would replace the test collector
    process with the harness CLI and exit 2. This test pins that the
    import path is safe — the guard lives behind ``__main__`` only.
    """
    # If the guard were at module top, the importlib._load earlier in
    # this file (or pytest collection) would already have re-exec'd
    # away. Reaching this line is the assertion.
    assert sec.__name__.endswith("eval_secondary_t")


def test_run_head_oracle_and_judge_converts_oracle_timeout(tmp_path: Path):
    """A RunUnprocessable from invoke_oracle must surface as SecondaryError.

    The oracle now runs IN-PROCESS (PydanticAI): run_stage maps a hung / timed-out / model-errored
    per-lead call to ``RunUnprocessable`` (there is no subprocess to raise TimeoutExpired). Left
    uncaught it would escape the per-alert handler in run_secondary() and abort the whole harness
    before the summary is written. This test pins the conversion. NB the harness now sources the
    in-process stages' keys BEFORE the oracle, so the fake stubs ``_prepare_engines_for`` too.
    """
    actor_story = tmp_path / "actor_story.md"
    actor_story.write_text("not a SKIP\n")
    lead_seq = tmp_path / "lead_sequence.yaml"
    lead_seq.write_text("entries: []\n")
    alert = tmp_path / "alert.json"
    alert.write_text("{}")
    head_run = tmp_path
    staging = tmp_path / "stage"
    staging.mkdir()
    (staging / "actor_story.md").write_text("not a SKIP\n")

    class FakeLoop:
        class RunUnprocessable(Exception):
            pass

        @staticmethod
        def is_skip_story(text):
            return False

        @staticmethod
        def _prepare_engines_for(_directions, **_kw):  # **_kw: absorbs include_actor=
            pass  # hermetic: no metered key sourced, no engine validation

        @staticmethod
        def invoke_oracle(*_a, **_kw):
            raise FakeLoop.RunUnprocessable("per-lead oracle timed out")

    with pytest.raises(sec.SecondaryError, match="oracle invocation failed"):
        sec.run_head_oracle_and_judge(head_run, staging, FakeLoop)


def test_run_head_oracle_and_judge_converts_judge_timeout(tmp_path: Path):
    """Same protection for the judge invoke."""
    head_run = tmp_path
    (head_run / "alert.json").write_text("{}")
    (head_run / "investigation.md").write_text("")
    staging = tmp_path / "stage"
    staging.mkdir()
    (staging / "actor_story.md").write_text("not a SKIP\n")

    valid_oracle = "projections: []\n"

    class _FakeLR:
        @staticmethod
        def render_joined_yaml(run_dir):
            return "leads: []\n"

    class _FakeSubagents:
        def judge(self, *_a, **_kw):
            raise subprocess.TimeoutExpired(cmd=["claude"], timeout=300)

    class FakeLoop:
        class RunUnprocessable(Exception):
            pass

        lead_repository = _FakeLR
        ADVERSARIAL_WIRING = object()  # opaque — the judge stub ignores it
        ClaudePrintSubagents = _FakeSubagents

        @staticmethod
        def is_skip_story(text):
            return False

        @staticmethod
        def invoke_oracle(*_a, **_kw):
            return valid_oracle

        @staticmethod
        def strip_yaml_fence(text):
            return text

        @staticmethod
        def _prepare_engines_for(_directions, **_kw):  # **_kw: absorbs include_actor=
            pass  # hermetic: no metered key sourced, no engine validation

    with pytest.raises(sec.SecondaryError, match="judge invocation failed"):
        sec.run_head_oracle_and_judge(head_run, staging, FakeLoop)


def test_write_summary_appends_to_existing_index(tmp_path: Path):
    out = tmp_path / "eval-out"
    s1 = sec.SecondarySummary(
        current_generation=4, pinned_generation=1, pinned_sha="a" * 40,
        pinned_model="m", k=3, eligible=0,
    )
    s2 = sec.SecondarySummary(
        current_generation=5, pinned_generation=2, pinned_sha="b" * 40,
        pinned_model="m", k=3, eligible=0,
    )
    sec.write_summary(s1, out)
    sec.write_summary(s2, out)
    rows = [json.loads(line) for line in (out / "index.jsonl").read_text().splitlines() if line.strip()]
    assert [r["current_generation"] for r in rows] == [4, 5]
