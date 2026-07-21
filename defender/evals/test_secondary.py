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



def test_summary_md_replay_incompatible_short_form():
    s = sec.SecondarySummary(
        current_generation=2, pinned_generation=None, pinned_sha=None,
        pinned_model=None, k=3,
        replay_incompatible_reason="have 2 commits, need 3",
    )
    md = sec.format_summary_md(s)
    assert "replay-incompatible" in md
    assert "have 2 commits, need 3" in md
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
    assert sec.resolve_target_pin(repo, k=3) is None


def test_resolve_target_pin_picks_correct_generation(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=5, model_name="m")
    pin = sec.resolve_target_pin(repo, k=3)
    assert pin is not None
    assert pin.generation == 2
    assert pin.actor_model == "m"


def test_ensure_worktree_idempotent(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=4, model_name="m")
    pin = sec.resolve_target_pin(repo, k=3)
    assert pin is not None

    p1 = sec.ensure_worktree(pin, repo, worktrees_dir=tmp_path / "wts")
    assert p1.is_dir()
    assert (p1 / ".git").exists()
    p2 = sec.ensure_worktree(pin, repo, worktrees_dir=tmp_path / "wts")
    assert p2 == p1
    assert sec._worktree_head_sha(p2) == pin.sha


def test_ensure_worktree_recreates_when_head_mismatch(tmp_path: Path):
    repo = _init_repo_with_actor_commits(tmp_path, n=4, model_name="m")
    worktrees_dir = tmp_path / "wts"
    pin = sec.resolve_target_pin(repo, k=3)
    assert pin is not None

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
    replay = _load("replay_actor_t", _HERE.parent / "learning" / "ops" / "replay_actor.py")

    captured: dict = {}

    class FakeLoop:
        ACTOR_MODEL = "claude-sonnet-4-6"

        class RunUnprocessable(Exception):
            pass

        @staticmethod
        def _actor_seed(run_id):
            return f"seed-of-{run_id}"

        @staticmethod
        def invoke_actor(alert_path, actor_input_path, learning_run_dir):
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
    (staging / "gather_raw").mkdir()

    import unittest.mock as mock
    with mock.patch.object(replay, "_load_sibling", side_effect=fake_load_sibling), \
         mock.patch.object(replay, "source_first_party_key", return_value=None):
        rc = replay.main([str(staging), "--case-id", "sec-eval-gen4-b01"])

    assert rc == 0
    assert (staging / "actor_story.md").read_text() == "STORY\n"
    assert captured["seed"] == "seed-of-sec-eval-gen4-b01"


def test_module_import_does_not_reexec():
    assert sec.__name__.endswith("eval_secondary_t")


def test_run_head_oracle_and_judge_converts_oracle_timeout(tmp_path: Path):
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

        class InProcessSubagents:
            def oracle(self, *_a, **_kw):
                raise FakeLoop.RunUnprocessable("per-lead oracle timed out")

        @staticmethod
        def is_skip_story(text):
            return False

        @staticmethod
        def _prepare_engines_for(_directions, **_kw):
            pass

    with pytest.raises(sec.SecondaryError, match="oracle invocation failed"):
        sec.run_head_oracle_and_judge(head_run, staging, FakeLoop)


def test_run_head_oracle_and_judge_converts_judge_timeout(tmp_path: Path):
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
        def oracle(self, *_a, **_kw):
            return valid_oracle

        def judge(self, *_a, **_kw):
            raise subprocess.TimeoutExpired(cmd=["claude"], timeout=300)

    class FakeLoop:
        class RunUnprocessable(Exception):
            pass

        lead_repository = _FakeLR
        ADVERSARIAL_WIRING = object()
        InProcessSubagents = _FakeSubagents

        @staticmethod
        def is_skip_story(text):
            return False

        @staticmethod
        def strip_yaml_fence(text):
            return text

        @staticmethod
        def _prepare_engines_for(_directions, **_kw):
            pass

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
