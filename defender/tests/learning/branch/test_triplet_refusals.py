"""#947: the family launcher's refusals that nothing later could recover from.

#947: what a refusal may tell the model about a branched episode.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.learning.branch import _triplet_947 as T


def cli_mod():
    """`defender.learning.branch.cli` — imported per test, so a missing target is one failure
    per test rather than one collection error for the file."""
    return importlib.import_module("defender.learning.branch.cli")


@pytest.fixture
def tenant_paths(tmp_path, monkeypatch):
    """The tenant whose data root the episode-id refusals are judged against."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    return set_up_tenant(root, fixture_uuid("tenant:acme"))


def _tree(root: Path) -> list[str]:
    """Every path under `root`, sorted — a refusal's no-write claim is compared on this."""
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.fixture
def episodes_root(tmp_path, monkeypatch):
    """The retired configured episodes root, set as a decoy: nothing may be created there."""
    root = tmp_path / "episodes-root"
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(root))
    return root


@pytest.mark.parametrize("episode_id", ["../escaped", "/tmp/escaped", "nested/episode"])
def test_an_episode_id_that_is_not_one_safe_component_is_refused_before_priming(
        tmp_path, tenant_paths, episodes_root, episode_id):
    """Absolute and traversing episode ids never reach the capture writer."""
    from defender.records._run_id import episode_id_fault

    # An accepted tenant's data root exists before the launcher runs, so "created nothing under
    # the data root" is compared on its tree rather than on its absence.
    data_root = location_path(tenant_paths.data_root)
    before = _tree(data_root)
    runs = tenant_paths.runs_repository()

    assert episode_id_fault(episode_id), f"the episode-id rule admits {episode_id!r}"
    try:
        with runs.episode(episode_id):
            refused = None
    except Exception as exc:  # noqa: BLE001 — the refusal is the observation
        refused = exc
    assert refused is not None, f"the episode door opened {episode_id!r}"
    assert not isinstance(refused, OSError), (
        f"the door built a path from {episode_id!r} and let the OS answer: {refused!r}")
    assert not episodes_root.exists()
    assert _tree(data_root) == before, "the refused id wrote under the data root"

    with runs.create_episode() as view:
        claimed = view.episode_id
    with runs.episode(claimed) as opened:
        assert opened is not None, "positive control: the claimed episode does not open"


def test_a_safe_episode_id_resolves_beneath_the_configured_episodes_root(
        tenant_paths, episodes_root):
    """The positive control for the path-component refusal."""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    with tenant_paths.runs_repository().create_episode() as view:
        episode_id = view.episode_id
    claimed = S.episodes_dir(location_path(tenant_paths.data_root), str(tenant_paths.id)) / episode_id
    assert S.is_canonical_uuid(episode_id), f"{episode_id!r} is not a canonical uuid"
    assert claimed.is_dir(), claimed
    assert not claimed.is_symlink(), claimed
    assert location_path(tenant_paths.tenant_root) in claimed.parents, f"{claimed} is not under the tenant's folder"
    assert not episodes_root.exists(), "the configured episodes root was created"


def test_an_existing_episode_is_refused_even_if_only_stale_world_rows_remain(
        tmp_path, tenant_paths, episodes_root):
    """Reusing an episode id cannot revive old per-world live-base rows."""
    from defender.tests.storage.ids_1187 import _spec1187 as S

    episodes = S.episodes_dir(location_path(tenant_paths.data_root), str(tenant_paths.id))
    stale_id = S.new_id()
    stale = episodes / stale_id / "served" / "w1.jsonl"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"source":"base","world_id":null}\n', encoding="utf-8")

    with tenant_paths.runs_repository().create_episode() as view:
        fresh = view.episode_id
        assert fresh != stale_id, "the stale episode was handed out"
        assert not fresh.endswith("-r2"), f"{fresh!r} is a retry name"
        assert S.is_canonical_uuid(fresh), f"{fresh!r} is not a canonical uuid"
        assert list((episodes / fresh).rglob("*.jsonl")) == [], "the fresh episode holds rows"

    assert sorted(os.listdir(episodes)) == sorted([stale_id, fresh])
    assert stale.read_text(encoding="utf-8") == '{"source":"base","world_id":null}\n', (
        "the relaunch should not mutate or sanitize the stale episode")


def test_the_launcher_bootstraps_the_package_when_invoked_by_path(tmp_path):
    """The documented ``python3 defender/cli/learning/branch.py`` shape reaches argparse."""
    cli_path = Path(__file__).resolve().parents[3] / "cli" / "learning" / "branch.py"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)

    proc = subprocess.run(  # noqa: S603 — fixed in-repo launcher and interpreter
        [sys.executable, str(cli_path), "--help"], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert "usage: branch" in proc.stdout


def test_p4_a_branch_request_without_a_continuation_prompt_is_complete():
    """A tenant, a source run and a branch point are the whole request: it parses, and carries no
    prompt field."""
    ns = cli_mod().parse_branch_args(["--tenant", fixture_uuid("tenant:acme"), "run-x", "59"])

    assert (ns.tenant, ns.source_run_id, ns.branch_message_id) == (fixture_uuid("tenant:acme"), "run-x", 59)
    assert not hasattr(ns, "continuation_prompt"), (
        "the parsed request still carries a continuation prompt")


def test_p4_the_branch_command_line_refuses_a_continuation_prompt(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_mod().parse_branch_args(
            ["--tenant", fixture_uuid("tenant:acme"), "run-x", "59", "--continuation-prompt", "go"])

    assert exc.value.code == 2, f"exit {exc.value.code}"
    assert "--continuation-prompt" in capsys.readouterr().err


def test_p4_the_branch_help_offers_no_continuation_prompt(capsys):
    """The operator's help names no continuation prompt. Positive control: it still names the
    required tenant, so this is the launcher's help."""
    with pytest.raises(SystemExit) as exc:
        cli_mod().parse_branch_args(["--help"])

    out = capsys.readouterr().out
    assert exc.value.code == 0, out
    assert "--tenant" in out, out
    assert "continuation" not in out.lower(), out


TOKEN_A = T.fixture_world_id("a")


TOKEN_C = T.fixture_world_id("c")


# no model-visible text names a run or world token


def _model_text(detail: str) -> str:
    """The text a fault's detail becomes on the model's side of the tool boundary."""
    return T.mod("_redaction").redact_model_visible(
        detail, frozenset((TOKEN_A, TOKEN_C, T.EPISODE_ID)))


@pytest.mark.parametrize("detail", [
    "the system refused the read for run {a}: rate limited",
    "no record of {c} is visible to {a}",
    "Elasticsearch query failed (HTTP 404): no such index [logs-{a}]",
])
def test_947_no_model_visible_fault_text_names_a_run_or_world_token(detail):
    rendered = _model_text(detail.format(a=TOKEN_A, c=TOKEN_C))
    for leak in (TOKEN_A, TOKEN_C, T.EPISODE_ID):
        assert leak not in rendered, f"{leak!r} survived into model-visible text"
    assert rendered != detail.format(a=TOKEN_A, c=TOKEN_C), "nothing was redacted at all"


def test_947_an_ordinary_refusal_still_tells_the_model_something_actionable():
    plain = "index expression 'logs-*,alerts-*' names a multi-index list — refused whole"
    assert _model_text(plain) == plain
    redacted = _model_text(f"index 'logs-{TOKEN_A}' falls outside the configured patterns")
    assert redacted.strip()
    assert "falls outside the configured patterns" in redacted


#: Words that only a BRANCHED run could honestly use about itself: a defender reading any of
#: them in a refusal learns it is inside a branched episode.
_SCHEME_WORDS = ("world", "staged", "staging", "episode", "sibling", "branch", "overlay",
                 "corpus", "view")


@pytest.mark.parametrize("detail", [
    "Elasticsearch query failed (HTTP 404): no such index [logs-{a}]",
    "index 'logs-{a}' falls outside the configured patterns",
    "no such file /runs/{a}/alert.json",
])
def test_947_what_the_redaction_leaves_behind_names_nothing_about_the_scheme(detail):
    """WHAT REPLACES a removed name discloses no more than the name did."""
    rendered = _model_text(detail.format(a=TOKEN_A)).casefold()
    for word in _SCHEME_WORDS:
        assert word not in rendered, (
            f"the redaction's own replacement text says {word!r} — the marker discloses the "
            "scheme the removal exists to hide")
    assert rendered != detail.format(a=TOKEN_A).casefold(), (
        "nothing was redacted at all, so the assertion above passed on an unfiltered string")
