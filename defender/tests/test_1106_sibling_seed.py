"""#1106 M2 — a branched sibling runs on its EPISODE's tenant, handed the tenants root explicitly.

A sibling is a child PROCESS: `cli.py` starts `run.py --resume <manifest> --world X` with only
`DEFENDER_RUNS_BASE=<episode>/runs` in its env. The child reads its tenant from that runs base's
`_tenant.json` (D4) — and before #1106 nothing seeded it, so every sibling minted the default
tenant whatever the episode's own stamp said: the same bug class `cli.py` already records for
the model. And the child would resolve its tenants root by itself, from its own checkout.

M2: before spawning, the parent writes `<episode>/runs/_tenant.json` carrying the episode
stamp's `tenant_id` (through `_tenant`'s create lane) and hands the child `--tenants-root`. A
stamp with no tenant — or the legacy `default` — refuses (N10, D3): no fallback.

Observed through the launcher's existing process seam (`spawn=`): the recorder reads the tenant
record AT SPAWN TIME, so "written before the child starts" is an observation, and parses the
child's argv with `run.py`'s own parser, so "handed the root" means the child would actually
receive it. No `run.py` is launched.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.tests import _tenants1106 as T
from defender.tests import _triplet_947 as P


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """The launcher's two configured roots inside `tmp_path` (as `test_947_triplet_launcher`)."""
    monkeypatch.setenv(P.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


class SpawnRecorder:
    """`spawn=`: records each child's argv and env, and the tenant record the child's runs base
    held at the moment the child was started."""

    def __init__(self) -> None:
        self.launches: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **_kw: Any) -> int:
        env = dict(env or {})
        runs = Path(env.get("DEFENDER_RUNS_BASE", ""))
        try:
            record = T.mod("_tenant").read_tenant(runs).tenant_id
        except Exception as e:  # noqa: BLE001 — "no readable record at spawn" is the observation
            record = f"<unreadable: {e!r}>"
        self.launches.append({"argv": list(argv), "env": env, "tenant_at_spawn": record})
        return 0


def _child_tenants_root(argv: list[str]) -> Path:
    """The tenants root the child `run.py` would receive, read by `run.py`'s OWN parser."""
    assert argv[1].endswith("run.py"), argv
    ns = T.mod("run").parse_args(argv[2:])
    assert ns.tenants_root is not None, argv
    return Path(ns.tenants_root)


# ---- the argv surface ---------------------------------------------------------------------------

def test_run_py_accepts_a_tenants_root_on_both_paths(tmp_path):
    run = T.mod("run")
    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")
    assert Path(run.parse_args([str(alert), "--tenants-root", str(tmp_path / "t")]).tenants_root) \
        == tmp_path / "t"
    resumed = run.parse_args(["--resume", str(tmp_path / "family.yaml"), "--world", "b",
                              "--tenants-root", str(tmp_path / "t")])
    assert Path(resumed.tenants_root) == tmp_path / "t"


def test_the_branch_launcher_accepts_a_tenants_root(tmp_path):
    cli = T.mod("learning.branch.cli")
    ns = cli.parse_branch_args([str(tmp_path / "src"), "3", "--continuation-prompt", "go",
                                "--tenants-root", str(tmp_path / "t")])
    assert Path(ns.tenants_root) == tmp_path / "t"


# ---- start_family: the seed and the hand-off ----------------------------------------------------

def test_start_family_seeds_the_episodes_tenant_before_any_child_starts(tmp_path):
    cli = T.mod("learning.branch.cli")
    ep = tmp_path / "episode"
    ep.mkdir()
    root = tmp_path / "tenants"
    spawn = SpawnRecorder()
    exits = cli.start_family(ep, ["b", "c"], spawn=spawn, tenant_id="acme", tenants_root=root)
    assert exits == {"b": 0, "c": 0}
    assert len(spawn.launches) == 2
    for launch in spawn.launches:
        assert launch["tenant_at_spawn"] == "acme", launch
        assert Path(launch["env"]["DEFENDER_RUNS_BASE"]) == ep / "runs"
        assert _child_tenants_root(launch["argv"]).resolve() == root.resolve()
    assert T.mod("_tenant").read_tenant(ep / "runs").tenant_id == "acme"


@pytest.mark.parametrize("tenant_id", [None, "default"])
def test_start_family_refuses_an_episode_with_no_tenant_and_starts_nothing(tmp_path, tenant_id):
    """N10: a legacy family — its stamp carries no tenant, or the retired `default` — gets no
    fallback. Nothing is spawned and no record is minted (a minted record would be the
    fallback, just written down)."""
    cli = T.mod("learning.branch.cli")
    ep = tmp_path / "episode"
    ep.mkdir()
    spawn = SpawnRecorder()
    with pytest.raises(Exception) as caught:  # noqa: PT011 — the class is the launcher's; the effect is pinned
        cli.start_family(ep, ["b"], spawn=spawn, tenant_id=tenant_id,
                         tenants_root=tmp_path / "tenants")
    assert not isinstance(caught.value, TypeError), (
        f"start_family does not take the episode's tenant yet: {caught.value!r}")
    assert "tenant" in str(caught.value).lower(), caught.value
    assert spawn.launches == []
    assert not (ep / "runs" / "_tenant.json").exists()


# ---- end to end through the launcher ------------------------------------------------------------

def _launch(tmp_path: Path, *, stamp_tenant: str | None, root: Path) -> tuple[Any, SpawnRecorder]:
    """One episode through the real launcher (`cli.main`), as `test_947_triplet_launcher` drives
    it, with the SOURCE run's stamp naming `stamp_tenant` and `--tenants-root root`."""
    base, src = P.runs_base(tmp_path)
    P.source_stamp(src, tenant_id=stamp_tenant)
    spawn = SpawnRecorder()
    outcome: Any
    try:
        outcome = T.mod("learning.branch.cli").main(
            [str(src), str(P.BRANCH_MESSAGE_ID), "--continuation-prompt", "go",
             "--tenants-root", str(root)],
            spawn=spawn, door=P.FakeDoor(),
            questioner=P.FakeAgent(P.family_doc(), P.world_doc("b"), P.world_doc("c")),
            adapters=P.FakeAdapters(), invoke=P.FakeAgent(*["same"] * 24),
            preflight=P.no_preflight, live_tree=P.source_capture(tenant_id=stamp_tenant))
    except (Exception, SystemExit) as refused:  # noqa: BLE001 — a refusal is an outcome here
        outcome = refused
    return outcome, spawn


def _episode_tenant(root: Path) -> Path:
    """A complete tenant whose elastic patterns are the fixture's configured pair, so the
    stager's namespace checks accept the family's overlays."""
    return T.plant_tenant(root, "acme", configs=T.config_texts(
        "acme", events_index=P.EVENTS_PATTERN, alerts_index=P.ALERTS_PATTERN))


def test_a_launched_episodes_siblings_run_on_the_source_stamps_tenant(tmp_path):
    root = tmp_path / "tenants"
    _episode_tenant(root)
    outcome, spawn = _launch(tmp_path, stamp_tenant="acme", root=root)
    assert spawn.launches, f"no sibling was started: {outcome!r}"
    for launch in spawn.launches:
        assert launch["tenant_at_spawn"] == "acme", launch
        assert _child_tenants_root(launch["argv"]).resolve() == root.resolve()


@pytest.mark.parametrize("stamp_tenant", [None, "default"])
def test_a_source_stamp_with_no_usable_tenant_refuses_the_episode_before_any_sibling(
        tmp_path, capsys, stamp_tenant):
    """The negative on the same launch: only the source stamp's tenant differs from the
    positive above, and no sibling starts and no tenant record is minted for the episode."""
    root = tmp_path / "tenants"
    _episode_tenant(root)
    outcome, spawn = _launch(tmp_path, stamp_tenant=stamp_tenant, root=root)
    err = capsys.readouterr().err
    assert "unrecognized arguments" not in err, f"the launcher never read the stamp: {err}"
    assert spawn.launches == [], spawn.launches
    assert "tenant" in f"{outcome!r} {err}".lower(), (outcome, err)
    episodes = tmp_path / "episodes-root"
    minted = sorted(str(p) for p in episodes.rglob("_tenant.json")) if episodes.exists() else []
    assert minted == [], minted
