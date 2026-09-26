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

def _launch(tmp_path: Path, *, stamp_tenant: str | None, root: Path,
            door: Any = None) -> tuple[Any, SpawnRecorder]:
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
            spawn=spawn, door=door if door is not None else P.FakeDoor(),
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


# ---- O2/O6 on the branching lane: the launcher reads the INJECTED episode tenant ------------------

#: Corpus patterns no committed tenant configures — the checkout's playground names `logs-*`
#: and the security alerts index, so a launcher that read the checkout would record those. The
#: events pattern is WIDER than `logs-*` (it still reaches the fixture world's `logs-*` overlay,
#: so the episode can stage it); the alerts pattern is one no tenant in the checkout has.
TENANT_PATTERNS = ("log*", "tenant-alerts-*")


def test_the_launcher_judges_and_records_the_episode_tenants_own_corpus_patterns(tmp_path):
    """The episode tenant, under an injected root, configures corpus patterns the checkout's
    playground does not. The launcher's preflight probes the cluster through the FIRST of THEM
    (the write door's `count` is the inbound payload), and the manifest it writes records THEM
    as `configured_patterns` — the set every sibling, the registry's own-view test and the
    judge re-read. The episode still runs (the positive control: siblings start)."""
    stager = T.mod("learning.branch.estate.stagers.elastic")
    assert tuple(stager.configured_patterns(T.PLAYGROUND_SETTINGS)) != TENANT_PATTERNS, \
        "the fixture no longer discriminates from the checkout's copy"
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme", configs=T.config_texts(
        "acme", events_index=TENANT_PATTERNS[0], alerts_index=TENANT_PATTERNS[1]))
    door = P.FakeDoor()
    outcome, spawn = _launch(tmp_path, stamp_tenant="acme", root=root, door=door)
    assert spawn.launches, f"no sibling was started: {outcome!r}"
    probed = [name for op, name in door.ops if op == "count"]
    assert probed, door.ops
    assert probed[0] == TENANT_PATTERNS[0], probed
    assert not {"logs-*", P.ALERTS_PATTERN} & set(probed), probed
    manifest = T.mod("learning.branch.cli").episode_dir_for(P.EPISODE_ID) / "family.yaml"
    doc = T.mod("_yaml").safe_load(manifest.read_text(encoding="utf-8"))
    assert tuple(doc["configured_patterns"]) == TENANT_PATTERNS, doc["configured_patterns"]


def test_a_source_stamp_naming_a_tenant_absent_from_the_injected_root_refuses_before_any_sibling(
        tmp_path, capsys):
    """The stamp names `ghost`; the injected root holds only `acme` (and the checkout's own root
    holds `playground`) — no fallback to either: refused, naming the missing folder, before a
    sibling starts or a record is minted. The control is the `acme` launch above."""
    root = tmp_path / "tenants"
    _episode_tenant(root)
    outcome, spawn = _launch(tmp_path, stamp_tenant="ghost", root=root)
    err = capsys.readouterr().err
    assert spawn.launches == [], spawn.launches
    assert str(root / "ghost") in f"{outcome} {err}", (outcome, err)
    episodes = tmp_path / "episodes-root"
    minted = sorted(str(p) for p in episodes.rglob("_tenant.json")) if episodes.exists() else []
    assert minted == [], minted


def test_the_reviews_production_read_side_is_built_on_the_episode_tenant(tmp_path):
    """The review replays through `seams.adapter_seam(episode, tenant)` when no adapters are
    injected: its registry must hold the EPISODE tenant's gather grant (a pair the family's
    siblings cannot reach must not be reachable by the review either), point its refusals at
    that tenant's table (by name, not host path), and carry that tenant's settings on its verb context. Tenant B's
    table differs from the checkout playground's, pair by pair."""
    seams = T.mod("learning.branch.seams")
    b = T.plant_tenant(tmp_path / "tenants", "bravo", table=T.TABLE_B, marker="bravo")
    tenant = T.tenants().tenant_dir(tmp_path / "tenants", "bravo")
    ep = P.episode(tmp_path)
    side = seams.adapter_seam(ep, tenant)
    assert {(s, v) for s, v, _ in side.registry.grant.entries} == set(T.GATHER_PAIRS_B)
    assert side.registry.decide("identity", "get-user").outcome == "GRANTED"
    denied = side.registry.decide("identity", "can-access")
    assert denied.outcome == "DENIED", denied
    # The refusal is MODEL-facing: it names the episode tenant's table, never its host path.
    from defender.runtime.run_tenant import table_pointer

    assert table_pointer("bravo") in (denied.refusal or ""), denied.refusal
    assert str(b) not in (denied.refusal or ""), denied.refusal
    assert str(tenant.settings) not in (denied.refusal or ""), denied.refusal
    assert Path(side.ctx.settings_dir) == tenant.settings
    transport = T.mod("scripts.adapters._stub_transport")
    assert transport.load_config(side.ctx, "identity", "IDENTITY")["URL_BASE"] == \
        "http://identity-bravo:8080"


# ---- O3 on the resume path: a sibling serves through its OWN run's grant ------------------------

_ELASTIC_FOR_GATHER = """\
  elastic:
    health-check: {roles: [gather]}
    query: {roles: [gather]}
"""


def test_a_resumed_siblings_world_registry_holds_its_runs_gather_grant(tmp_path):
    """`run.py --resume` builds a `WorldRegistry` rather than the production registry, and it
    must be built over the RUN's `grants.gather` — the parity the ordinary arm already pins
    (`e2e/test_1106_run_start.py`). One process drives the world arm for two tenants whose
    tables differ; each registry holds exactly its own tenant's pairs, grants a pair only its
    tenant holds and refuses the other's, and points its refusals at its own table."""
    run = T.mod("run")
    base, src = P.runs_base(tmp_path)
    ep = P.episode(tmp_path, doc=P.family_doc(source_run_dir=str(src)))
    root = tmp_path / "tenants"
    # The fixture world touches elastic, and a world may only touch a system its grant serves,
    # so both tables reach elastic; they still differ on cmdb and identity.
    T.plant_tenant(root, "acme", table=T.TABLE_A)
    T.plant_tenant(root, "bravo", table=T.TABLE_B + _ELASTIC_FOR_GATHER)
    elastic = {("elastic", "health-check"), ("elastic", "query")}
    expected = {"acme": (T.GATHER_PAIRS_A, ("cmdb", "get-host"), ("identity", "get-user")),
                "bravo": (T.GATHER_PAIRS_B | elastic, ("identity", "get-user"),
                          ("cmdb", "get-host"))}
    for tenant_id, (pairs, own_pair, other_pair) in expected.items():
        tenant = T.tenants().tenant_dir(root, tenant_id)
        grants = T.run_grants(tenant.settings)
        seen: dict = {}
        run._drive_investigation(
            alert_path=src / "alert.json", run_dir=src, run_id=src.name,
            defender_dir=P.DEFENDER, model_name="m", model_override=None, box=None,
            tenant=T.run_tenant(tenant, grants=grants),
            world=run.resume_world(ep / "family.yaml", "b", settings=lambda t=tenant: t.settings),
            investigate=lambda seen=seen, **kw: seen.update(kw) or {})
        registry = seen["verbs"]
        assert type(registry).__name__ == "WorldRegistry", type(registry)
        assert {(s, v) for s, v, _ in registry.grant.entries} == set(pairs), tenant_id
        assert registry.decide(*own_pair).outcome == "GRANTED", (tenant_id, own_pair)
        assert registry.decide(*other_pair).outcome != "GRANTED", (tenant_id, other_pair)
        # The MODEL-FACING pointer names this tenant's table, never the host path to it.
        assert repr(tenant_id) in str(registry.grant_home), (tenant_id, registry.grant_home)
        assert str(grants.path) not in str(registry.grant_home), registry.grant_home
