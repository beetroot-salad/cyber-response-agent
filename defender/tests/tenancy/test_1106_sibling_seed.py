"""A branched sibling runs on its episode's tenant, handed the data root by env; no stamped tenant refuses."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165

from pathlib import Path
from typing import Any

import pytest

from defender import _episode_handle as EH
from defender._episode_handle import Episode
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.learning.branch import _triplet_947 as P
from defender.tests.support.shared.contracts._data_root_1078 import DATA_ROOT_ENV, current_data_root
from defender.tests.learning.oracle.live_contracts import _spec1224 as O
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.run_repository import RunPaths


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(P.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(P.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


class SpawnRecorder:
    """`spawn=`: records each child's argv and env, and the tenant record the child's runs base
    held at the moment the child was started."""

    def __init__(self) -> None:
        self.launches: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **_kw: Any) -> int:
        env = dict(env or {})
        # The child's runs base is its episode's `runs/` (#1078 D2); #1105 PR 2: the child
        # names its episode by id, under the episodes base its environment carries.
        runs = (Path(env[P.EPISODES_BASE_ENV]).resolve() / argv[argv.index("--episode") + 1]
                / "runs")
        try:
            record = T.mod("_tenant").read_tenant(runs).tenant_id
        except Exception as e:  # noqa: BLE001 — "no readable record at spawn" is the observation
            record = f"<unreadable: {e!r}>"
        self.launches.append({"argv": list(argv), "env": env, "tenant_at_spawn": record})
        return 0


def _child_data_root(launch: dict[str, Any]) -> Path:
    """The data root the child `run.py` would re-accept its tenant under: the
    `DEFENDER_DATA_ROOT` in the env it was spawned with (#1120 — the separate tenants root, and
    the flag that carried it, are gone)."""
    assert launch["argv"][1].endswith("run.py"), launch["argv"]
    assert launch["env"].get(DATA_ROOT_ENV), launch["env"]
    return Path(launch["env"][DATA_ROOT_ENV])


# ---- start_family: the seed and the hand-off ----------------------------------------------------

def test_start_family_seeds_the_episodes_tenant_before_any_child_starts(tmp_path):
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105

    cli = T.mod("learning.branch.cli")
    ep = tmp_path / "episodes-root" / "episode"
    ep.mkdir(parents=True)
    root = current_data_root()
    spawn = SpawnRecorder()
    acme = H1105.tenant(root, "acme")
    with Episode.open(ep) as episode:
        acme.runs_repository().episode(episode.dir.name, held=episode).create_container()
        exits = cli.start_family(episode, ["b", "c"], spawn=spawn, tenant_id="acme")
    assert exits == {"b": 0, "c": 0}
    assert len(spawn.launches) == 2
    for launch in spawn.launches:
        assert launch["tenant_at_spawn"] == "acme", launch
        argv = launch["argv"]
        assert argv[argv.index("--tenant") + 1] == "acme", argv
        assert _child_data_root(launch).resolve() == root.resolve()
    assert T.mod("_tenant").read_tenant(ep / "runs").tenant_id == "acme"


@pytest.mark.parametrize("tenant_id", [None, "Not A Tenant"])
def test_start_family_refuses_an_episode_with_no_tenant_and_starts_nothing(tmp_path, tenant_id):
    cli = T.mod("learning.branch.cli")
    ep = tmp_path / "episode"
    ep.mkdir()
    spawn = SpawnRecorder()
    with Episode.open(ep) as episode, \
            pytest.raises(Exception) as caught:  # noqa: PT011 — the class is the launcher's; the effect is pinned
        cli.start_family(episode, ["b"], spawn=spawn, tenant_id=tenant_id)
    assert not isinstance(caught.value, TypeError), (
        f"start_family does not take the episode's tenant yet: {caught.value!r}")
    assert "tenant" in str(caught.value).lower(), caught.value
    assert spawn.launches == []
    assert not (ep / "runs" / "_tenant.json").exists()


# ---- end to end through the launcher ------------------------------------------------------------

_AS_STAMPED = object()


def _main(src: Path, *, stamp_tenant: str | None, roster: Any = None) -> tuple[Any, SpawnRecorder]:
    """One episode from `src` through the real launcher (`cli.main`), every seam injected: the
    question-writer, the role preflight, the live tree, and pre-flight's roster and oracle and
    verifier doubles (#1224 — an oracle serving every call unchanged and a verifier passing it).
    A refusal is returned as the outcome rather than raised."""
    spawn = SpawnRecorder()
    outcome: Any
    try:
        # #1105 PR 2 (declared change 1): the request names the tenant whose location
        # `<root>/<T>/runs/<run id>` the source sits at, and the source by its id.
        outcome = T.mod("learning.branch.cli").main(
            ["--tenant", src.parent.parent.name, src.name, str(P.BRANCH_MESSAGE_ID),
             *P.retired_continuation_argv()],
            spawn=spawn, questioner=O.questioner_for(), preflight=O.no_preflight,
            live_tree=P.source_capture(tenant_id=stamp_tenant), roster=roster,
            oracle=O.oracle(then=O.submit(_BASE, O.EMPTY_CLAIM)).model,
            verifier=O.passing_verifier().model)
    except (Exception, SystemExit) as refused:  # noqa: BLE001 — a refusal is an outcome here
        outcome = refused
    return outcome, spawn


def _launch(tmp_path: Path, *, stamp_tenant: str | None, record_tenant: Any = _AS_STAMPED,
            source: Path | None = None) -> tuple[Any, SpawnRecorder]:
    """One episode through the real launcher, as `test_947_triplet_launcher` drives it, with
    the SOURCE run's stamp naming `stamp_tenant` and its runs base's record naming
    `record_tenant` (the same tenant unless a scenario says otherwise; `None` leaves the
    fixture's own record). The launcher finds tenants under this test's data root (#1120).
    `source` is a source run dir the scenario already built (its tenant shaped by hand). Every
    scenario driving this one is refused before pre-flight reads anything."""
    record = stamp_tenant if record_tenant is _AS_STAMPED else record_tenant
    # The source sits at its record's tenant location (#1078 O5); `None` keeps the fixture's.
    src = source if source is not None else P.runs_base(tmp_path, tenant_id=record)[1]
    P.source_stamp(src, tenant_id=stamp_tenant)
    return _main(src, stamp_tenant=stamp_tenant)


#: The one answer every captured call of the estate source carries, so one scripted oracle
#: submission serves every call unchanged and the family is accepted.
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "host": "web-1"}]}


def _estate_launch(tmp_path: Path) -> tuple[Any, SpawnRecorder, Any]:
    """One ACCEPTED episode over `_spec1224`'s estate tenant (`acme`, systems the checkout's
    playground does not have), stamped `acme`. Returns `(outcome, spawn, estate)`."""
    est = O.estate(tmp_path)
    _base, src = O.source_run(tmp_path, est, calls=[
        O.Call("idp", "query", O.query_params("user:alice"), _BASE),
        O.Call("edr", "query", O.query_params("host:web-1"), _BASE)])
    outcome, spawn = _main(src, stamp_tenant="acme", roster=est.roster())
    return outcome, spawn, est


def _episode_tenant(root: Path) -> Path:
    """A complete tenant `acme` (its elastic patterns the fixture's configured pair) — the
    episode tenant a refused launch is refused beside."""
    return T.place_tenant(root, "acme", configs=S.config_texts(
        "acme", events_index=P.EVENTS_PATTERN, alerts_index=P.ALERTS_PATTERN))


def _knowledgeless_source(tmp_path: Path, tenant_id: str) -> Path:
    """A source run under `tenant_id`, whose row and runs-base record exist in the data root but
    whose knowledge folder does not — the tenant no operator set up knowledge for (before #1120:
    a row in the data root with no folder in the separate tenants root). Built FIRST, while the
    root is fresh (O10: `create_tenant` mints only into a fresh root); the episode's complete
    tenant is planted beside it afterwards, by hand."""
    import shutil

    _base, src = P.runs_base(tmp_path, tenant_id=tenant_id)
    shutil.rmtree(current_data_root() / tenant_id / "knowledge")
    return src


@pytest.mark.parametrize("stamp_tenant", [None, "default"])
def test_a_source_stamp_with_no_usable_tenant_refuses_the_episode_before_any_sibling(
        tmp_path, capsys, stamp_tenant):
    src = None if stamp_tenant is None else _knowledgeless_source(tmp_path, stamp_tenant)
    _episode_tenant(current_data_root())
    outcome, spawn = _launch(tmp_path, stamp_tenant=stamp_tenant, source=src)
    err = capsys.readouterr().err
    assert "unrecognized arguments" not in err, f"the launcher never read the stamp: {err}"
    assert spawn.launches == [], spawn.launches
    assert "tenant" in f"{outcome!r} {err}".lower(), (outcome, err)
    episodes = tmp_path / "episodes-root"
    minted = sorted(str(p) for p in episodes.rglob("_tenant.json")) if episodes.exists() else []
    assert minted == [], minted


# ---- O2/O6 on the branching lane: the launcher reads the INJECTED episode tenant ------------------

def test_the_launcher_judges_and_records_the_episode_tenants_own_served_systems(tmp_path):
    checkout = T.fixture_run_tenant().grants.gather
    outcome, spawn, est = _estate_launch(tmp_path)
    assert spawn.launches, f"no sibling was started: {outcome!r}"
    served = sorted(est.served_systems())
    assert not set(served) & {s for s, _v, _c in checkout.entries}, (
        "the fixture no longer discriminates from the checkout's copy")
    manifest = EH.episode_dir(P.current_tenant().data_root, P.EPISODE_ID) / "family.yaml"
    doc = T.mod("_yaml").safe_load(manifest.read_text(encoding="utf-8"))
    assert doc["served_systems"] == served, doc["served_systems"]
    assert {c["system"] for c in est.calls()} == {"idp", "edr"}, est.calls()


def test_a_source_stamp_disagreeing_with_its_runs_base_record_refuses_before_any_sibling(
        tmp_path, capsys):
    root = current_data_root()
    _episode_tenant(root)
    T.place_tenant(root, "bravo", configs=S.config_texts(
        "bravo", events_index=P.EVENTS_PATTERN, alerts_index=P.ALERTS_PATTERN))
    outcome, spawn = _launch(tmp_path, stamp_tenant="bravo", record_tenant="acme")
    text = f"{outcome} {capsys.readouterr().err}"
    assert spawn.launches == [], spawn.launches
    assert "'bravo'" in text, text
    assert "'acme'" in text, text
    assert "_tenant.json" in text, text


def test_an_episode_tenant_gather_can_query_nothing_under_refuses_before_the_questioner(
        tmp_path, capsys):
    T.place_tenant(current_data_root(), "acme", table=(
        "dispositions:\n"
        "  cmdb:\n"
        "    get-host: {roles: [], reason: \"withheld in this fixture\"}\n"
        "    health-check: {roles: [gather]}\n"),
        configs=S.config_texts("acme", events_index=P.EVENTS_PATTERN,
                               alerts_index=P.ALERTS_PATTERN))
    questioner = O.questioner_for()
    base, src = P.runs_base(tmp_path, tenant_id="acme")
    P.source_stamp(src, tenant_id="acme")
    spawn = SpawnRecorder()
    with pytest.raises((Exception, SystemExit)) as refused:  # noqa: PT011 — the launcher's refusal type is not what is pinned; its text and timing are
        T.mod("learning.branch.cli").main(
            ["--tenant", "acme", src.name, str(P.BRANCH_MESSAGE_ID),
             *P.retired_continuation_argv()],
            spawn=spawn, questioner=questioner,
            preflight=O.no_preflight, live_tree=P.source_capture(tenant_id="acme"))
    text = f"{refused.value} {capsys.readouterr().err}"
    assert "query" in text, text
    assert "verb-grants.yaml" in text, text
    assert spawn.launches == []
    assert questioner.calls == 0, "the questioner was paid for before the refusal"


# ---- O3 on the resume path: a sibling serves through its OWN run's grant ------------------------

_ELASTIC_FOR_GATHER = """\
  elastic:
    health-check: {roles: [gather]}
    query: {roles: [gather]}
"""


def test_a_resumed_siblings_world_registry_holds_its_runs_gather_grant(tmp_path):
    run = T.mod("run")
    base, src = P.runs_base(tmp_path)
    ep = P.episode(tmp_path, doc=P.family_doc(source_run_dir=str(src)))
    root = current_data_root()
    # Both tables reach elastic, the system the fixture source's one captured call read; they
    # still differ on cmdb and identity.
    T.place_tenant(root, "acme", table=T.TABLE_A, configs=S.config_texts("acme"))
    T.place_tenant(root, "bravo", table=T.TABLE_B + _ELASTIC_FOR_GATHER,
                   configs=S.config_texts("bravo"))
    elastic = {("elastic", "health-check"), ("elastic", "query")}
    expected = {"acme": (T.GATHER_PAIRS_A, ("cmdb", "get-host"), ("identity", "get-user")),
                "bravo": (T.GATHER_PAIRS_B | elastic, ("identity", "get-user"),
                          ("cmdb", "get-host"))}
    for tenant_id, (pairs, own_pair, other_pair) in expected.items():
        tenant = T.accept(root, tenant_id)
        record = T.run_tenant(tenant)
        grants = record.grants
        seen: dict = {}
        run._drive_investigation(
            alert_path=RunPaths(src).alert, run=_fixture_run_1165(src),
            defender_dir=P.DEFENDER, model_name="m", model_override=None, box=None,
            tenant=record,
            world=run.resume_world(Episode.open(ep), "b", tenant=lambda r=record: r),
            episode=Episode.open(ep), serving=O.serving(), source=P.open_source(src),
            investigate=lambda seen=seen, **kw: seen.update(kw) or {})
        registry = seen["verbs"]
        assert type(registry).__name__ == "WorldRegistry", type(registry)
        assert {(s, v) for s, v, _ in registry.grant.entries} == set(pairs), tenant_id
        assert registry.decide(*own_pair).outcome == "GRANTED", (tenant_id, own_pair)
        assert registry.decide(*other_pair).outcome != "GRANTED", (tenant_id, other_pair)
        # The MODEL-FACING pointer names the table, never a tenant (#1255 O3) and never the
        # host path to it.
        pointer = str(registry.grant_home)
        assert "verb-grants.yaml" in pointer, (tenant_id, pointer)
        named = [tid for tid in expected if tid in pointer]
        assert not named, f"the model-facing pointer names tenant(s) {named}: {pointer!r}"
        assert str(grants.path) not in pointer, pointer
