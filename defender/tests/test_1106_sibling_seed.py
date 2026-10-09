"""#1106 M2 — a branched sibling runs on its EPISODE's tenant, handed the data root by env.

A sibling is a child PROCESS: `cli.py` starts `run.py --resume <manifest> --world X` with only
`DEFENDER_RUNS_BASE=<episode>/runs` in its env. The child reads its tenant from that runs base's
`_tenant.json` (D4) — and before #1106 nothing seeded it, so every sibling minted the default
tenant whatever the episode's own stamp said: the same bug class `cli.py` already records for
the model. And the child would resolve its tenants root by itself, from its own checkout.

M2: before spawning, the parent writes `<episode>/runs/_tenant.json` carrying the episode
stamp's `tenant_id` (through `_tenant`'s create lane) and hands the child its root. A stamp with
no tenant — or the legacy `default` — refuses (N10, D3): no fallback.

#1120: tenants live under the data root only (the separate tenants root and its flag are
gone), so "the root" a child is handed is `DEFENDER_DATA_ROOT` in the environment it is spawned
with, and the episode's tenants are planted under this test's data root.

Observed through the launcher's existing process seam (`spawn=`): the recorder reads the tenant
record AT SPAWN TIME, so "written before the child starts" is an observation, and reads the
data root out of the env the child is actually spawned with, so "handed the root" means the
child would actually receive it. No `run.py` is launched.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender._episode_handle import Episode
from defender.tests import _tenants1106 as T
from defender.tests import _triplet_947 as P
from defender.tests._data_root_1078 import DATA_ROOT_ENV, current_data_root
from defender.tests.live_oracle_1224 import _spec1224 as O
from defender.tests.tenant_1107_settings import _spec1107 as S


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
        # The child's runs base is its episode's `runs/` (#1078 D2), the manifest's sibling.
        runs = Path(argv[argv.index("--resume") + 1]).parent / "runs"
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


#: #1120: the two argv-surface cases (`run.py` and the branch launcher each accepting a tenants
#: root flag) are RETIRED — tenants are found under `DEFENDER_DATA_ROOT` only, so neither
#: process takes a root on its command line. The hand-off they guarded is the env the child is
#: spawned with, pinned by `_child_data_root` below.


# ---- start_family: the seed and the hand-off ----------------------------------------------------

def test_start_family_seeds_the_episodes_tenant_before_any_child_starts(tmp_path):
    cli = T.mod("learning.branch.cli")
    ep = tmp_path / "episode"
    ep.mkdir()
    root = current_data_root()
    spawn = SpawnRecorder()
    with Episode.open(ep) as episode:
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
    """A family with no tenant, or an id no tenant can have, gets no fallback — there is no
    default tenant (#1078). Nothing is spawned and no record is minted (a minted record would
    be the fallback, just written down)."""
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
        outcome = T.mod("learning.branch.cli").main(
            [str(src), str(P.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
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


def test_a_launched_episodes_siblings_run_on_the_source_stamps_tenant(tmp_path):
    root = current_data_root()
    outcome, spawn, _est = _estate_launch(tmp_path)
    assert spawn.launches, f"no sibling was started: {outcome!r}"
    for launch in spawn.launches:
        assert launch["tenant_at_spawn"] == "acme", launch
        assert _child_data_root(launch).resolve() == root.resolve()


@pytest.mark.parametrize("stamp_tenant", [None, "default"])
def test_a_source_stamp_with_no_usable_tenant_refuses_the_episode_before_any_sibling(
        tmp_path, capsys, stamp_tenant):
    """The negative on the same launch: only the source stamp's tenant differs from the
    positive above, and no sibling starts and no tenant record is minted for the episode.
    (`default` is a row in the data root with no knowledge folder, as it was before #1120.)"""
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
    """The episode tenant, under an injected root, grants gather systems the checkout's
    playground does not have (`_spec1224`'s estate: `edr`, `idp`, `siem-x`). The manifest the
    launcher writes records THEM as `served_systems` — the set every sibling, the judge and the
    question-writer re-read (#1224 M20/M21, which replaced the corpus patterns this file once
    pinned) — and pre-flight's reads reach the episode tenant's estate. The episode still runs
    (the positive control: siblings start)."""
    checkout = T.fixture_run_tenant().grants.gather
    outcome, spawn, est = _estate_launch(tmp_path)
    assert spawn.launches, f"no sibling was started: {outcome!r}"
    served = sorted(est.served_systems())
    assert not set(served) & {s for s, _v, _c in checkout.entries}, (
        "the fixture no longer discriminates from the checkout's copy")
    manifest = T.mod("learning.branch.cli").episode_dir_for(
        P.EPISODE_ID, tenant=P.current_tenant()) / "family.yaml"
    doc = T.mod("_yaml").safe_load(manifest.read_text(encoding="utf-8"))
    assert doc["served_systems"] == served, doc["served_systems"]
    assert {c["system"] for c in est.calls()} == {"idp", "edr"}, est.calls()


def test_a_source_stamp_disagreeing_with_its_runs_base_record_refuses_before_any_sibling(
        tmp_path, capsys):
    """The stamp is in the box's writable run dir; a model can rewrite its `tenant_id`. Both
    tenants exist, the record says `acme`, the stamp says `bravo`: refused, naming both and the
    record, before a sibling starts — never a family staged into bravo's estate. The control is
    `test_a_launched_episodes_siblings_run_on_the_source_stamps_tenant` (the two agree)."""
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
    """The launcher applies the run start's content rules to the episode's tenant: a table
    that loads but grants gather only `health-check` is refused before the questioner is paid,
    pre-flight replays or any sibling starts — not by every sibling afterwards. The control is
    `test_a_launched_episodes_siblings_run_on_the_source_stamps_tenant`."""
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
            [str(src), str(P.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
            spawn=spawn, questioner=questioner,
            preflight=O.no_preflight, live_tree=P.source_capture(tenant_id="acme"))
    text = f"{refused.value} {capsys.readouterr().err}"
    assert "query" in text, text
    assert "verb-grants.yaml" in text, text
    assert spawn.launches == []
    assert questioner.calls == 0, "the questioner was paid for before the refusal"


def test_a_source_stamp_naming_a_tenant_absent_from_the_injected_root_refuses_before_any_sibling(
        tmp_path, capsys):
    """The stamp names `ghost`; the data root holds `ghost`'s row and runs base but no knowledge
    folder for it, and a complete `acme` — no fallback to `acme`: refused, naming the missing
    folder, before a sibling starts or a record is minted. The control is the `acme` launch
    above. (#1120: one root now holds both the rows and the knowledge, so "absent from the
    injected root" is `ghost`'s knowledge folder absent beside its row.)"""
    root = current_data_root()
    src = _knowledgeless_source(tmp_path, "ghost")
    _episode_tenant(root)
    outcome, spawn = _launch(tmp_path, stamp_tenant="ghost", source=src)
    err = capsys.readouterr().err
    assert spawn.launches == [], spawn.launches
    assert str(root / "ghost") in f"{outcome} {err}", (outcome, err)
    episodes = tmp_path / "episodes-root"
    minted = sorted(str(p) for p in episodes.rglob("_tenant.json")) if episodes.exists() else []
    assert minted == [], minted


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
            alert_path=src / "alert.json", run_dir=src, run_id=src.name,
            defender_dir=P.DEFENDER, model_name="m", model_override=None, box=None,
            tenant=record,
            world=run.resume_world(Episode.open(ep), "b", tenant=lambda r=record: r),
            episode=Episode.open(ep),
            investigate=lambda seen=seen, **kw: seen.update(kw) or {})
        registry = seen["verbs"]
        assert type(registry).__name__ == "WorldRegistry", type(registry)
        assert {(s, v) for s, v, _ in registry.grant.entries} == set(pairs), tenant_id
        assert registry.decide(*own_pair).outcome == "GRANTED", (tenant_id, own_pair)
        assert registry.decide(*other_pair).outcome != "GRANTED", (tenant_id, other_pair)
        # The MODEL-FACING pointer names this tenant's table, never the host path to it.
        assert repr(tenant_id) in str(registry.grant_home), (tenant_id, registry.grant_home)
        assert str(grants.path) not in str(registry.grant_home), registry.grant_home
