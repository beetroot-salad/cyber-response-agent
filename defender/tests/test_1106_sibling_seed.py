"""#1106 M2 — a branched sibling runs on its EPISODE's tenant, handed the data root by env.

A sibling is a child PROCESS: `cli.py` starts `run.py --resume <manifest> --world X` (#1105 PR 2:
`--tenant T --episode <episode_id> --world X`) with only
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

#1187 (R1, R2): the episode's `runs/_tenant.json` is retired — the child's tenant is the
`--tenant` it is started with, and its episode is `<data root>/<T>/episodes/<ep>`, where only
that tenant's request can reach it. What the launcher writes before the first child starts is
the arm ROSTER (`arms.json`, at the start of RUNS), naming every manifest world.

Observed through the launcher's existing process seam (`spawn=`): the recorder reads the
episode's ROSTER AT SPAWN TIME, so "written before the child starts" is an observation, and
reads the data root out of the env the child is actually spawned with, so "handed the root"
means the child would actually receive it. No `run.py` is launched.
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _fixture_run_1165

from pathlib import Path
from typing import Any

import pytest

from defender._episode_handle import Episode
from defender.tests import _tenants1106 as T
from defender.tests import _triplet_947 as P
from defender.tests._data_root_1078 import DATA_ROOT_ENV, current_data_root
from defender.tests.live_oracle_1224 import _spec1224 as O
from defender.tests.tenant_1107_settings import _spec1107 as S
from defender.run_repository import RunPaths


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """The launcher's configured operator runs base inside `tmp_path` (as
    `test_947_triplet_launcher`). #1187 (O9): no episodes root is configured."""
    monkeypatch.setenv(P.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))


def _arg(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


class SpawnRecorder:
    """`spawn=`: records each child's argv and env, the `--tenant` it is started with, and the
    arm roster its episode held at the moment the child was started (#1187: the episode is
    `<data root>/<T>/episodes/<ep>` of the child's own `--tenant` and `--episode`; the data
    root is the one the child's env hands it)."""

    def __init__(self) -> None:
        self.launches: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **_kw: Any) -> int:
        import json

        env = dict(env or {})
        tenant_id = _arg(argv, "--tenant")
        ep = (Path(env[DATA_ROOT_ENV]).resolve() / tenant_id / "episodes"
              / _arg(argv, "--episode"))
        roster_path = ep / P.ROSTER_NAME
        try:
            roster = json.loads(roster_path.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 — "no readable roster at spawn" is the observation
            roster = f"<unreadable: {e!r}>"
        self.launches.append({"argv": list(argv), "env": env, "tenant_at_spawn": tenant_id,
                              "roster_at_spawn": roster, "episode": ep})
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
    """Every child is started with the episode tenant's `--tenant` and handed the data root,
    over an episode that reached RUNS: the episode at `<acme>/episodes/<uuid>` whose roster the
    view's `start_runs` wrote before `start_family` — so every child, at the moment it starts,
    finds the roster naming its label (O4b). No `_tenant.json` is written anywhere.
    #1187 declared change 6
    #1187 declared change 10
    """
    from defender.tests.tenant_1105_run_repository import _spec1105 as H1105

    cli = T.mod("learning.branch.cli")
    root = current_data_root()
    spawn = SpawnRecorder()
    acme = H1105.tenant(root, "acme")
    runs = acme.runs_repository()
    with runs.create_episode() as view:
        roster = view.start_runs(["b", "c"])
        ep = root / "acme" / "episodes" / view.episode_id
        with Episode.open(ep) as episode:
            exits = cli.start_family(episode, ["b", "c"], spawn=spawn, tenant_id="acme")
    assert ep.parent == root / "acme" / "episodes", ep
    assert exits == {"b": 0, "c": 0}
    assert len(spawn.launches) == 2
    for launch in spawn.launches:
        argv = launch["argv"]
        assert launch["tenant_at_spawn"] == "acme", launch
        assert launch["episode"] == ep.resolve(), launch
        label = _arg(argv, "--world")
        assert isinstance(launch["roster_at_spawn"], dict), launch
        assert launch["roster_at_spawn"].get(label) == str(roster[label]), launch
        assert _child_data_root(launch).resolve() == root.resolve()
    assert sorted(p.name for p in root.rglob("_tenant.json")) == [], (
        "a `_tenant.json` was written (#1187 R1 retires it)")


@pytest.mark.parametrize("tenant_id", [None, "Not A Tenant"])
def test_start_family_refuses_an_episode_with_no_tenant_and_starts_nothing(tmp_path, tenant_id):
    """A family with no tenant, or an id no tenant can have, gets no fallback — there is no
    default tenant (#1078). Nothing is spawned and nothing is written into the episode (no
    `runs/`, no roster — a written one would be the fallback, just written down).
    #1187 declared change 6
    """
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
    assert not (ep / "runs").exists(), "the refused family made the arm container"
    assert not (ep / P.ROSTER_NAME).exists(), "the refused family wrote a roster"


# ---- end to end through the launcher ------------------------------------------------------------

_AS_STAMPED = object()


def _main(src: Path, *, stamp_tenant: str | None, roster: Any = None,
          questioner: Any = None) -> tuple[Any, SpawnRecorder]:
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
             "--continuation-prompt", "go"],
            spawn=spawn, questioner=O.questioner_for() if questioner is None else questioner,
            preflight=O.no_preflight,
            live_tree=P.source_capture(tenant_id=stamp_tenant), roster=roster,
            oracle=O.oracle(then=O.submit(_BASE, O.EMPTY_CLAIM)).model,
            verifier=O.passing_verifier().model)
    except (Exception, SystemExit) as refused:  # noqa: BLE001 — a refusal is an outcome here
        outcome = refused
    return outcome, spawn


def _launch(tmp_path: Path, *, stamp_tenant: str | None, location_tenant: Any = _AS_STAMPED,
            source: Path | None = None, questioner: Any = None) -> tuple[Any, SpawnRecorder]:
    """One episode through the real launcher, as `test_947_triplet_launcher` drives it, with
    the SOURCE run's stamp naming `stamp_tenant` and the source sitting at `location_tenant`'s
    runs folder `<root>/<T>/runs/<uuid>` (the same tenant unless a scenario says otherwise;
    `None` keeps the fixture's tenant) — the request names that location's tenant (#1187: the
    run's tenant is where it sits; no record). The launcher finds tenants under this test's
    data root (#1120). `source` is a source run dir the scenario already built (its tenant
    shaped by hand). Every scenario driving this one is refused before pre-flight reads
    anything."""
    location = stamp_tenant if location_tenant is _AS_STAMPED else location_tenant
    src = source if source is not None else P.runs_base(tmp_path, tenant_id=location)[1]
    P.source_stamp(src, tenant_id=stamp_tenant)
    return _main(src, stamp_tenant=stamp_tenant, questioner=questioner)


def _episodes_made() -> list[str]:
    """Every entry under any tenant's `<data root>/<T>/episodes/` (#1187: where every launch
    claims its episode) — the census a refusal leaves empty and an accepted launch does not."""
    return sorted(str(p) for p in current_data_root().glob("*/episodes/*"))


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
    """A source run under `tenant_id`, whose row and runs folder exist in the data root but
    whose knowledge folder does not — the tenant no operator set up knowledge for (before #1120:
    a row in the data root with no folder in the separate tenants root). Built FIRST, while the
    root is fresh (O10: `create_tenant` mints only into a fresh root); the episode's complete
    tenant is planted beside it afterwards, by hand."""
    import shutil

    _base, src = P.runs_base(tmp_path, tenant_id=tenant_id)
    shutil.rmtree(current_data_root() / tenant_id / "knowledge")
    return src


def test_a_launched_episodes_siblings_run_on_the_source_stamps_tenant(tmp_path):
    """The positive control the refusals below are measured against: the stamp agrees with the
    request, the siblings start on `acme` with the data root, each over a roster naming its
    label, and the launch's one episode sits under `<acme>/episodes/` (#1187)."""
    root = current_data_root()
    outcome, spawn, _est = _estate_launch(tmp_path)
    assert spawn.launches, f"no sibling was started: {outcome!r}"
    for launch in spawn.launches:
        assert launch["tenant_at_spawn"] == "acme", launch
        assert _child_data_root(launch).resolve() == root.resolve()
        assert isinstance(launch["roster_at_spawn"], dict), launch
        assert _arg(launch["argv"], "--world") in launch["roster_at_spawn"], launch
    made = _episodes_made()
    assert len(made) == 1, made
    assert Path(made[0]).parent == root / "acme" / "episodes", made


@pytest.mark.parametrize("stamp_tenant", [None, "default"])
def test_a_source_stamp_with_no_usable_tenant_refuses_the_episode_before_any_sibling(
        tmp_path, capsys, stamp_tenant):
    """The negative on the same launch: only the source stamp's tenant differs from the
    positive above, and no sibling starts and no episode is made under any tenant's
    `<T>/episodes/` (the positive above leaves one there). The refusal names the stamp.
    (`default` is a row in the data root with no knowledge folder, as it was before #1120.)
    #1187 declared change 1: the fixture source's id is a uuid, so the refusal is the stamp's,
    never the id rule's (whose text also says "tenant").
    """
    src = None if stamp_tenant is None else _knowledgeless_source(tmp_path, stamp_tenant)
    _episode_tenant(current_data_root())
    outcome, spawn = _launch(tmp_path, stamp_tenant=stamp_tenant, source=src)
    err = capsys.readouterr().err
    said = f"{outcome!r} {err}"
    assert "unrecognized arguments" not in err, f"the launcher never read the stamp: {err}"
    assert "invalid run id" not in said.lower(), f"refused by the id rule, not the stamp: {said}"
    assert spawn.launches == [], spawn.launches
    assert "tenant" in said.lower(), (outcome, err)
    assert _episodes_made() == [], _episodes_made()


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
    made = _episodes_made()
    assert len(made) == 1, f"expected the launch's one episode under <T>/episodes: {made}"
    manifest = Path(made[0]) / "family.yaml"
    doc = T.mod("_yaml").safe_load(manifest.read_text(encoding="utf-8"))
    assert doc["served_systems"] == served, doc["served_systems"]
    assert {c["system"] for c in est.calls()} == {"idp", "edr"}, est.calls()


def test_a_source_stamp_disagreeing_with_its_runs_base_record_refuses_before_any_sibling(
        tmp_path, capsys):
    """The stamp is in the box's writable run dir; a model can rewrite its `tenant_id` (or a
    run folder can be copied by hand from another tenant's tree, N14). Both tenants exist, the
    source sits in `acme`'s runs folder and is requested as `acme`'s, the stamp says `bravo`:
    refused, naming both, before anything is spent — no sibling starts, the questioner is never
    asked, and no episode is made under any tenant's `<T>/episodes/`. Never a family staged into
    bravo's estate. The control is `test_a_launched_episodes_siblings_run_on_the_source_stamps_
    tenant` (the two agree; one episode made, siblings started).
    #1187 declared change 6: the launcher's stamp compare (`_source_stamp_agrees`) is KEPT as
    an advisory check (N14, R2-27), its message no longer naming the retired `_tenant.json`; no
    container record is planted or read. (Name kept: the spec graph's.)
    """
    from defender.tests.tenant_1105_run_repository._spec1105_pr2 import CountingQuestioner

    root = current_data_root()
    _episode_tenant(root)
    T.place_tenant(root, "bravo", configs=S.config_texts(
        "bravo", events_index=P.EVENTS_PATTERN, alerts_index=P.ALERTS_PATTERN))
    asked = CountingQuestioner(O.questioner_for())
    outcome, spawn = _launch(tmp_path, stamp_tenant="bravo", location_tenant="acme",
                             questioner=asked)
    text = f"{outcome} {capsys.readouterr().err}"
    assert spawn.launches == [], spawn.launches
    assert "'bravo'" in text, text
    assert "'acme'" in text, text
    assert asked.calls == 0, "the questioner was paid for before the stamp was compared"
    assert _episodes_made() == [], _episodes_made()
    assert sorted(p.name for p in root.rglob("_tenant.json")) == [], (
        "a `_tenant.json` was written (#1187 R1 retires it)")


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
            ["--tenant", "acme", src.name, str(P.BRANCH_MESSAGE_ID),
             "--continuation-prompt", "go"],
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
    # #1187: no episode made under any tenant (the accepted launch's control leaves one).
    assert _episodes_made() == [], _episodes_made()


# ---- O3 on the resume path: a sibling serves through its OWN run's grant ------------------------

_ELASTIC_FOR_GATHER = """\
  elastic:
    health-check: {roles: [gather]}
    query: {roles: [gather]}
"""


def test_a_resumed_siblings_world_registry_holds_its_runs_gather_grant(tmp_path):
    """`run.py --episode` builds a `WorldRegistry` rather than the production registry, and it
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
        # The MODEL-FACING pointer names this tenant's table, never the host path to it.
        assert repr(tenant_id) in str(registry.grant_home), (tenant_id, registry.grant_home)
        assert str(grants.path) not in str(registry.grant_home), registry.grant_home
