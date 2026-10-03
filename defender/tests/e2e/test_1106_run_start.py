"""#1106 — a run starts on its own tenant or not at all, and the refusal comes BEFORE the box
(O4, C9, D4, M5), end to end through `run.py`'s real `main`.

`run.py` is the entry point that resolves the data root (`$DEFENDER_DATA_ROOT`, #1120: the one
place tenants are found, with no default) and hands it down (D2). The run's tenant is the one
its request names (`--tenant`, #1078 — there is no default). Before `start_box` the run accepts
the tenant (`accept_tenant(root, tenant)`, its knowledge folder at `<root>/<T>/knowledge/`),
loads the table and lead-zero, runs the lead-zero agreement check and checks gather's grant is
not empty (M5) — every refusal naming the path an operator must fix.

Each scenario drives the REAL `main` with the REAL lifecycle (`_run_investigation_lifecycle`)
composed over its existing seams: a recording `start_box` (so "never reached" is an
observation), and — on the path that does reach it — the REAL `_drive_investigation` over a
recording registry class and a recording driver, so what the run hands its box, its verb
registry, its driver and its ticket writer is captured as the INBOUND payload each fake
received. No new seam is added to `main`; nothing is monkeypatched but the data-root env var
`main` already reads.

The positive half is O1/O2/O3 at the run level: ONE process runs tenant A then tenant B, and
each run's box gets its own `agent/` half and no settings path, each run's registry holds
exactly its own table's gather pairs, and each run's driver and ticket writer are handed its
own settings folder and nobody else's.
"""
from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _tenants1106 as T

pytestmark = pytest.mark.e2e


class _StartBoxReached(Exception):
    """Raised by the recording `start_box` when a scenario must stop at the box."""


class StartBoxRecorder:
    """The lifecycle's `start_box` seam: records every call's (args, kwargs). With `stop`, it
    raises once called, so a refusal scenario that wrongly reaches the box fails loudly here
    rather than running an investigation; without it, it hands back the unboxed executor."""

    def __init__(self, *, stop: bool) -> None:
        self.stop = stop
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        if self.stop:
            raise _StartBoxReached(repr((args, kwargs)))
        from defender.runtime import box as box_mod

        return box_mod.unboxed_executor()


class TicketWriterRecorder:
    """`main`'s `ticket_writer` seam (a module-shaped object): records what each leg is handed —
    the run's record, the code tree and the run's env (#1107) with the rest of its arguments."""

    def __init__(self) -> None:
        self.opened: list[tuple[tuple, dict]] = []
        self.recorded: list[tuple[tuple, dict]] = []
        self.tenants: list[Any] = []

    def open_case_ticket(self, *args: Any, tenant: Any, defender_dir: Any, env: Any,
                         **kwargs: Any) -> None:
        self.tenants.append(tenant)
        self.opened.append((args, {"tenant": tenant, "defender_dir": defender_dir,
                                   "env": env, **kwargs}))

    def record_case_ticket(self, *args: Any, tenant: Any, defender_dir: Any, env: Any,
                           **kwargs: Any) -> None:
        self.tenants.append(tenant)
        self.recorded.append((args, {"tenant": tenant, "defender_dir": defender_dir,
                                     "env": env, **kwargs}))


@pytest.fixture
def world(tmp_path, monkeypatch):
    """An alert, a data root outside the checkout (`DEFENDER_DATA_ROOT`, where each scenario
    plants its tenants' knowledge folders and rows), and a `runs_base(tenant_id)` factory that
    chooses the run's tenant, gives it a row if the scenario planted none, and returns its runs
    base; the tenant then rides on every argv below as `--tenant` (#1078)."""
    alert_dir = tmp_path / "alerts" / "a-1106"
    alert_dir.mkdir(parents=True)
    alert = alert_dir / "alert.json"
    alert.write_text(json.dumps({
        "rule": {"id": "r-1106", "description": "fixture"}, "timestamp": "2026-09-26T00:00:00Z",
    }), encoding="utf-8")
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learning-state"))
    chosen: dict[str, str] = {}

    def runs_base(tenant_id: str) -> Path:
        tenant = T.mod("_tenant")
        layout = tenant._TenantPaths(root, tenant_id)
        if not layout.row.exists():
            # The row alone (no knowledge folder): a tenant set up in name only.
            layout.dir.mkdir(parents=True, exist_ok=True)
            layout.row.write_text(json.dumps(
                {"tenant_id": tenant_id, "created_at": "2026-09-28T00:00:00+00:00"}) + "\n",
                encoding="utf-8")
        chosen["tenant"] = tenant_id
        return layout.runs

    return {"alert": alert, "root": root, "runs_base": runs_base, "chosen": chosen}


def _run():
    return T.mod("run")


def _lifecycle(start_box: StartBoxRecorder, *, investigate: Any = None) -> Any:
    run = _run()
    if investigate is None:
        def investigate(**_kw: Any) -> dict:
            raise AssertionError("the investigation ran on a refused tenant")
    return functools.partial(
        run._run_investigation_lifecycle, investigate=investigate, start_box=start_box,
        stop_box=lambda *a, **k: None, scrub=lambda tree: None)


def _names(text: str, path: Path) -> bool:
    return str(path) in text or str(Path(path).resolve()) in text


def _refusal(world: dict, capsys, *extra: str) -> tuple[str, StartBoxRecorder]:
    """Drive `main` for the current runs base and return (refusal text, the recorder).

    A refusal may be a `SystemExit` carrying the message (the entry point's existing
    operator-refusal idiom), a raised exception, or a non-zero return with the message on
    stderr — the exit mechanism is not what is pinned; the TIMING (never reaching `start_box`)
    and the NAMED PATH are."""
    start = StartBoxRecorder(stop=True)
    argv = [str(world["alert"]), "--tenant", world["chosen"]["tenant"], "--no-learn", *extra]
    text = ""
    try:
        rc = _run().main(argv, lifecycle=_lifecycle(start), visualize=lambda p, **kw: None,
                         preflight=lambda m: 0)
    except _StartBoxReached:
        pytest.fail(f"start_box was reached for a tenant that must be refused: {start.calls}")
    except SystemExit as e:
        text = f"SystemExit({e.code!r})"
    except Exception as e:  # noqa: BLE001 — any raised refusal; its text is what is asserted
        text = f"{type(e).__name__}: {e}"
    else:
        assert rc != 0, "main returned 0 for a tenant it must refuse"
    captured = capsys.readouterr()
    text = "\n".join((text, captured.err, captured.out))
    assert "unrecognized arguments" not in text, (
        f"run.py rejected its argv, so nothing was checked:\n{text}")
    assert start.calls == [], start.calls
    return text, start


# =============================================================================================
# O4 / C9 / D4 — each refusal lands before the box, naming the path.
# =============================================================================================

def test_a_run_for_a_tenant_with_no_folder_refuses_before_the_box_naming_it(world, capsys):
    T.place_tenant(world["root"], "acme")
    world["runs_base"]("ghost")
    text, _ = _refusal(world, capsys)
    assert _names(text, world["root"] / "ghost"), text


def test_a_tenant_missing_its_mapping_refuses_and_leaves_no_runs_base_record(world, capsys):
    """O4's second named case: the injected root's `playground` lacks `mapping.yaml`, and a run
    for it refuses naming that file — rather than reaching the ticket screen's quiet "serve no
    comments". And refused, it leaves NO runs-base record: a base gets its tenant record only
    when a run dir is actually built there (the run-dir builder creates it), never from a run
    that stopped."""
    T.place_tenant(world["root"], T.PLAYGROUND_ID,
                   omit=("systems/case-history/mapping.yaml",))
    base = world["runs_base"](T.PLAYGROUND_ID)
    text, _ = _refusal(world, capsys)
    assert _names(
        text, world["root"] / T.PLAYGROUND_ID / "knowledge" / "settings" / "systems"
        / "case-history" / "mapping.yaml"), text
    assert not T.mod("_tenant").record_path(base).exists(), "a refused run minted a record"


@pytest.mark.parametrize("missing", ["verb-grants.yaml", "lead-zero.yaml"])
def test_a_tenant_missing_another_required_file_refuses_before_the_box(world, capsys, missing):
    T.place_tenant(world["root"], "acme", omit=(missing,))
    world["runs_base"]("acme")
    text, _ = _refusal(world, capsys)
    assert _names(text, world["root"] / "acme" / "knowledge" / "settings" / missing), text


def test_a_tenant_copied_from_the_template_refuses_at_start_naming_its_table(world, capsys):
    """C9: a grant-nothing table loads clean, and gather's own `GrantError` would fire only at
    `bind`, mid-run, after the box started and MAIN spent model calls. M5 moves it to start:
    refused before the box, naming the table the operator must grant gather a verb in."""
    T.place_tenant(world["root"], "newco", table=T.TABLE_BLANK)
    world["runs_base"]("newco")
    text, _ = _refusal(world, capsys)
    assert _names(text, world["root"] / "newco" / "knowledge" / "settings" / "verb-grants.yaml"), text


#: Gather is granted `health-check` and nothing else: the table loads, gather's grant is
#: NON-EMPTY, and binding it succeeds — yet no `query` can ever be granted.
TABLE_HEALTH_CHECK_ONLY = """\
dispositions:
  cmdb:
    get-host: {roles: [], reason: "not yet granted in this fixture"}
    health-check: {roles: [gather]}
"""


def test_a_tenant_whose_gather_grant_is_health_checks_alone_refuses_at_start(world, capsys):
    """The template refusal's sibling: a table granting gather only `health-check` is not an
    empty grant, so a check on `entries` alone passes it — and the run then spends model calls
    to have every query DENIED. A health check reaches no data; refused before the box, naming
    the table. The control is the positive-control test below (a table granting a query)."""
    T.place_tenant(world["root"], "probe", table=TABLE_HEALTH_CHECK_ONLY)
    grants = T.run_grants(world["root"] / "probe" / "knowledge" / "settings")
    assert {(s, v) for s, v, _ in grants.gather.entries} == {("cmdb", "health-check")}, \
        "the fixture must grant gather a health check and nothing else"
    world["runs_base"]("probe")
    text, _ = _refusal(world, capsys)
    assert _names(text, world["root"] / "probe" / "knowledge" / "settings" / "verb-grants.yaml"), text
    assert "query" in text, text


def test_a_lead_zero_template_the_catalog_lacks_refuses_before_the_box(world, capsys):
    """M5 runs the lead-zero agreement check at start: a tenant whose table grants the lead
    while its config names a template the catalog does not hold is refused before the box —
    today that surfaces inside `run_investigation`, after the box is up."""
    T.place_tenant(world["root"], "drift", lead_zero=T.lead_zero_text("elastic.no-such-template"))
    world["runs_base"]("drift")
    text, _ = _refusal(world, capsys)
    assert "elastic.no-such-template" in text, text


#: A table whose correlation lead holds `elastic.query` — a legal narrowing (one system, one
#: query verb, a pair gather holds) that DISAGREES with the shipped template, which binds
#: `elastic.alerts`.
TABLE_LEAD_ON_QUERY = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
  elastic:
    alerts: {roles: [gather]}
    health-check: {roles: [gather, lead-zero-correlation]}
    query: {roles: [gather, lead-zero-correlation]}
"""


def test_a_lead_zero_template_on_another_pair_than_the_table_grants_refuses_before_the_box(
        world, capsys):
    """M5's agreement half, not only its existence half: the configured template EXISTS and is
    established, but it binds `elastic.alerts` while the table grants the lead `elastic.query`.
    An existence-only check passes this; the run must refuse before the box, naming both
    sides. The control is `test_the_positive_control_reaches_the_box_…` — the same template
    with a table granting the lead the pair it binds."""
    T.place_tenant(world["root"], "drift", table=TABLE_LEAD_ON_QUERY)
    grants = T.run_grants(world["root"] / "drift" / "knowledge" / "settings")
    assert {(s, v) for s, v, _ in grants.correlation.entries} == {
        ("elastic", "health-check"), ("elastic", "query")}, "the fixture's lead pair moved"
    world["runs_base"]("drift")
    text, _ = _refusal(world, capsys)
    assert T.SHIPPED_CORRELATION_TEMPLATE in text, text
    assert "elastic.query" in text, text


def test_the_positive_control_reaches_the_box_with_the_tenants_agent_half(world, capsys):
    """The complementary condition for every refusal above: the same root, a complete tenant,
    and `start_box` IS called — with the run's resolved `agent/` half (M6), and with no
    settings path and no other tenant among its arguments (O1)."""
    T.place_tenant(world["root"], "acme")
    T.place_tenant(world["root"], "bravo", table=T.TABLE_B)
    world["runs_base"]("acme")
    start = StartBoxRecorder(stop=True)
    with pytest.raises(_StartBoxReached):
        _run().main(
            [str(world["alert"]), "--tenant", "acme", "--no-learn"],
            lifecycle=_lifecycle(start), visualize=lambda p, **kw: None, preflight=lambda m: 0)
    assert len(start.calls) == 1, start.calls
    _args, kwargs = start.calls[0]
    acme, bravo = world["root"] / "acme" / "knowledge", world["root"] / "bravo"
    assert Path(kwargs["tenant_agent"]) == (acme / "agent").resolve()
    assert not T.reaches(start.calls, acme / "settings")
    assert not T.reaches(start.calls, bravo)
    # Nor anything that CONTAINS a settings folder or the other tenant (a tenant folder or the
    # root handed over as a tree): `exposes` also counts an ancestor of the forbidden path.
    for forbidden in (acme / "settings", bravo / "knowledge" / "settings", bravo):
        assert not T.exposes(start.calls, forbidden), (forbidden, start.calls)


# =============================================================================================
# O1 / O2 / O3 — one process, tenant A then tenant B: each run carries only its own tenant.
# =============================================================================================

class _RegistryRecorder:
    """`_drive_investigation`'s `registry_cls` seam: records what the run built its verb
    registry from."""

    built: list[tuple[tuple, dict]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        type(self).built.append((args, kwargs))


def _grant_of(call: tuple[tuple, dict]) -> Any:
    from defender.runtime.verb_grant import VerbGrant

    args, kwargs = call
    grants = [v for v in (*args, *kwargs.values()) if isinstance(v, VerbGrant)]
    assert len(grants) == 1, call
    return grants[0]


def test_one_process_runs_tenant_a_then_b_and_each_run_carries_only_its_own_tenant(world, capsys):
    root = world["root"]
    T.place_tenant(root, "acme", table=T.TABLE_A, marker="acme")
    T.place_tenant(root, "bravo", table=T.TABLE_B, marker="bravo")
    expected = {"acme": T.GATHER_PAIRS_A, "bravo": T.GATHER_PAIRS_B}
    run = _run()

    for tenant_id, other in (("acme", "bravo"), ("bravo", "acme")):
        world["runs_base"](tenant_id)
        _RegistryRecorder.built = []
        driven: list[dict] = []
        start = StartBoxRecorder(stop=False)
        writer = TicketWriterRecorder()
        investigate = functools.partial(
            run._drive_investigation, registry_cls=_RegistryRecorder,
            investigate=lambda driven=driven, **kw: (
                driven.append(kw) or {"output": "done", "requests": 0}))
        rc = run.main(
            [str(world["alert"]), "--tenant", tenant_id, "--no-learn", "--update-ticket"],
            lifecycle=_lifecycle(start, investigate=investigate), visualize=lambda p, **kw: None,
            preflight=lambda m: 0, ticket_writer=writer)
        assert rc == 0, capsys.readouterr().err
        own_settings = root / tenant_id / "knowledge" / "settings"

        # O1 — the box: this tenant's agent half, no settings path, nothing of the other tenant.
        assert len(start.calls) == 1, start.calls
        assert Path(start.calls[0][1]["tenant_agent"]) == \
            (root / tenant_id / "knowledge" / "agent").resolve()
        assert not T.reaches(start.calls, own_settings)
        assert not T.reaches(start.calls, root / other)
        assert not T.exposes(start.calls, own_settings), start.calls
        assert not T.exposes(start.calls, root / other), start.calls

        # O3 — the registry: exactly this tenant's gather pairs.
        assert len(_RegistryRecorder.built) == 1, _RegistryRecorder.built
        grant = _grant_of(_RegistryRecorder.built[0])
        assert {(s, v) for s, v, _ in grant.entries} == set(expected[tenant_id]), tenant_id

        # O2 — the driver and the ticket writer are handed this tenant's settings folder, and
        # neither the other tenant's nor the checkout's committed copy.
        assert len(driven) == 1
        for seam, payload in (("driver", driven[0]), ("ticket open", writer.opened),
                              ("ticket record", writer.recorded)):
            assert payload, seam
            assert T.reaches(payload, own_settings), f"{seam} was not handed {own_settings}"
            assert not T.reaches(payload, root / other), f"{seam} was handed {other}'s folder"
            assert not T.reaches(payload, T.FIXTURE_SETTINGS), f"{seam} got the checkout's"

