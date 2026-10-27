"""#1106 e2e through run.py's real main: a run for a tenant that is missing, incomplete or inconsistent refuses before the box naming the path to fix; one process running tenant A then B hands each run only its own tenant's agent half, grant and settings."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import contextlib
import functools
import json
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.tenancy import _tenants1106 as T

pytestmark = pytest.mark.e2e


class _StartBoxReached(Exception):
    """Raised by the recording `start_box` when a scenario must stop at the box."""


class StartBoxRecorder:
    """The lifecycle's `start_box` seam:"""

    def __init__(self, *, stop: bool) -> None:
        self.stop = stop
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        if self.stop:
            raise _StartBoxReached(repr((args, kwargs)))
        from defender import box as box_mod

        return box_mod.unboxed_executor()


class TicketWriterRecorder:
    """`main`'s `ticket_writer` seam (a module-shaped object):"""

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
    """An alert, a data root outside the checkout (`DEFENDER_DATA_ROOT`, where each scenario plants its tenants'..."""
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
        tenant = T.mod("tenancy._tenant")
        layout = tenant._TenantPaths(fixture_data_root(root), tenant_id)
        if not layout.row.exists():
            # The row alone (no knowledge folder): a tenant set up in name only.
            layout.tenant_root.mkdir(parents=True, exist_ok=True)
            layout.row.write_text(json.dumps(
                {"tenant_id": tenant_id, "created_at": "2026-09-28T00:00:00+00:00"}) + "\n",
                encoding="utf-8")
        chosen["tenant"] = tenant_id
        return location_path(layout.runs)

    published: dict[str, Any] = {}

    def publish_tenant(tenant_id: str, files: dict[str, str | None]) -> Any:
        """#1108 P4: the tenant set up and published for real (S0's one helper) with `files`
        (repo-relative, `None` deletes) over the committed fixture, so the run has an export
        and its own refusal is the one that fires (not "no `current`")."""
        from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

        published[tenant_id] = stack.enter_context(published_tenant(
            tmp_path / "forge", root=root, tenant_id=tenant_id, files=files,
            repo_name=f"t{len(published)}"))
        chosen["tenant"] = tenant_id
        return published[tenant_id]

    with contextlib.ExitStack() as stack:
        yield {"alert": alert, "root": root, "runs_base": runs_base, "chosen": chosen,
               "publish_tenant": publish_tenant, "published": published}


def _run():
    return T.mod("run")


def _lifecycle(start_box: StartBoxRecorder, *, investigate: Any = None) -> Any:
    run = _run()
    if investigate is None:
        def investigate(**_kw: Any) -> dict:
            raise AssertionError("the investigation ran on a refused tenant")
    return functools.partial(
        run._run_investigation_lifecycle, investigate=investigate, start_box=start_box,
        stop_box=lambda *a, **k: None, scrub=lambda tree, **kw: None)


def _names(text: str, path: Path) -> bool:
    return str(path) in text or str(Path(path).resolve()) in text


def _refusal(world: dict, capsys, *extra: str) -> tuple[str, StartBoxRecorder]:
    """Drive `main` for the current runs base and return (refusal text, the recorder)."""
    start = StartBoxRecorder(stop=True)
    argv = [str(world["alert"]), "--tenant", world["chosen"]["tenant"], "--no-learn", *extra]
    text = ""
    try:
        own = world["published"].get(world["chosen"]["tenant"])
        # #1108 P4: a published tenant's launch reports its export fresh (O11 `publish=`); a
        # tenant refused at acceptance never reaches the publish.
        seams = ({} if own is None
                 else {"publish": lambda *a, own=own, **k: f"fresh {own.commit}"})
        rc = _run().main(argv, lifecycle=_lifecycle(start), visualize=lambda p, **kw: None,
                         preflight=lambda m: 0, **seams)
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


def test_a_run_for_a_tenant_with_no_folder_refuses_before_the_box_naming_it(world, capsys):
    T.place_tenant(world["root"], fixture_uuid("tenant:acme"))
    world["runs_base"](fixture_uuid("tenant:ghost"))
    text, _ = _refusal(world, capsys)
    assert _names(text, world["root"] / fixture_uuid("tenant:ghost")), text


#: #1108 P4: the file an operator edits is the tenant repo's `settings/...` (the run reads its
#: copy of an export of it), so a refusal names it repo-relative; the clone, export or copy
#: spelling of the same path all contain it.
def _settings_named(text: str, rel: str) -> bool:
    return f"settings/{rel}" in text


def _published_without(world: dict, tenant_id: str, rel: str) -> Any:
    """A published tenant whose `current` export lacks `settings/<rel>`: published whole (its
    setup accepts only a complete tenant), then a merged commit deleting the file, published —
    the state an operator reaches by merging the deletion."""
    t = world["publish_tenant"](tenant_id, {})
    t.merge({f"settings/{rel}": None}, message=f"delete settings/{rel}")
    t.publish()
    return t


def test_a_tenant_missing_its_mapping_refuses_and_leaves_no_runs_base(world, capsys):
    """O4's second named case (#1108 P4: over a published tenant, so "no `current`" cannot
    mask it):"""
    _published_without(world, T.PLAYGROUND_ID, "systems/case-history/mapping.yaml")
    base = world["runs_base"](T.PLAYGROUND_ID)
    text, _ = _refusal(world, capsys)
    assert _settings_named(text, "systems/case-history/mapping.yaml"), text
    assert not base.exists(), "a refused run created its runs base"


@pytest.mark.parametrize("missing", ["verb-grants.yaml", "lead-zero.yaml"])
def test_a_tenant_missing_another_required_file_refuses_before_the_box(world, capsys, missing):
    _published_without(world, fixture_uuid("tenant:acme"), missing)
    text, _ = _refusal(world, capsys)
    assert _settings_named(text, missing), text


def test_a_tenant_copied_from_the_template_refuses_at_start_naming_its_table(world, capsys):
    """C9:"""
    world["publish_tenant"](fixture_uuid("tenant:newco"),
                            {"settings/verb-grants.yaml": T.TABLE_BLANK})
    text, _ = _refusal(world, capsys)
    assert _settings_named(text, "verb-grants.yaml"), text


#: Gather is granted `health-check` and nothing else: the table loads, gather's grant is
#: NON-EMPTY, and binding it succeeds — yet no `query` can ever be granted.
TABLE_HEALTH_CHECK_ONLY = """\
dispositions:
  cmdb:
    get-host: {roles: [], reason: "not yet granted in this fixture"}
    health-check: {roles: [gather]}
"""


def test_a_tenant_whose_gather_grant_is_health_checks_alone_refuses_at_start(world, capsys):
    """The template refusal's sibling:"""
    from defender.tests.tenancy.tenant_1108_p4._support import export_dir

    t = world["publish_tenant"](fixture_uuid("tenant:probe"),
                                {"settings/verb-grants.yaml": TABLE_HEALTH_CHECK_ONLY})
    grants = T.run_grants(export_dir(t.tenant, t.commit) / "settings")
    assert {(s, v) for s, v, _ in grants.gather.entries} == {("cmdb", "health-check")}, \
        "the fixture must grant gather a health check and nothing else"
    text, _ = _refusal(world, capsys)
    assert _settings_named(text, "verb-grants.yaml"), text
    assert "query" in text, text


def test_a_lead_zero_template_the_catalog_lacks_refuses_before_the_box(world, capsys):
    """M5 runs the lead-zero agreement check at start:"""
    world["publish_tenant"](fixture_uuid("tenant:drift"),
                            {"settings/lead-zero.yaml": T.lead_zero_text("elastic.no-such-template")})
    text, _ = _refusal(world, capsys)
    assert "elastic.no-such-template" in text, text


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
    """M5's agreement half, not only its existence half:"""
    from defender.tests.tenancy.tenant_1108_p4._support import export_dir

    t = world["publish_tenant"](fixture_uuid("tenant:drift"),
                                {"settings/verb-grants.yaml": TABLE_LEAD_ON_QUERY})
    grants = T.run_grants(export_dir(t.tenant, t.commit) / "settings")
    assert {(s, v) for s, v, _ in grants.correlation.entries} == {
        ("elastic", "health-check"), ("elastic", "query")}, "the fixture's lead pair moved"
    text, _ = _refusal(world, capsys)
    assert T.SHIPPED_CORRELATION_TEMPLATE in text, text
    assert "elastic.query" in text, text


class _RegistryRecorder:
    """`_drive_investigation`'s `registry_cls` seam:"""

    built: list[tuple[tuple, dict]] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        type(self).built.append((args, kwargs))


def _grant_of(call: tuple[tuple, dict]) -> Any:
    from defender.systems.verb_grant import VerbGrant

    args, kwargs = call
    grants = [v for v in (*args, *kwargs.values()) if isinstance(v, VerbGrant)]
    assert len(grants) == 1, call
    return grants[0]


def test_one_process_runs_tenant_a_then_b_and_each_run_carries_only_its_own_tenant(world, capsys):
    """Rewritten for #1108 P4 (O-A/O-B/O2): each tenant is published for real (S0's helper) and
    every run reads its own RUN COPY (`<T>/run-knowledge/<run_id>/`) — the box is handed that
    copy's `agent/`, the driver and ticket writer that copy's `settings/` — never the tenant's
    clone, the other tenant, or the checkout's committed copy. (P2/#1106 pinned the clone's
    `agent/` as the box's `tenant_agent`, the retired `agent` mount.)"""
    import contextlib

    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
    from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

    root = world["root"]
    scratch = root.parent / "forge-1106"
    expected = {fixture_uuid("tenant:acme"): T.GATHER_PAIRS_A, fixture_uuid("tenant:bravo"): T.GATHER_PAIRS_B}
    run = _run()
    with contextlib.ExitStack() as stack:
        published = {
            tenant_id: stack.enter_context(published_tenant(
                scratch, root=root, tenant_id=tenant_id, repo_name=name,
                files={"settings/verb-grants.yaml": table}))
            for tenant_id, table, name in ((fixture_uuid("tenant:acme"), T.TABLE_A, "acme"),
                                           (fixture_uuid("tenant:bravo"), T.TABLE_B, "bravo"))}
        for tenant_id, other in ((fixture_uuid("tenant:acme"), fixture_uuid("tenant:bravo")),
                                 (fixture_uuid("tenant:bravo"), fixture_uuid("tenant:acme"))):
            own = published[tenant_id]
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
                preflight=lambda m: 0, ticket_writer=writer,
                publish=lambda *a, own=own, **k: B.fresh(own.commit))
            assert rc == 0, capsys.readouterr().err
            assert len(driven) == 1
            copy_root = B.run_copies(own) / Path(driven[0]["run"].run_dir).name
            own_settings = copy_root / "settings"

            # O1/O-A/U9 — the box: this tenant's run copy's stage/agent, no settings, no clone, nothing
            # of the other tenant.
            assert len(start.calls) == 1, start.calls
            assert T.reaches(start.calls, copy_root / "stage" / "agent"), start.calls
            assert not T.exposes(start.calls, own_settings), start.calls
            assert not T.exposes(start.calls, B.clone_dir(own)), start.calls
            assert not T.reaches(start.calls, root / other)
            assert not T.exposes(start.calls, root / other), start.calls

            # O3 — the registry: exactly this tenant's gather pairs.
            assert len(_RegistryRecorder.built) == 1, _RegistryRecorder.built
            grant = _grant_of(_RegistryRecorder.built[0])
            assert {(s, v) for s, v, _ in grant.entries} == set(expected[tenant_id]), tenant_id

            # O2/O-B — the driver and the ticket writer are handed this run copy's settings, and
            # neither the clone's, the other tenant's, nor the checkout's committed copy.
            for seam, payload in (("driver", driven[0]), ("ticket open", writer.opened),
                                  ("ticket record", writer.recorded)):
                assert payload, seam
                assert T.reaches(payload, own_settings), f"{seam} was not handed {own_settings}"
                assert not T.reaches(payload, B.clone_dir(own) / "settings"), f"{seam} got the clone's"
                assert not T.reaches(payload, root / other), f"{seam} was handed {other}'s folder"
                assert not T.reaches(payload, T.FIXTURE_SETTINGS), f"{seam} got the checkout's"
