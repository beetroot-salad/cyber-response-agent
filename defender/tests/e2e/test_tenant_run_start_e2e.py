"""#1106 e2e through run.py's real main: a run for a tenant that is missing, incomplete or inconsistent refuses before the box naming the path to fix; one process running tenant A then B hands each run only its own tenant's agent half, grant and settings."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory

import contextlib
import dataclasses
import functools
import json
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.tenancy._fetch_standin_1618 import halves_at, in_process_fetch

pytestmark = pytest.mark.e2e


class _StartBoxReached(Exception):
    """Raised by the recording `start_box` when a scenario must stop at the box."""


class StartBoxRecorder:
    """The lifecycle's `start_box` seam: records each call, then stops or returns the unboxed executor."""

    def __init__(self, *, stop: bool) -> None:
        self.stop = stop
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        if self.stop:
            raise _StartBoxReached(repr((args, kwargs)))
        from defender import box as box_mod

        return box_mod.unboxed_executor()


@pytest.fixture
def world(tmp_path, monkeypatch):
    """An alert, a data root outside the checkout (`DEFENDER_DATA_ROOT`), and helpers that choose or
    publish the tenant a scenario runs as."""
    alert_dir = tmp_path / "alerts" / "a-1106"
    alert_dir.mkdir(parents=True)
    alert = alert_dir / "alert.json"
    alert.write_text(json.dumps({
        "rule": {"id": "r-1106", "description": "fixture"}, "timestamp": "2026-09-26T00:00:00Z",
    }), encoding="utf-8")
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    chosen: dict[str, str] = {}

    def runs_base(tenant_id: str) -> Path:
        tenant = T.mod("tenancy._tenant")
        layout = tenant._TenantPaths(fixture_data_root(root), tenant_id)
        if not layout.tenant_root.exists():
            # No knowledge folder: a tenant active in the directory in name only (O6: no row on disk).
            layout.tenant_root.mkdir(parents=True, exist_ok=True)
        chosen["tenant"] = tenant_id
        return location_path(layout.runs)

    published: dict[str, Any] = {}

    def publish_tenant(tenant_id: str, files: dict[str, str | None]) -> Any:
        """The tenant published for real with `files` (repo-relative, `None` deletes) over the
        committed fixture on its Forgejo `main`, so the run fetches a copy and its own refusal fires."""
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
        # Every launch fetches the tenant's Forgejo `main` through its one seam (#1618 flow 2): a published tenant's own
        # remote, else the data root's served remote, which holds only what the scenario placed (nothing, for a ghost).
        seams = {"fetch": in_process_fetch(own.remote if own is not None else None)}
        # #1214 Flow 4: the tenant is active in the directory whether or not its folder is placed.
        directory = (own.directory if own is not None
                     else tenant_directory(world["root"], world["chosen"]["tenant"]))
        rc = _run().main(argv, directory=directory, lifecycle=_lifecycle(start), visualize=lambda p, **kw: None,
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


def test_a_run_for_a_tenant_whose_forgejo_serves_no_knowledge_refuses_before_the_box_naming_it(world, capsys):
    """A tenant active in the directory whose Forgejo holds no knowledge (another tenant's is placed) refuses before the
    box, its refusal naming the tenant and that its knowledge could not be fetched. (#1618 K8: a tenant has no knowledge
    folder for acceptance to find missing, so the refusal is the fetch's; was `..._with_no_folder_...`, which named
    `<root>/<T>`.)"""
    T.place_tenant(world["root"], fixture_uuid("tenant:acme"))
    world["runs_base"](fixture_uuid("tenant:ghost"))
    text, _ = _refusal(world, capsys)
    assert f"tenant {fixture_uuid('tenant:ghost')}'s knowledge could not be fetched" in text, text
    assert "did not serve main" in text, text


#: An operator edits the tenant repo's `settings/...`, so a refusal names it repo-relative; the
#: run-copy spelling of the path contains it.
def _settings_named(text: str, rel: str) -> bool:
    return f"settings/{rel}" in text


def _published_without(world: dict, tenant_id: str, rel: str) -> Any:
    """A published tenant whose `main` lacks `settings/<rel>`: published whole (its
    setup accepts only a complete tenant), then a merged commit deleting the file, published —
    the state an operator reaches by merging the deletion (#1618: `main` is what a run fetches; nothing publishes)."""
    t = world["publish_tenant"](tenant_id, {})
    t.merge({f"settings/{rel}": None}, message=f"delete settings/{rel}")
    return t


def test_a_tenant_with_no_case_record_is_not_refused_and_reaches_the_box(world):
    """#1359 O2: the case record is optional (the retired `systems/case-history/mapping.yaml` was
    required): an imported tenant whose records hold no case record starts and reaches the box.
    #1366 O9: the case record is a database record now (the fixture's `case-record.yaml` file is
    gone), so the tenant is seeded with the fixture's systems and no case.
    Control: the sibling test below, where a missing required file refuses."""
    from defender.tests.support.tenancy import _systems1366 as R

    own = world["publish_tenant"](T.PLAYGROUND_ID, {})
    no_case = dataclasses.replace(R.fixture_records(), case=None)
    directory = own.directory_with(records=no_case)
    world["runs_base"](T.PLAYGROUND_ID)
    start = StartBoxRecorder(stop=True)
    argv = [str(world["alert"]), "--tenant", T.PLAYGROUND_ID, "--no-learn"]
    with pytest.raises(_StartBoxReached):
        _run().main(argv, directory=directory, lifecycle=_lifecycle(start),
                    visualize=lambda p, **kw: None, preflight=lambda m: 0,
                    fetch=in_process_fetch(own.remote))
    assert len(start.calls) == 1, start.calls


def test_a_tenant_missing_its_grant_table_refuses_before_the_box(world, capsys):
    """The table is the settings half's only file (#1503), so a commit without it has no
    `settings/` at all (git keeps no empty folder): the run's copy is refused before the box, naming the missing table
    (#1618 K8: the copy is held to `check_run_settings`; the "no settings/ half" wording was the retired clone's
    acceptance, now only `check_knowledge_folder`'s)."""
    _published_without(world, fixture_uuid("tenant:acme"), "verb-grants.yaml")
    text, _ = _refusal(world, capsys)
    assert "a required settings file is missing" in text, text
    assert _settings_named(text, "verb-grants.yaml"), text


def test_a_tenant_copied_from_the_template_refuses_at_start_naming_its_table(world, capsys):
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
    t = world["publish_tenant"](fixture_uuid("tenant:probe"),
                                {"settings/verb-grants.yaml": TABLE_HEALTH_CHECK_ONLY})
    grants = T.run_grants(halves_at(t.remote, t.commit, world["root"].parent / "probe-copy") / "settings")
    assert {(s, v) for s, v, _ in grants.gather.entries} == {("cmdb", "health-check")}, \
        "the fixture must grant gather a health check and nothing else"
    text, _ = _refusal(world, capsys)
    assert _settings_named(text, "verb-grants.yaml"), text
    assert "query" in text, text


class _RegistryRecorder:
    """`_drive_investigation`'s `registry_cls` seam, recording each construction's arguments."""

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
    """Each run reads its own RUN COPY (`<T>/run-knowledge/<run_id>/`): the box gets its `agent/`,
    the driver its `settings/`; never the seed checkout, the other tenant, or the
    checkout's committed copy."""
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
            investigate = functools.partial(
                run._drive_investigation, registry_cls=_RegistryRecorder,
                investigate=lambda driven=driven, **kw: (
                    driven.append(kw) or {"output": "done", "requests": 0}))
            argv = [str(world["alert"]), "--tenant", tenant_id, "--no-learn"]
            rc = run.main(
                argv, directory=own.directory,
                lifecycle=_lifecycle(start, investigate=investigate), visualize=lambda p, **kw: None,
                preflight=lambda m: 0,
                fetch=in_process_fetch(own.remote))
            assert rc == 0, capsys.readouterr().err
            assert len(driven) == 1
            copy_root = B.run_copies(own) / Path(driven[0]["run"].run_dir).name
            own_settings = copy_root / "settings"

            # The box: this run copy's stage/agent; no settings, no clone, nothing of the other tenant.
            assert len(start.calls) == 1, start.calls
            # `data_root` is the folder the box check is made under (#1469), beside the job sockets; it
            # is not bound into the box. So it is judged on its own (it must be the tenants' data root,
            # not a tenant's folder or a copy), and `exposes` (which reads an ancestor as exposure)
            # judges only what the call hands the box to mount.
            (_, start_kwargs), = start.calls
            assert Path(location_path(start_kwargs["data_root"])).resolve() == root.resolve(), start.calls
            handed = [(a, {k: v for k, v in kw.items() if k != "data_root"}) for a, kw in start.calls]
            assert T.reaches(handed, copy_root / "stage" / "agent"), start.calls
            assert not T.exposes(handed, own_settings), start.calls
            assert not T.exposes(handed, own.checkout), start.calls  # the tenant's other copy (#1618: no host clone)
            assert not T.reaches(start.calls, root / other)
            assert not T.exposes(handed, root / other), start.calls

            # The registry: exactly this tenant's gather pairs.
            assert len(_RegistryRecorder.built) == 1, _RegistryRecorder.built
            grant = _grant_of(_RegistryRecorder.built[0])
            assert {(s, v) for s, v, _ in grant.entries} == set(expected[tenant_id]), tenant_id

            # The driver: this run copy's settings, and no other. (An operator run has no ticket lane, W7.)
            for seam, payload in (("driver", driven[0]),):
                assert payload, seam
                assert T.reaches(payload, own_settings), f"{seam} was not handed {own_settings}"
                assert not T.reaches(payload, own.checkout / "settings"), f"{seam} got the seed checkout's"
                assert not T.reaches(payload, root / other), f"{seam} was handed {other}'s folder"
                assert not T.reaches(payload, T.FIXTURE_SETTINGS), f"{seam} got the checkout's"
