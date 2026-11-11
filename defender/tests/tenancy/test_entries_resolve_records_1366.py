"""#1366 R8 + R12 + O6 at EVERY entry that resolves a tenant to run: one contract, four entries.

The grants x records verdict is one rule (R12) with one refusal (R8), so it is stated once and every entry that turns a
tenant into something that runs is held to it. The entries:

- `fresh run`: `run.main` over a planted tenant (`_spec1222.run_alert`);
- `--episode sibling`: `run.main --episode ... --world ...` of a branched episode (`_sibling_of_records`' recipe);
- `branch launch`: the real launcher `cli.learning.branch.main` over the #1224 estate, with pre-flight's replay behind it
  (the launcher serves the episode's worlds and pre-flight reads captured calls through the tenant's narrowed grants);
- `defender-policy`: `policy_cli.main show gather`, which builds gather's definition from the tenant's grants.

Fixture, the same shape at each: the tenant is IMPORTED, its records are a strict subset of the catalog the entry reads,
and its grants name a system that has no enabled record (never recorded, or recorded and disabled). For each relation:

(a) a tenant not imported is refused naming the import (`tenant.py import`), before anything runs or is spent;
(b) what the entry serves is exactly the enabled records' systems (the roster of a run, the `served_systems` of an
    episode; `defender-policy` prints no system, so there (b) is its accept/refuse alone), and when every granted system
    lost its record the entry is refused under the empty-gather rule naming those grants, not the import;
(c) there is exactly one WARNING line per ignored grant, naming the system and a grant (the entry's own, not a
    caller's);
(d) where the entry is itself a run (a fresh run, a sibling) it writes its record of the system and case versions it read
    (`record-versions.json`, host-held), for every current version, the disabled one too. A branch launch and the policy
    CLI run nothing of their own: the launch's siblings are `--episode` runs, which this row holds.

A read rule that is kept at one entry and forgotten at another is the failure this test is for: each entry has to
resolve the tenant through the same verdict (`tenant_systems`, `require_imported`, `warn_ignored`).
(#1366 R8, R12, O6, H9, O1)
"""
from __future__ import annotations

import dataclasses
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender.records._layout import RunPaths
from defender.tests.learning.oracle.live_contracts import _spec1224 as O
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

#: The relations between a granted system and the tenant's records the entries are held to.
NOT_IMPORTED = "not-imported"
UNRECORDED = "unrecorded"
DISABLED = "disabled"
EMPTIED = "no-granted-system-recorded"
RELATIONS = (NOT_IMPORTED, UNRECORDED, DISABLED, EMPTIED)


@dataclasses.dataclass(frozen=True)
class Seen:
    """What one entry did with one relation.

    `refusal` is the text the entry was refused with (None: it ran). `served` is the set of systems it serves (None: the
    entry prints none); `enabled` the systems with an enabled record (what `served` must equal); `ignored` the granted
    systems with no enabled record. `versions` is the run's record of what it read (None: no run of its own at this entry).
    """

    refusal: str | None
    served: frozenset[str] | None
    enabled: frozenset[str]
    ignored: tuple[str, ...]
    versions: dict[str, Any] | None
    versions_expected: dict[str, Any] | None = None
    #: The branch launch only: why pre-flight could not replay the source run's captured call to each system, by system.
    not_replayable: dict[str, str] = dataclasses.field(default_factory=dict)


def _records_for(base: R.RecordsSpec, relation: str, *, granted: tuple[str, ...], lost: str) -> R.RecordsSpec | None:
    """`base` (every system the tenant records) as the relation says: `lost` has no record or a disabled one, every system
    the tenant's grants name has none, or the tenant is not imported (None)."""
    if relation == NOT_IMPORTED:
        return None
    if relation == UNRECORDED:
        return R.without(base, lost)
    if relation == DISABLED:
        return R.edited(base, lost, enabled=False)
    return R.without(base, *granted)


def _ignored(relation: str, granted: tuple[str, ...], lost: str) -> tuple[str, ...]:
    return {NOT_IMPORTED: (), UNRECORDED: (lost,), DISABLED: (lost,), EMPTIED: ()}[relation]


def _enabled(records: R.RecordsSpec | None) -> frozenset[str]:
    return frozenset() if records is None else frozenset(s for s, v in records.systems.items() if v.enabled)


def _versions_of(records: R.RecordsSpec | None) -> dict[str, Any] | None:
    if records is None:
        return None
    return {"systems": {s: v.version for s, v in records.systems.items()},
            "case": None if records.case is None else records.case.version}


def _read_versions(run_dir: Path | None) -> dict[str, Any] | None:
    path = None if run_dir is None else RunPaths(run_dir).record_versions
    return json.loads(path.read_text(encoding="utf-8")) if path is not None and path.is_file() else None


# --- the entries ---------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Env:
    tmp_path: Path
    data_root: Path
    monkeypatch: pytest.MonkeyPatch


def _fresh_run(env: Env, relation: str) -> Seen:
    planted = S.plant_tenant(fixture_uuid("tenant:acme"))
    granted = ("cmdb", "elastic")
    base = R.records_from_settings(planted.settings)
    records = _records_for(base, relation, granted=granted, lost="cmdb")
    directory = tenant_directory(planted.root, planted.tenant_id, alert_mapping=S.current_mapping(planted), records=records)

    ran = S.run_alert(env.tmp_path / "fresh", tenant=planted, main=S.closing_main_turns(), directory=directory)

    assert ran.raised is None, ran.raised
    served = (frozenset(ran.lifecycle_calls[0]["systems"].roster.systems) - {"tacit-knowledge"}
              if ran.lifecycle_calls else None)
    return Seen(ran.refusal, served, _enabled(records), _ignored(relation, granted, "cmdb"),
                _read_versions(ran.run_dir), _versions_of(records))


def _sibling(env: Env, relation: str) -> Seen:
    for name in S1107.BRANCH_CONFIG_VARS:
        env.monkeypatch.delenv(name, raising=False)
    env.monkeypatch.setenv("PATH", S1107.DockerShim(env.tmp_path / "docker").path_value())
    tenant = fixture_uuid("tenant:acme-t1107")
    _base, src = H.tenant_source(env.data_root, tenant, published=True)
    folder = S1107.plant(env.data_root, tenant, marker="g2")
    granted = ("cmdb", "elastic")
    base = R.records_from_settings(S1107.settings_of(folder))
    records = _records_for(base, relation, granted=granted, lost="cmdb")
    argv = H.sibling_argv(H.family_for(src), "b", "--tenant", tenant)
    rec = S1107.RunRecorder(env.tmp_path / "sibling-run")

    rc, refused = S1107.drive_run(argv, rec, visualize=rec.visualize, directory=directory_for_argv(argv, records=records))

    assert (rc, refused is None) in {(0, True), (None, False)}, (rc, refused)
    ran = rec.lifecycle_calls[0] if rec.lifecycle_calls else None
    served = frozenset(ran["systems"].roster.systems) - {"tacit-knowledge"} if ran else None
    return Seen(None if refused is None else H.refusal_text(refused), served, _enabled(records),
                _ignored(relation, granted, "cmdb"), _read_versions(ran["run"].run_dir if ran else None),
                _versions_of(records))


def _branch_launch(env: Env, relation: str) -> Seen:
    est = O.estate(env.tmp_path)
    granted = tuple(est.systems)
    records = _records_for(est.records(), relation, granted=granted, lost="siem-x")
    directory = est.directory(records=records)
    base = {"rows": [{"user": "alice", "event_id": "e-100", "host": "web-1"}]}
    lookup = O.query_params("x")
    est.answer("siem-x", "lookup", lookup, base)

    launched = O.launch(
        env.tmp_path, est, calls=[O.Call("idp", "query", O.query_params("user:alice"), base),
                                  O.Call("siem-x", "lookup", lookup, base)],
        oracle=O.oracle(then=O.submit(base, O.EMPTY_CLAIM)), verifier=O.passing_verifier(), directory=directory)

    manifest = launched.ep / "family.yaml"
    served = (frozenset(yaml.safe_load(manifest.read_text(encoding="utf-8"))["served_systems"])
              if manifest.is_file() else None)
    outcome = O.read_outcome(launched.ep) or {}
    return Seen(launched.message or None, served, _enabled(records), _ignored(relation, granted, "siem-x"), None,
                not_replayable={n["system"]: n["reason"] for n in outcome.get("not_replayable", [])})


def _policy(env: Env, relation: str) -> Seen:
    from defender.cli import policy_cli

    root = env.tmp_path / "tenants"
    tenants.place_tenant(root, fixture_uuid("tenant:acme"), table=tenants.TABLE_A)
    env.monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    run_dir = env.tmp_path / "policy-run"
    (run_dir / "gather_raw").mkdir(parents=True)
    granted = ("cmdb", "elastic")
    records = _records_for(R.fixture_records(), relation, granted=granted, lost="cmdb")
    argv = ["show", "gather", "--run-dir", str(run_dir), "--tenant", fixture_uuid("tenant:acme")]
    refusal: str | None = None
    try:
        policy_cli.main(argv, directory=directory_for_argv(argv, records=records))
    except SystemExit as stop:
        refusal = str(stop.code)
    return Seen(refusal, None, _enabled(records), _ignored(relation, granted, "cmdb"), None)


ENTRIES: dict[str, Callable[[Env, str], Seen]] = {
    "fresh run": _fresh_run,
    "episode sibling": _sibling,
    "branch launch": _branch_launch,
    "defender-policy": _policy,
}
#: The entries that are themselves a run (hold row (d)).
RUNS = ("fresh run", "episode sibling")


def _warned(caplog: pytest.LogCaptureFixture, system: str) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and system in r.getMessage() and "grant" in r.getMessage().lower()]


@pytest.mark.parametrize("relation", RELATIONS)
@pytest.mark.parametrize("entry", ENTRIES)
def test_1366_every_entry_that_resolves_a_tenant_applies_the_one_grants_by_records_verdict(
        tmp_path, data_root, monkeypatch, caplog, entry, relation):
    """Each entry, over a tenant whose records are a strict subset of the catalog and whose grants name a system with no
    enabled record: not imported is refused naming the import; the entry serves exactly the enabled records' systems; one
    warning line per ignored grant; and an entry that is a run records the versions it read. (#1366 R8, R12, O6, H9)"""
    with caplog.at_level(logging.WARNING):
        seen = ENTRIES[entry](Env(tmp_path, data_root, monkeypatch), relation)
    text = seen.refusal or ""

    if relation == NOT_IMPORTED:  # (a)
        assert R.AUTHOR[R.IMPORT] in text, (entry, seen)
        assert not seen.served, (entry, "served systems of a tenant that is not imported", seen.served)
        assert seen.versions is None, (entry, "wrote versions for a tenant that is not imported")
        return
    assert R.AUTHOR[R.IMPORT] not in text, (entry, "named the import for a tenant that IS imported", text)

    if relation == EMPTIED:  # (b), the limit: nothing granted is left
        assert seen.refusal is not None, (entry, "ran with no granted system recorded")
        assert all(system in text for system in ("cmdb", "elastic")) or all(
            system in text for system in ("edr", "idp", "siem-x")), (entry, text)
        assert not seen.served, (entry, seen.served)
        return

    assert seen.refusal is None, (entry, seen.refusal)  # the tenant still has a granted, recorded system
    if seen.served is not None:  # (b)
        assert seen.served == seen.enabled, (entry, sorted(seen.served), sorted(seen.enabled))
    for system in seen.ignored:
        # (b) at the launch's pre-flight: the source run's captured call to a system the tenant has no enabled record of
        # is one pre-flight does not know (the roster it was handed lacks the system), not a declared verb the grant
        # happens to withhold: it is the roster, not only the narrowed grants, that is the tenant's.
        if entry == "branch launch":
            why = seen.not_replayable.get(system, "")
            assert "unknown" in why, (entry, system, seen.not_replayable)
            assert "is declared" not in why, (entry, system, seen.not_replayable)
    for system in seen.ignored:  # (c)
        assert len(_warned(caplog, system)) == 1, (entry, system, caplog.text)
    assert sum(1 for r in caplog.records if r.levelno >= logging.WARNING and "grant" in r.getMessage().lower()
               and "ignored" in r.getMessage().lower()) == len(seen.ignored), caplog.text
    if entry in RUNS:  # (d)
        assert seen.versions == seen.versions_expected, (entry, seen.versions, seen.versions_expected)
    else:
        assert seen.versions is None
