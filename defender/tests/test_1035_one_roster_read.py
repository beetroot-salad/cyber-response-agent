"""#1035 — one roster read: `runtime.verbs.read_roster`, and the four readers that consume it."""
from __future__ import annotations

import functools
import os
import shutil
import sys
from pathlib import Path

import pytest

from defender import _git
from defender.tests import _tenants1106
from defender.learning.core import drains, persist
from defender.learning.core.config import LoopPaths
from defender.learning.core.faults import SYSTEMIC_FAULTS
from defender.learning.leads import declared_systems, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import verbs
from defender.runtime.verb_grant import DENY_ALL
from defender.runtime.verb_roster import RosterError, audit_read_surfaces
from defender.runtime.verbs import ModuleVerbRegistry, RegistryError
from defender.skills.invlang.validate import _gating
from defender.tests._declared869 import (
    ADAPTER_BODY,
    ADAPTERS_REL,
    pitfall_row,
    seed_tree,
    write,
)
from defender.tests._curator1134 import open_state
from defender.tests._declared870 import graveyard_by_id, queue_ids
from defender.tests._roster1035 import (
    EXIT_RAISED_EXPECTED,
    EXIT_RETURNED,
    ChildVerdict,
    handed_to_nobody,
    read_roster,
    run_as_nobody,
)
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL
from defender.learning.core.state import PITFALLS

#: The phrase O5 keeps: `test_hardening_772.py` matches the resolver's absent-directory
#: message on it through `bind`, and M2 unifies BOTH cannot-read arms onto it.
CANNOT_READ = "not a directory this process can read"

#: The swallow's own log line — the shape `_run_curator_module` renders an `OSError` as.
CONTINUING = "(continuing)"

#: An adapter whose `VERBS` literal the roster's cold read can parse, so a consumer that
#: also reads verbs (the gate, the audit) sees `query` declared on it.
QUERY_ADAPTER = (
    "def query(ctx, *, native_query: str) -> list[dict]:\n"
    "    return [{'hit': native_query}]\n"
    "VERBS = {'query': query}\n"
)

#: The names the anomaly fixture derives and the dispatch seam refuses — `verbs._system_of`
ANOMALY_NAMES = frozenset({"dir", ".hidden", "", "..", "change-mgmt"})


def _anomaly_adapters(adapters: Path) -> Path:
    """The anomaly fixture: one real `cmdb_adapter.py` beside the five anomalies."""
    write(adapters / "cmdb_adapter.py", QUERY_ADAPTER)
    write(adapters / "dir_adapter.py" / ".keep", "")
    write(adapters / ".hidden_adapter.py", ADAPTER_BODY)
    write(adapters / "_adapter.py", ADAPTER_BODY)
    write(adapters / ".._adapter.py", ADAPTER_BODY)
    write(adapters / "change-mgmt_adapter.py", ADAPTER_BODY)
    derived = {verbs._system_of(p) for p in adapters.glob("*" + verbs.ADAPTER_SUFFIX)}
    assert derived == ANOMALY_NAMES | {"cmdb"}, f"the fixture is not what it claims: {derived}"
    return adapters


def _repo_adapters(root: Path) -> Path:
    """`<root>/defender/scripts/adapters` — the address every consumer that starts from a
    repo root (`adapter_declared_systems`, `known_capabilities`) derives, and the one the
    audit derives from `<root>/defender`."""
    return root / ADAPTERS_REL


def _expect_raised(verdict: ChildVerdict, expected: type[BaseException]) -> None:
    assert verdict.code == EXIT_RAISED_EXPECTED, (
        f"expected {expected.__name__} out of the nobody child; {verdict.describe()}"
    )


def _expect_returned(verdict: ChildVerdict, value: object) -> None:
    assert verdict.code == EXIT_RETURNED, (
        f"the readable positive control did not return; {verdict.describe()}"
    )
    assert verdict.returned == repr(value), (
        f"the readable positive control did not answer {value!r}; {verdict.describe()}"
    )


# M1 — the primitive itself


def test_read_roster_accepts_what_dispatches_and_reports_what_it_refused(tmp_path):
    adapters = _anomaly_adapters(tmp_path / "adapters")

    roster = read_roster(adapters)
    for view in (roster.accepted, roster.verbs):
        with pytest.raises(TypeError):
            view["ghost"] = None  # type: ignore[index]

    assert roster.accepted == {"cmdb": (adapters / "cmdb_adapter.py").resolve()}, roster.accepted
    assert roster.accepted["cmdb"].is_file()
    assert roster.verbs == {"cmdb": frozenset({"query"})}, roster.verbs
    assert roster.refused == tuple(sorted(ANOMALY_NAMES)), roster.refused
    assert "read_roster" in verbs.__all__, "the primitive is not exported"
    assert ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems() == tuple(sorted(roster.accepted))
    assert ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems() == ("cmdb",)


def test_read_roster_refuses_a_directory_it_cannot_read_naming_it(tmp_path):
    missing = tmp_path / "nope"
    assert not missing.exists()
    with pytest.raises(RegistryError) as exc:
        read_roster(missing)
    assert str(missing) in str(exc.value), f"does not name the directory: {exc.value}"

    not_a_dir = tmp_path / "file"
    not_a_dir.write_text(ADAPTER_BODY, encoding="utf-8")
    with pytest.raises(RegistryError) as exc:
        read_roster(not_a_dir)
    assert str(not_a_dir) in str(exc.value), f"does not name the path: {exc.value}"

    adapters = tmp_path / "adapters"
    write(adapters / "cmdb_adapter.py", ADAPTER_BODY)
    os.symlink("loop_adapter.py", adapters / "loop_adapter.py")
    if sys.version_info < (3, 13):
        with pytest.raises(RegistryError) as exc:
            read_roster(adapters)
        assert str(adapters) in str(exc.value), f"does not name the directory: {exc.value}"
    else:
        assert set(read_roster(adapters).accepted) == {"cmdb"}
    (adapters / "loop_adapter.py").unlink()
    assert set(read_roster(adapters).accepted) == {"cmdb"}


def test_read_roster_refuses_an_unsearchable_directory_as_nobody(tmp_path):
    root = tmp_path / "tree"
    adapters = root / "adapters"
    write(adapters / "cmdb_adapter.py", ADAPTER_BODY)

    def probe():
        return set(read_roster(adapters).accepted)

    with handed_to_nobody(root, adapters, 0o755):
        _expect_returned(run_as_nobody(probe, expected=RegistryError), {"cmdb"})
    for mode in (0o400, 0o000):
        with handed_to_nobody(root, adapters, mode):
            verdict = run_as_nobody(probe, expected=RegistryError)
        _expect_raised(verdict, RegistryError)
        assert str(adapters) in verdict.message, (
            f"mode {mode:o}: the error does not name the directory; {verdict.describe()}"
        )

    shape_only = root / "shape-only"
    write(shape_only / ".hidden_adapter.py", ADAPTER_BODY)

    def probe_shape_only():
        return set(read_roster(shape_only).accepted)

    with handed_to_nobody(root, shape_only, 0o755):
        _expect_returned(run_as_nobody(probe_shape_only, expected=RegistryError), set())
    with handed_to_nobody(root, shape_only, 0o400):
        verdict = run_as_nobody(probe_shape_only, expected=RegistryError)
    _expect_raised(verdict, RegistryError)
    assert str(shape_only) in verdict.message, verdict.describe()


# P1 / P2 — the resolver (O1, O5)


def test_the_resolver_reports_an_unreadable_directory_as_its_own_fault_as_nobody(tmp_path):
    root = tmp_path / "tree"
    adapters = _repo_adapters(root)
    write(adapters / "cmdb_adapter.py", ADAPTER_BODY)

    def probe():
        return declared_systems.adapter_systems_under(adapters)

    with handed_to_nobody(root, adapters, 0o755):
        _expect_returned(run_as_nobody(probe, expected=LeadAuthorError), frozenset({"cmdb"}))
    for mode in (0o400, 0o000):
        with handed_to_nobody(root, adapters, mode):
            verdict = run_as_nobody(probe, expected=LeadAuthorError)
        _expect_raised(verdict, LeadAuthorError)
        assert f"{adapters} is {CANNOT_READ}" in verdict.message, (
            f"mode {mode:o}: the resolver's error does not name the directory with the "
            f"unified phrase; {verdict.describe()}"
        )

    missing = tmp_path / "absent" / ADAPTERS_REL
    with pytest.raises(LeadAuthorError) as exc:
        declared_systems.adapter_systems_under(missing)
    assert f"{missing} is {CANNOT_READ}" in str(exc.value), str(exc.value)

    shape_only = root / "shape-only"
    write(shape_only / ".hidden_adapter.py", ADAPTER_BODY)

    def probe_shape_only():
        return declared_systems.adapter_systems_under(shape_only)

    with handed_to_nobody(root, shape_only, 0o400):
        verdict = run_as_nobody(probe_shape_only, expected=LeadAuthorError)
    _expect_raised(verdict, LeadAuthorError)
    assert f"{shape_only} is {CANNOT_READ}" in verdict.message, verdict.describe()


def test_a_symlink_loop_named_like_an_adapter_never_escapes_the_resolver_untyped(tmp_path):
    adapters = tmp_path / "adapters"
    write(adapters / "cmdb_adapter.py", ADAPTER_BODY)
    os.symlink("loop_adapter.py", adapters / "loop_adapter.py")
    assert (adapters / "loop_adapter.py").is_symlink()

    # Any OTHER exception propagates out of this `try` and fails the test as itself — which
    # is the pin: the `except` names the one class allowed to escape.
    outcome: frozenset[str] | LeadAuthorError
    try:
        outcome = declared_systems.adapter_systems_under(adapters)
    except LeadAuthorError as e:
        outcome = e
    if isinstance(outcome, LeadAuthorError):
        assert str(adapters) in str(outcome), (
            f"the resolver's error does not name the directory: {outcome}"
        )
    else:
        assert outcome == frozenset({"cmdb"}), (
            f"the loop arm answered {outcome!r}, not the control's set"
        )

    (adapters / "loop_adapter.py").unlink()
    assert declared_systems.adapter_systems_under(adapters) == frozenset({"cmdb"})


# P4 — the drain seam (O2)


def test_an_unsearchable_adapters_directory_is_not_a_successful_pitfalls_tick(
    tmp_path, monkeypatch,
):
    assert not issubclass(LeadAuthorError, OSError)
    assert drains._CURATOR_MODULES["pitfalls_curator"] == pitfalls_curator.__name__
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("cmdb",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    adapters = _repo_adapters(repo)
    paths = LoopPaths(repo_root=repo, state_dir=repo / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "mcpsys"), pitfall_row("r:l-001:0", "mcpsys")],
        state=open_state(paths),
    )
    assert len(persist.read_pitfalls(open_state(paths))) == 2

    def probe():
        return drains._invoke_pitfalls(paths, open_state(paths), on_curated=lambda _d: None,
                                       label=LEAD_AUTHOR_DRAIN_LABEL)

    with handed_to_nobody(repo, adapters, 0o400):
        verdict = run_as_nobody(probe, expected=LeadAuthorError)
    _expect_raised(verdict, LeadAuthorError)
    assert f"{adapters} is {CANNOT_READ}" in verdict.message, (
        f"the raise is not the resolver's own refusal; {verdict.describe()}"
    )
    assert CONTINUING not in verdict.log, f"the drain seam swallowed the fault: {verdict.log!r}"
    assert len(persist.read_pitfalls(open_state(paths))) == 2, "the queue was rotated on a failed tick"
    assert not (paths.state_root / PITFALLS.consumed).exists(), "rows were stamped consumed on a failed tick"

    with handed_to_nobody(repo, adapters, 0o755):
        control = run_as_nobody(probe, expected=LeadAuthorError)
    _expect_returned(control, 0)
    assert CONTINUING not in control.log, control.log
    assert CANNOT_READ not in control.log, control.log
    assert persist.read_pitfalls(open_state(paths)) == [], (
        "the readable control did not get past the resolver to rotate the unattributable rows"
    )


def _redirect_repo_root(monkeypatch, root: Path) -> None:
    """Point the checkout at `root`. `_adapters_at_run_start` reads `_git.REPO_ROOT` at call
    time to find the checkout's adapters directory, so the module constant is the address
    to redirect."""
    monkeypatch.setattr(_git, "REPO_ROOT", root)  # lint-monkeypatch: ok — a module constant read at call time; the checkout root has no other seam


def test_the_nothing_to_try_gate_never_answers_without_a_held_roster(tmp_path):
    root = tmp_path / "tree"
    adapters = _repo_adapters(root)
    write(adapters / "cmdb_adapter.py", QUERY_ADAPTER)

    _gating.release_capabilities()
    with pytest.raises(_gating.CapabilitiesNotRead) as exc:
        _gating._capability_exists("cmdb")
    assert "hold_capabilities" in str(exc.value), exc.value

    roster = read_roster(adapters)
    with pytest.raises(TypeError):
        _gating.hold_capabilities(roster.verbs)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        _gating.hold_capabilities(adapters)  # type: ignore[arg-type]
    with pytest.raises(_gating.CapabilitiesNotRead):
        _gating._capability_exists("cmdb")

    _gating.hold_capabilities(roster)
    assert _gating.known_capabilities() is roster.verbs
    assert _gating._capability_exists("cmdb") is True
    assert _gating._capability_exists("cmdb.query") is True
    assert _gating._capability_exists("nosuch") is False
    assert _gating._capability_exists("cmdb.nosuch") is False


def _run_start():
    pytest.importorskip("pydantic_ai")
    from defender.runtime.driver import _adapters_at_run_start

    return _adapters_at_run_start


def test_the_run_refuses_an_absent_checkout_adapters_directory_at_its_own_frame(
    tmp_path, monkeypatch,
):
    """P6c (O6), the absent arm — the directory is the process's OWN checkout's, and "absent" is a
    fault there, not an empty roster."""
    at_run_start = _run_start()
    run_tree = tmp_path / "run-tree"
    write(_repo_adapters(run_tree) / "cmdb_adapter.py", QUERY_ADAPTER)
    root = tmp_path / "tree"
    root.mkdir()
    adapters = _repo_adapters(root)
    assert not adapters.exists()
    _redirect_repo_root(monkeypatch, root)

    _gating.release_capabilities()
    with pytest.raises(RegistryError) as exc:
        at_run_start(run_tree / "defender", None, object(), _tenants1106.fixture_run_tenant())
    assert str(adapters) in str(exc.value), f"does not name the directory: {exc.value}"
    with pytest.raises(_gating.CapabilitiesNotRead):
        _gating._capability_exists("cmdb")


# P7 — the read-surface audit (O7)


def _audit_tree(root: Path, *, skill_body: str) -> Path:
    """`<root>/defender` with one `cmdb` adapter declaring `query` and one `cmdb` SKILL.md —
    the minimal tree `audit_read_surfaces` scans."""
    tree = root / "defender"
    write(tree / "scripts" / "adapters" / "cmdb_adapter.py", QUERY_ADAPTER)
    write(tree / "skills" / "cmdb" / "SKILL.md", f"---\nname: cmdb\n---\n\n{skill_body}\n")
    return tree


def test_the_read_surface_audit_never_reports_a_tree_it_could_not_read_as_clean(tmp_path):
    dirty = _audit_tree(tmp_path / "dirty", skill_body="call cmdb.query for hosts")
    hits = audit_read_surfaces(dirty, {})
    assert len(hits) == 1, hits
    assert "skills/cmdb/SKILL.md" in hits[0], hits
    assert "cmdb.query" in hits[0], hits

    clean = _audit_tree(tmp_path / "clean", skill_body="nothing advertised here")
    assert audit_read_surfaces(clean, {}) == ()

    adapters = clean / "scripts" / "adapters"

    def probe():
        return audit_read_surfaces(clean, {})

    with handed_to_nobody(tmp_path / "clean", adapters, 0o755):
        _expect_returned(run_as_nobody(probe, expected=RosterError), ())
    for mode in (0o400, 0o000):
        with handed_to_nobody(tmp_path / "clean", adapters, mode):
            verdict = run_as_nobody(probe, expected=RosterError)
        _expect_raised(verdict, RosterError)
        assert str(adapters) in verdict.message, (
            f"mode {mode:o}: the audit's error does not name the directory; {verdict.describe()}"
        )


def test_the_read_surface_audit_refuses_an_absent_adapters_directory(tmp_path):
    """P7 (O7), the absent arm — `audit_read_surfaces(<tree>/nowhere, {})` raises `RosterError`
    naming the missing adapters directory; an absent tree must not report a clean audit."""
    tree = _audit_tree(tmp_path, skill_body="nothing advertised here")
    assert audit_read_surfaces(tree, {}) == ()

    nowhere = tree / "nowhere"
    assert not nowhere.exists()
    with pytest.raises(RosterError) as exc:
        audit_read_surfaces(nowhere, {})
    assert str(nowhere / "scripts" / "adapters") in str(exc.value), (
        f"does not name the missing adapters directory: {exc.value}"
    )


# P3 / P8 — one set, measured (O4)


def test_every_consumer_declares_the_registrys_set_over_the_anomaly_fixture(
    tmp_path, capsys,
):
    root = tmp_path / "tree"
    adapters = _anomaly_adapters(_repo_adapters(root))
    capsys.readouterr()
    expected = ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems()
    assert expected == ("cmdb",), "the anchor is not the filtered roster, so the equalities are vacuous"
    assert read_roster(adapters).refused == tuple(sorted(ANOMALY_NAMES))
    silent = capsys.readouterr()
    assert silent.err + silent.out == "", (
        f"the registry / the primitive logged on their own: {silent.err!r} {silent.out!r}"
    )

    assert declared_systems.adapter_systems_under(adapters) == frozenset(expected)
    log = capsys.readouterr().err
    for name in ANOMALY_NAMES:
        assert sum(repr(name) in ln and str(adapters) in ln for ln in log.splitlines()) == 1, (
            f"{name!r} is not refused on exactly one line naming the directory: {log}"
        )

    _gating.hold_capabilities(read_roster(adapters))
    assert set(_gating.known_capabilities()) == set(expected)
    assert _gating._capability_exists("cmdb") is True
    assert _gating._capability_exists("cmdb.query") is True
    assert _gating._capability_exists("change-mgmt") is False, (
        "a hyphen-in-filename adapter the dispatch seam cannot resolve counts as a capability"
    )
    assert _gating._capability_exists("dir") is False, (
        "a DIRECTORY named like an adapter counts as a capability"
    )

    assert set(read_roster(adapters).accepted) == set(expected)


def _seed_pitfalls_queue(tmp_path: Path, monkeypatch) -> tuple[Path, LoopPaths]:
    """Two `mcpsys` rows queued over a tree whose adapters directory declares `cmdb` — the
    P4 fixture, minus the privilege drop. The rows name a system no adapter declares so that
    the readable control rotates them out without ever reaching a curator spawn."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "1")
    repo = seed_tree(tmp_path, adapters=("cmdb",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    paths = LoopPaths(repo_root=repo, state_dir=repo / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "mcpsys"), pitfall_row("r:l-001:0", "mcpsys")],
        state=open_state(paths),
    )
    assert queue_ids(paths) == ["r:l-000:0", "r:l-001:0"]
    return repo, paths


def test_the_pitfalls_drain_does_not_spend_the_queue_on_an_unreadable_adapters_tree(
    tmp_path, monkeypatch,
):
    repo, paths = _seed_pitfalls_queue(tmp_path, monkeypatch)
    adapters = _repo_adapters(repo)
    shutil.rmtree(adapters)

    with pytest.raises(LeadAuthorError) as exc:
        drains._drain_pitfalls(
            paths, open_state(paths), functools.partial(drains._invoke_pitfalls, label=LEAD_AUTHOR_DRAIN_LABEL))
    assert f"{adapters} is {CANNOT_READ}" in str(exc.value), (
        f"the raise is not the resolver's own refusal: {exc.value}"
    )
    assert isinstance(exc.value, SYSTEMIC_FAULTS), (
        "the resolver's fault is not systemic, so `run_or_dead_letter` files it as the "
        "batch's own failure"
    )
    assert queue_ids(paths) == ["r:l-000:0", "r:l-001:0"], "the queue was spent on a host fault"
    assert all(int(r.get("attempts") or 0) == 0 for r in persist.read_pitfalls(open_state(paths))), (
        "a queued row's lifetime `attempts` was bumped for a tree this process cannot read"
    )
    assert graveyard_by_id(paths) == {}, "rows were retired for a host fault"

    # The tick's own `finally` (`ClaimGit.reset`: `reset --hard` + `clean`) has
    # already put the committed adapters directory back, so the control needs no rebuild.
    assert (adapters / "cmdb_adapter.py").is_file()
    drains._drain_pitfalls(
        paths, open_state(paths), functools.partial(drains._invoke_pitfalls, label=LEAD_AUTHOR_DRAIN_LABEL))
    assert queue_ids(paths) == [], (
        "the readable control did not get past the resolver to rotate the unattributable rows"
    )


def _never_called(messages, info):  # pragma: no cover — reached only by a regressed run
    raise AssertionError("the model was called before the roster was read")


def test_the_run_reads_the_roster_before_any_model_call(tmp_path, monkeypatch):
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import (
        GOLDEN_AB3, ReplayFn, Turn, drive, materialize,
    )

    # Control, same read: a run over the readable checkout DOES open its wire log, so the
    # absent log below is "never opened", not a path no run ever writes.
    control = materialize(tmp_path / "control", GOLDEN_AB3, run_id='r-1035-ctl')
    drive(control, run_id="r-1035-ctl", main=ReplayFn([Turn(text="Investigation complete.")]))
    assert (control / "wire_logs").is_dir(), "the control run opened no wire log"

    root = tmp_path / "tree"
    root.mkdir()
    assert not _repo_adapters(root).exists()
    _redirect_repo_root(monkeypatch, root)
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id='r-1035')
    with pytest.raises(RegistryError) as exc:
        drive(run_dir, run_id="r-1035", main=_never_called)
    assert str(_repo_adapters(root)) in str(exc.value), exc.value
    assert not (run_dir / "wire_logs").exists(), "the wire log opened before the roster was read"


def test_an_unreadable_adapter_file_is_the_hosts_fault_not_an_empty_declaration(tmp_path):
    root = tmp_path / "tree"
    adapters = _repo_adapters(root)
    write(adapters / "cmdb_adapter.py", QUERY_ADAPTER)
    adapter = adapters / "cmdb_adapter.py"

    def probe():
        return {s: set(v) for s, v in read_roster(adapters).verbs.items()}

    with handed_to_nobody(root, adapter, 0o644):
        _expect_returned(run_as_nobody(probe, expected=RegistryError), {"cmdb": {"query"}})
    with handed_to_nobody(root, adapter, 0o000):
        verdict = run_as_nobody(probe, expected=RegistryError)
    _expect_raised(verdict, RegistryError)
    assert str(adapters) in verdict.message, (
        f"the error does not name the directory; {verdict.describe()}"
    )
    assert str(adapter) in verdict.message, (
        f"the error blames the directory and does not name the one FILE at fault — the "
        f"operator's `ls -la` on the directory shows nothing wrong; {verdict.describe()}"
    )


def test_an_adapter_that_does_not_parse_is_recorded_on_the_roster_not_raised_or_swallowed(
    tmp_path,
):
    adapters = tmp_path / "adapters"
    write(adapters / "cmdb_adapter.py", QUERY_ADAPTER)
    (adapters / "latin_adapter.py").write_bytes(b"VERBS = {'query': 'caf\xe9'}\n")
    (adapters / "nul_adapter.py").write_bytes(b"VERBS = {'query': 1}\x00\n")
    (adapters / "broken_adapter.py").write_bytes(b"VERBS = {'query': \n")
    (adapters / "declared_adapter.py").write_bytes(
        b"# coding: latin-1\n# caf\xe9\nVERBS = {'query': 1}\n"
    )
    (adapters / "comment_adapter.py").write_bytes(b"# caf\xe9\nVERBS = {'query': 1}\n")

    roster = read_roster(adapters)
    assert set(roster.accepted) == {"cmdb", "latin", "nul", "broken", "declared", "comment"}
    assert roster.refused == ()
    assert set(roster.verbs["cmdb"]) == {"query"}
    for parses in ("declared", "comment"):
        assert set(roster.verbs[parses]) == {"query"}, (
            f"{parses}: the importer accepts this file and the cold reader declares nothing for it"
        )
        assert set(ModuleVerbRegistry(roster, DENY_ALL).verbs(parses)) == {"query"}
    assert set(roster.unparsed) == {"latin", "nul", "broken"}, dict(roster.unparsed)
    for name in ("latin", "nul", "broken"):
        assert roster.verbs[name] == frozenset()
        assert roster.declared_verbs(name) == frozenset()
        assert "SyntaxError" in roster.unparsed[name], roster.unparsed[name]

    from defender.runtime.verb_grant import GrantError, VerbGrant

    with pytest.raises(GrantError) as exc:
        ModuleVerbRegistry(roster, VerbGrant(role="gather", entries=(("latin", "query", "r"),)))
    assert "latin.query" in str(exc.value)
