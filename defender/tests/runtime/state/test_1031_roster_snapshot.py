"""#1031 — the roster is fixed at registry construction, and a directory that cannot be listed
fails there."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender import _scaffold_rules  # noqa: E402
from defender.tests.learning.oracle.live_contracts._spec1224 import build_registry  # noqa: E402
from defender.runtime import verbs  # noqa: E402
from defender.runtime.query_tool import QueryCapture  # noqa: E402
from defender.runtime.verb_grant import DENY_ALL  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.scripts.gather_tools.record_query import system_fingerprint  # noqa: E402
from defender.tests.support.runtime.engine._declared869 import ADAPTER_BODY, write  # noqa: E402
from defender.tests.support.learning.curation._verb_authorization_632 import grant_of  # noqa: E402
from defender.tests.learning.branch.test_920_estate_seam import AS_OF, SERVED_FILE, World, fresh_ledger  # noqa: E402
from defender.runtime.verbs import read_roster  # noqa: E402

#: A grant that reaches the one system the fixtures declare, with the one verb they declare —
GRANT = grant_of("gather", (("elastic", "query"),))

#: An adapter declaring `query`, so `GRANT`'s load check passes over it.
QUERY_ADAPTER = (
    "from defender.runtime.verbs import VerbContext, verb\n"
    "@verb()\n"
    "def query(ctx: VerbContext, *, native_query: str) -> list[dict]:\n"
    "    return [{'hit': native_query}]\n"
    "VERBS = {'query': query}\n"
)


def _adapters(tmp_path: Path, *systems: str) -> Path:
    """A real adapters directory declaring `systems` (each a `VERBS = {}` stub)."""
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    for system in systems:
        write(adapters / f"{system.replace('-', '_')}_adapter.py", ADAPTER_BODY)
    return adapters


# O1 / D1 — the roster is fixed at construction


def test_the_roster_is_the_construction_time_one_after_the_directory_is_removed(tmp_path):
    adapters = _adapters(tmp_path, "elastic", "cmdb", "host-state")
    write(adapters / "host-state_adapter.py", ADAPTER_BODY)     # derives `host-state` again
    write(adapters / "change-mgmt_adapter.py", ADAPTER_BODY)    # derives a name that resolves to nothing
    (adapters / "foo_adapter.py").mkdir()                      # the glob yields it; is_file refuses it
    expected = ("cmdb", "elastic", "host-state")

    registry = ModuleVerbRegistry(read_roster(adapters), DENY_ALL)
    assert registry.systems() == expected, "the roster before the removal is not the filtered one"

    (adapters / "cmdb_adapter.py").unlink()
    assert sorted(adapters.glob("*_adapter.py")), "the fixture emptied the directory"
    assert registry.systems() == expected, \
        "the roster followed one file off the disk: it is re-read per call, not fixed"

    shutil.rmtree(adapters)
    assert not adapters.exists(), "the fixture did not remove the directory"
    assert registry.systems() == expected, \
        "the roster followed the disk: it is re-read per call rather than fixed at construction"
    assert registry.systems() == registry.systems(), "two reads of the snapshot disagree"


def test_the_query_tool_consults_the_snapshot_not_the_disk(tmp_path):
    adapters = _adapters(tmp_path, "elastic")
    capture = QueryCapture(ModuleVerbRegistry(read_roster(adapters), DENY_ALL))
    ghost_pair = ("", system_fingerprint("ghostone", ""))
    assert ghost_pair[1], "the ghost mints no fingerprint, so the control below is vacuous"

    assert capture._system_of_record("elastic") == "elastic"
    assert capture._system_of_record("ghostone") == ""
    assert capture._coarsen("elastic") == ("elastic", "")
    assert capture._coarsen("ghostone") == ghost_pair

    shutil.rmtree(adapters)
    assert capture._system_of_record("elastic") == "elastic", \
        "a declared system reads as undeclared once its directory is gone"
    assert capture._system_of_record("ghostone") == ""
    assert capture._coarsen("elastic") == ("elastic", ""), \
        "the forbidden pair: a declared name coarsened away and fingerprinted"
    assert capture._coarsen("ghostone") == ghost_pair


def test_an_adapter_added_after_construction_is_not_on_the_roster(tmp_path):
    """N2/D1 — the snapshot is not live in EITHER direction: an adapter written after construction
    is undeclared to that registry for its lifetime."""
    adapters = _adapters(tmp_path, "elastic")
    before = ModuleVerbRegistry(read_roster(adapters), DENY_ALL)
    assert before.systems() == ("elastic",)

    write(adapters / "cmdb_adapter.py", ADAPTER_BODY)
    assert before.systems() == ("elastic",), \
        "the roster grew after construction: it is read from the disk per call"
    assert ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems() == ("cmdb", "elastic"), \
        "a fresh registry does not see the new adapter, so the control above is vacuous"


# O2 / D2 — a directory that cannot be listed fails at construction


def test_a_missing_directory_fails_at_construction_under_deny_all(tmp_path):
    """O2/D2 — `ModuleVerbRegistry(read_roster(<missing dir>), DENY_ALL)` raises `RegistryError`
    before construction, and the message names the directory."""
    missing = tmp_path / "nope"
    assert not missing.exists()
    with pytest.raises(verbs.RegistryError) as exc:
        ModuleVerbRegistry(read_roster(missing), DENY_ALL)
    assert str(missing) in str(exc.value), \
        f"the registry error does not name the directory: {exc.value}"

    assert ModuleVerbRegistry(read_roster(_adapters(tmp_path, "elastic")), DENY_ALL).systems() == ("elastic",)


def test_a_regular_file_at_the_adapters_path_fails_at_construction(tmp_path):
    not_a_dir = tmp_path / "adapters"
    not_a_dir.write_text("VERBS = {}\n", encoding="utf-8")
    assert not_a_dir.is_file()
    with pytest.raises(verbs.RegistryError) as exc:
        ModuleVerbRegistry(read_roster(not_a_dir), DENY_ALL)
    assert str(not_a_dir) in str(exc.value)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores mode bits; the directory stays listable")
def test_an_unreadable_directory_fails_at_construction(tmp_path):
    """O2/D2, the cannot-list arm the issue names — an existing directory with mode 0."""
    adapters = _adapters(tmp_path, "elastic")
    adapters.chmod(0)
    try:
        with pytest.raises(verbs.RegistryError) as exc:
            ModuleVerbRegistry(read_roster(adapters), DENY_ALL)
        assert str(adapters) in str(exc.value)
    finally:
        adapters.chmod(0o700)
    assert ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems() == ("elastic",)


def test_a_symlink_loop_named_like_an_adapter_is_the_registrys_own_error(tmp_path):
    """O2/D2, the arm the roster FILTER raises rather than the listing — an entry named like an
    adapter that is a symlink to itself."""
    adapters = _adapters(tmp_path / "defender" / "scripts", "elastic")
    os.symlink("loop_adapter.py", adapters / "loop_adapter.py")
    loops_raise = sys.version_info < (3, 13)

    if loops_raise:
        with pytest.raises(verbs.RegistryError) as exc:
            ModuleVerbRegistry(read_roster(adapters), DENY_ALL)
        assert str(adapters) in str(exc.value), \
            f"the registry error does not name the directory: {exc.value}"
        with pytest.raises(_scaffold_rules.ScaffoldRuleError):
            _scaffold_rules.VerbResolver(tmp_path / "defender")
    else:
        assert ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems() == ("elastic",)
        assert _scaffold_rules.VerbResolver(tmp_path / "defender").is_system("elastic")

    (adapters / "loop_adapter.py").unlink()
    assert ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems() == ("elastic",)


def test_decide_and_verbs_read_the_roster_not_the_disk(tmp_path):
    adapters = tmp_path / "loaded" / "adapters"
    write(adapters / "elastic_adapter.py", QUERY_ADAPTER)
    registry = ModuleVerbRegistry(read_roster(adapters), GRANT)
    before = registry.decide("elastic", "query")
    assert before.outcome == verbs.GRANTED
    assert before.fn is not None
    unknown_verb_before = registry.decide("elastic", "nope")
    assert unknown_verb_before.outcome == verbs.UNDECLARED
    assert "no verb of that name" in unknown_verb_before.refusal
    with pytest.raises(KeyError):
        registry.verbs("cmdb")

    shutil.rmtree(adapters)
    after = registry.decide("elastic", "query")
    assert after.outcome == verbs.GRANTED, \
        f"a granted call on a declared system was refused once the directory went: {after!r}"
    assert after.fn is before.fn, "the dispatch resolved a different function after the removal"
    assert registry.systems() == ("elastic",)
    unknown_verb = registry.decide("elastic", "nope")
    assert unknown_verb == unknown_verb_before, \
        f"a declared system's unknown-verb refusal changed after the removal: {unknown_verb!r}"
    assert "unknown system" not in unknown_verb.refusal
    with pytest.raises(KeyError):
        registry.verbs("cmdb")

    fresh_dir = tmp_path / "fresh" / "adapters"
    write(fresh_dir / "elastic_adapter.py", QUERY_ADAPTER)
    fresh = ModuleVerbRegistry(read_roster(fresh_dir), GRANT)
    shutil.rmtree(fresh_dir)
    assert fresh.systems() == ("elastic",)
    with pytest.raises(FileNotFoundError):
        fresh.decide("elastic", "query")


def test_the_world_registry_inherits_the_snapshot_and_the_construction_time_check(tmp_path):
    missing = tmp_path / "nope"
    with pytest.raises(verbs.RegistryError) as exc:
        build_registry(read_roster(missing), DENY_ALL, world=World("w1"),
                      ledger=fresh_ledger(tmp_path / "missing" / SERVED_FILE), as_of=AS_OF)
    assert str(missing) in str(exc.value)

    adapters = _adapters(tmp_path, "elastic")
    world = build_registry(read_roster(adapters), DENY_ALL, world=World("w1"),
                          ledger=fresh_ledger(tmp_path / "real" / SERVED_FILE), as_of=AS_OF)
    assert world.systems() == ("elastic",)
    shutil.rmtree(adapters)
    assert world.systems() == ("elastic",), "the subclass re-reads the roster from the disk"


# D2 / D1 through `_scaffold_rules.VerbResolver`


def test_the_scaffold_resolver_fails_at_construction_over_a_tree_with_no_adapters(tmp_path):
    with pytest.raises(_scaffold_rules.ScaffoldRuleError) as exc:
        _scaffold_rules.VerbResolver(tmp_path)
    assert str(tmp_path / "scripts" / "adapters") in str(exc.value), \
        f"the resolver's error does not name the directory: {exc.value}"

    write(tmp_path / "scripts" / "adapters" / "elastic_adapter.py", ADAPTER_BODY)
    resolver = _scaffold_rules.VerbResolver(tmp_path)
    assert resolver.is_system("elastic")
    assert not resolver.is_system("cmdb")


# D4 — the registry-cannot-list apparatus is gone
