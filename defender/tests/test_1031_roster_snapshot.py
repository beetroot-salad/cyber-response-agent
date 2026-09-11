"""#1031 — the roster is fixed at registry construction, and a directory that cannot be listed
fails there.

THE ROOT. `ModuleVerbRegistry` caches every per-system verb list at construction on the stated
basis that "an adapters tree does not change under a live registry" — and re-globbed the
ROSTER on every `systems()` call. That one per-call read is I/O on the above-guard path (the
query tool asks it whether the model's `system` string is declared), so it could fail mid-run,
and #1017 D4 built an apparatus to record that failure. The apparatus missed the shape the
real primitive produces: `Path.glob` over a directory removed after construction answers `[]`
and raises nothing, so a DECLARED system's rejection was coarsened to `system=""` beside
`sha256(real name)` in `system_key` — the pair `record_query.system_fingerprint`'s contract
says cannot exist — and a registry over a directory that never existed constructed fine under
`DENY_ALL` and answered `()`.

WHAT IS DRIVEN. Real `ModuleVerbRegistry` (and `WorldRegistry`, and `_scaffold_rules.VerbResolver`)
constructions over synthetic adapters directories under `tmp_path`, with the REAL fault through
the REAL primitive: the directory is `rmtree`d, or a regular file stands at its path, or it is
made unreadable. No fake whose `systems()` raises appears here — the design's N1 says such a fake
is a broken fake, not a contract. The query tool's reading of the roster is driven through the
real `QueryCapture` over the real registry; the e2e half (the recorded row under a live run) is
`tests/e2e/test_1031_removed_directory.py`.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender import _scaffold_rules  # noqa: E402
from defender.learning.branch.estate.registry import WorldRegistry  # noqa: E402
from defender.runtime import query_tool, verbs  # noqa: E402
from defender.runtime.query_tool import QueryCapture, _registry_declares  # noqa: E402
from defender.runtime.verb_grant import DENY_ALL, GrantError  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.scripts.gather_tools.record_query import system_fingerprint  # noqa: E402
from defender.tests._declared869 import ADAPTER_BODY, write  # noqa: E402
from defender.tests._verb_authorization_632 import grant_of  # noqa: E402
# The estate seam's own fixtures for a `WorldRegistry` — the clock, the world token and the
# primed ledger its constructor demands — imported rather than re-spelled, so the registry
# here is built the way `run.py:288` builds it.
from defender.tests.test_920_estate_seam import AS_OF, World, fresh_ledger  # noqa: E402

#: A grant that reaches the one system the fixtures declare, with the one verb they declare —
#: so a registry over the fixture tree constructs under it (the grant's own load check names
#: no offender) and a MISSING tree is refused for the tree's absence, not the grant's shape.
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


# ---------------------------------------------------------------------------------------
# O1 / D1 — the roster is fixed at construction
# ---------------------------------------------------------------------------------------


def test_the_roster_is_the_construction_time_one_after_the_directory_is_removed(tmp_path):
    """O1/D1 — `systems()` after the adapters directory is `rmtree`d is the SAME tuple it was
    before, and that tuple is the roster today's filter derives: the `*_adapter.py` names,
    `_`→`-`, deduplicated, and passed through `_adapter_path` — so `change-mgmt_adapter.py`
    (a hyphen in the FILENAME, which resolves to no adapter) and a DIRECTORY named
    `foo_adapter.py` are not on it, and `host-state` derived from two filenames is on it once.
    The positive control is the roster before the removal; the two must be equal, and both
    must be the filtered one, so a snapshot taken with a looser filter fails here too.

    Observed failing by (today): `()` after the removal — `Path.glob` over a directory that
    no longer exists yields nothing and raises nothing."""
    adapters = _adapters(tmp_path, "elastic", "cmdb", "host-state")
    write(adapters / "host-state_adapter.py", ADAPTER_BODY)     # derives `host-state` again
    write(adapters / "change-mgmt_adapter.py", ADAPTER_BODY)    # derives a name that resolves to nothing
    (adapters / "foo_adapter.py").mkdir()                      # the glob yields it; is_file refuses it
    expected = ("cmdb", "elastic", "host-state")

    registry = ModuleVerbRegistry(adapters, DENY_ALL)
    assert registry.systems() == expected, "the roster before the removal is not the filtered one"

    shutil.rmtree(adapters)
    assert not adapters.exists(), "the fixture did not remove the directory"
    assert registry.systems() == expected, \
        "the roster followed the disk: it is re-read per call rather than fixed at construction"
    assert registry.systems() == registry.systems(), "two reads of the snapshot disagree"


def test_the_query_tool_consults_the_snapshot_not_the_disk(tmp_path):
    """O1/O3 unit — `QueryCapture._system_of_record` and `_coarsen` over a real registry whose
    directory has since been removed answer exactly what they answered while it existed: the
    real name with no fingerprint for a declared system, `""` with the ghost's fingerprint for
    an undeclared one. The positive control is the same four answers before the removal.

    Observed failing by (today): `("", sha256("elastic"))` for the declared name after the
    removal — a fingerprint of a real name, keyed like a ghost's, which is O3's failure."""
    adapters = _adapters(tmp_path, "elastic")
    capture = QueryCapture(ModuleVerbRegistry(adapters, DENY_ALL))
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
    """N2/D1 — the snapshot is not live in EITHER direction: an adapter written after
    construction is undeclared to that registry for its lifetime. The positive control is a
    fresh registry over the same directory, which does see it — so the file is real and the
    first registry's answer is the snapshot's, not a filter's.

    Observed failing by (today): the first registry answering `("cmdb", "elastic")`."""
    adapters = _adapters(tmp_path, "elastic")
    before = ModuleVerbRegistry(adapters, DENY_ALL)
    assert before.systems() == ("elastic",)

    write(adapters / "cmdb_adapter.py", ADAPTER_BODY)
    assert before.systems() == ("elastic",), \
        "the roster grew after construction: it is read from the disk per call"
    assert ModuleVerbRegistry(adapters, DENY_ALL).systems() == ("cmdb", "elastic"), \
        "a fresh registry does not see the new adapter, so the control above is vacuous"


# ---------------------------------------------------------------------------------------
# O2 / D2 — a directory that cannot be listed fails at construction
# ---------------------------------------------------------------------------------------


def test_a_missing_directory_fails_at_construction_under_deny_all(tmp_path):
    """O2/D2 — `ModuleVerbRegistry(<missing dir>, DENY_ALL)` raises `RegistryError` at
    construction, and the message names the directory. `DENY_ALL` is the grant the two
    prompt-side registries (`_scaffold_rules`, the skill-description hook) construct over, and
    the one the grant's own load check cannot fail: a grant naming nothing has no offender, so
    without a check of the directory itself this constructs and answers `()`. The positive
    control is the same construction over a directory that exists.

    Observed failing by (today): the construction succeeding (`systems() == ()`)."""
    missing = tmp_path / "nope"
    assert not missing.exists()
    with pytest.raises(verbs.RegistryError) as exc:
        ModuleVerbRegistry(missing, DENY_ALL)
    assert str(missing) in str(exc.value), \
        f"the registry error does not name the directory: {exc.value}"

    assert ModuleVerbRegistry(_adapters(tmp_path, "elastic"), DENY_ALL).systems() == ("elastic",)


def test_a_missing_directory_fails_at_construction_under_a_real_grant(tmp_path):
    """O2/D2 — under a grant that names real verbs the same construction raises the SAME
    `RegistryError`, not the grant's `GrantError`. Today it fails at construction already, but
    as the grant's load check: "the adapters under … do not declare elastic.query", which sends
    the reader to the verb-disposition table for a directory that is not there. The fault is
    the tree's absence and the error must say so — which puts the directory listing AHEAD of
    the cold verb read the load check consumes. The positive control is the same grant over a
    directory declaring what it names.

    Observed failing by (today): `GrantError` raised instead."""
    missing = tmp_path / "nope"
    with pytest.raises(verbs.RegistryError) as exc:
        ModuleVerbRegistry(missing, GRANT)
    assert not isinstance(exc.value, GrantError), \
        "a missing directory is reported as a grant/declaration disagreement"
    assert str(missing) in str(exc.value)

    adapters = tmp_path / "adapters"
    write(adapters / "elastic_adapter.py", QUERY_ADAPTER)
    assert ModuleVerbRegistry(adapters, GRANT).systems() == ("elastic",)


def test_a_regular_file_at_the_adapters_path_fails_at_construction(tmp_path):
    """O2/D2, the cannot-LIST arm that needs no privilege — a regular file where the directory
    should be: `os.scandir` raises `NotADirectoryError` (an `OSError`) for it, where `Path.glob`
    yields nothing and raises nothing. `RegistryError` at construction, naming the path.

    Observed failing by (today): the construction succeeding (`systems() == ()`)."""
    not_a_dir = tmp_path / "adapters"
    not_a_dir.write_text("VERBS = {}\n", encoding="utf-8")
    assert not_a_dir.is_file()
    with pytest.raises(verbs.RegistryError) as exc:
        ModuleVerbRegistry(not_a_dir, DENY_ALL)
    assert str(not_a_dir) in str(exc.value)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores mode bits; the directory stays listable")
def test_an_unreadable_directory_fails_at_construction(tmp_path):
    """O2/D2, the cannot-list arm the issue names — an existing directory with mode 0. Skipped
    as root, for whom the directory is listable and the claim is not testable. `RegistryError`
    at construction, naming the path; the positive control restores the mode and constructs.

    Observed failing by (today, as a non-root user): the construction succeeding."""
    adapters = _adapters(tmp_path, "elastic")
    adapters.chmod(0)
    try:
        with pytest.raises(verbs.RegistryError) as exc:
            ModuleVerbRegistry(adapters, DENY_ALL)
        assert str(adapters) in str(exc.value)
    finally:
        adapters.chmod(0o700)
    assert ModuleVerbRegistry(adapters, DENY_ALL).systems() == ("elastic",)


def test_the_world_registry_inherits_the_snapshot_and_the_construction_time_check(tmp_path):
    """O2/D1 through the subclass — `WorldRegistry` (the branch lane's registry, `run.py:288`)
    overrides neither the constructor's directory check nor `systems()`: over a missing
    directory it raises `RegistryError` naming it, and over a real one its roster survives the
    directory's removal. Built through its own constructor with the estate seam's fixtures,
    not through a structural check that `__init__` calls `super()`.

    Observed failing by (today): the missing-directory construction succeeding, and the roster
    answering `()` after the removal."""
    missing = tmp_path / "nope"
    with pytest.raises(verbs.RegistryError) as exc:
        WorldRegistry(missing, DENY_ALL, world=World("w1"),
                      ledger=fresh_ledger(tmp_path / "missing" / "served.jsonl"), as_of=AS_OF)
    assert str(missing) in str(exc.value)

    adapters = _adapters(tmp_path, "elastic")
    world = WorldRegistry(adapters, DENY_ALL, world=World("w1"),
                          ledger=fresh_ledger(tmp_path / "real" / "served.jsonl"), as_of=AS_OF)
    assert world.systems() == ("elastic",)
    shutil.rmtree(adapters)
    assert world.systems() == ("elastic",), "the subclass re-reads the roster from the disk"


# ---------------------------------------------------------------------------------------
# D2 / D1 through `_scaffold_rules.VerbResolver`
# ---------------------------------------------------------------------------------------


def test_the_scaffold_resolver_fails_at_construction_over_a_tree_with_no_adapters(tmp_path):
    """O2/D2 through the resolver — `VerbResolver(<tree with no scripts/adapters>)` raises
    `ScaffoldRuleError`, the module's own "could not evaluate" error and the one its two
    production callers already catch, at CONSTRUCTION; the message names the directory. The
    positive control is a tree with the directory, which constructs and answers membership.

    Observed failing by (today): the resolver constructing and answering `is_system(...)`
    False for every name — "could not check" rendered as "nothing there", #901's own defect
    one step earlier."""
    with pytest.raises(_scaffold_rules.ScaffoldRuleError) as exc:
        _scaffold_rules.VerbResolver(tmp_path)
    assert str(tmp_path / "scripts" / "adapters") in str(exc.value), \
        f"the resolver's error does not name the directory: {exc.value}"

    write(tmp_path / "scripts" / "adapters" / "elastic_adapter.py", ADAPTER_BODY)
    resolver = _scaffold_rules.VerbResolver(tmp_path)
    assert resolver.is_system("elastic")
    assert not resolver.is_system("cmdb")


def test_the_scaffold_resolver_reads_the_snapshot(tmp_path):
    """D1 through the resolver — `is_system` reads the roster fixed at the resolver's
    construction, which is after the writes it checks (the lead author builds one resolver per
    batch after the agent's writes; the connect skill builds a fresh one per call): an adapter
    written after construction is not a system to that resolver, and is one to a fresh
    resolver over the same tree.

    Observed failing by (today): the first resolver answering True — `_systems` was
    deliberately un-memoised."""
    write(tmp_path / "scripts" / "adapters" / "elastic_adapter.py", ADAPTER_BODY)
    before = _scaffold_rules.VerbResolver(tmp_path)
    assert before.is_system("elastic")
    assert not before.is_system("cmdb")

    write(tmp_path / "scripts" / "adapters" / "cmdb_adapter.py", ADAPTER_BODY)
    assert not before.is_system("cmdb"), "the resolver's roster followed the disk"
    assert _scaffold_rules.VerbResolver(tmp_path).is_system("cmdb"), \
        "a fresh resolver does not see the new adapter, so the control above is vacuous"


# ---------------------------------------------------------------------------------------
# D4 — the registry-cannot-list apparatus is gone
# ---------------------------------------------------------------------------------------


def test_the_registry_cannot_list_apparatus_is_gone_and_declares_is_membership(tmp_path):
    """D4 — the four names #1017 D4 added to `query_tool` no longer exist (`RegistryUnavailable`,
    `REGISTRY_BREAKER_KEY`, `_coarsen_or_record_fault`, `_record_registry_fault`), the two
    public ones are out of `__all__`, and `_registry_declares` is a plain membership test over
    `systems()`: True for a name the registry declares, False for one it does not. Absence is
    the claim, so `hasattr` is the instrument — the one place in this suite it is.

    Observed failing by (today): the names existing."""
    for name in ("RegistryUnavailable", "REGISTRY_BREAKER_KEY",
                 "_coarsen_or_record_fault", "_record_registry_fault"):
        assert not hasattr(query_tool, name), f"query_tool.{name} still exists"
        assert name not in query_tool.__all__
    assert "RegistryError" in verbs.__all__, "the construction-time error is not exported"

    registry = ModuleVerbRegistry(_adapters(tmp_path, "elastic"), DENY_ALL)
    assert registry.systems() == ("elastic",)
    assert _registry_declares(registry, "elastic") is True
    assert _registry_declares(registry, "cmdb") is False
