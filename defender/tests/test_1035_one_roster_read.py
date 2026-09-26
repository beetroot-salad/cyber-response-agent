"""#1035 — one roster read: `runtime.verbs.read_roster`, and the four readers that consume it.

THE ROOT. Four spellings of "which systems does this adapters directory declare" — the
registry's `_read_roster`, the lead-author resolver's `_adapter_names`, the invlang
`nothing-to-try` gate's `_known_capabilities`, and the read-surface audit's glob — diverge on
exactly the fault class #1033 closed for the registry alone. Over a directory that is
listable but not searchable (mode `0o400`) the registry raises `RegistryError`; the resolver,
the gate and the audit each leak a raw `PermissionError` on 3.11 (and, on a Python whose
`Path.is_file` swallows `EACCES`, go quiet: an empty roster with every real adapter logged as
"anomalous"). Over a directory that cannot be listed at all the gate answers `{}` — so every
`nothing-to-try` receipt pays — and the audit reports the tree clean. A symlink loop named
like an adapter escapes the resolver as `RuntimeError`. And the pitfalls drain runs the
curator inside `except (SubprocessError, OSError)`, so the resolver's `PermissionError` is a
green tick with "(continuing)" logged over a queue that will never drain.

WHAT IS PINNED. One module-level primitive, `read_roster(adapters_dir)`, returning a
COMPLETE record — `.accepted: name -> resolved path`, `.verbs: name -> the verb names the
adapter declares (read cold)`, `.refused: tuple[name, ...]` (sorted, deduplicated) — raising
`RegistryError` naming the directory for every cannot-read arm, an adapter FILE this process
cannot open included; and each consumer's OWN fault class over the same faults:
`LeadAuthorError` from the resolver (message naming the directory once and carrying `not a
directory this process can read`, the phrase `test_hardening_772` matches on),
`RegistryError` out of the gate, `RosterError` from the audit. The record is a VALUE handed
down, not a handle: the registry takes it (`ModuleVerbRegistry(roster, grant)`), and
`run_investigation` reads it and primes the gate at its own frame before any model call, so
no guard on the document's path can ever meet the fault mid-run. The "one set" claim is
measured, not read off a docstring: over the anomaly fixture every consumer's system set
equals the registry's.

THE INSTRUMENT. Every permission arm is driven as `nobody` in a forked child
(`_roster1035.run_as_nobody`): the local gate runs as root, for whom `chmod` produces no
fault, and a `skipif` would leave these pins unexecuted where they are run most. The child
reports the raised class through its exit code and ships the message, the returned value and
its captured log back over a pipe. Every negative arm has a readable positive control driven
through the SAME child over the SAME tree, so a refusal cannot be blamed on the instrument.

"""
from __future__ import annotations

import ast
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
from defender.runtime import verb_roster, verbs
from defender.runtime.verb_grant import DENY_ALL
from defender.runtime.verb_roster import RosterError, audit_read_surfaces
from defender.runtime.verbs import ModuleVerbRegistry, RegistryError
from defender.skills.invlang.validate import _gating
from defender.scripts import workspace_map
from defender.tests._by_path import import_lint_lib
from defender.tests._declared869 import (
    ADAPTER_BODY,
    ADAPTERS_REL,
    pitfall_row,
    seed_tree,
    write,
)
from defender.tests._declared870 import graveyard_by_id, queue_ids
from defender.tests._roster1035 import (
    EXIT_RAISED_EXPECTED,
    EXIT_RETURNED,
    ChildVerdict,
    handed_to_nobody,
    read_roster,
    run_as_nobody,
)

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
#: of a DIRECTORY named `dir_adapter.py`, of `.hidden_adapter.py`, of the suffix-only
#: `_adapter.py`, of `.._adapter.py`, and of `change-mgmt_adapter.py` (a hyphen in the
#: FILENAME: well-formed, but the seam looks for `change_mgmt_adapter.py`). The first
#: four are #869 J4's; the fifth is the one that makes the two `is_system_name`-only globs
#: (the gate's, the audit's) disagree with the registry TODAY, so the four-consumer equality
#: below is red rather than vacuous.
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


# ---------------------------------------------------------------------------------------
# M1 — the primitive itself
# ---------------------------------------------------------------------------------------


def test_read_roster_accepts_what_dispatches_and_reports_what_it_refused(tmp_path):
    """M1 — `read_roster(d)` over the anomaly fixture answers `.accepted == {"cmdb": <the real
    file, resolved>}` and `.refused` equal to the five anomaly names as a SORTED tuple; it is
    exported in `__all__`; and `ModuleVerbRegistry(read_roster(d), DENY_ALL).systems()` is exactly
    `tuple(sorted(read_roster(d).accepted))` — the registry consumes the record rather than
    keeping a reader of its own.

    The record is a value: its two maps are read-only views, so a consumer holding one
    cannot edit the roster the registry was built over through it."""
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


def test_read_roster_refused_names_are_deduplicated_per_derived_name(tmp_path):
    """M1 — two filenames deriving ONE refused name (`.hid_den_adapter.py` and
    `.hid-den_adapter.py` both derive `.hid-den`, since `_system_of` maps `_` to `-`) are one
    entry in `.refused`, and the tuple stays sorted around it. Today's per-path log loop can
    log one derived name twice, which nothing pins; the record is per NAME, and the resolver's
    one-line-per-refusal log is built from it.

    Observed failing by (today): `ImportError` — the primitive does not exist."""
    adapters = _anomaly_adapters(tmp_path / "adapters")
    write(adapters / ".hid_den_adapter.py", ADAPTER_BODY)
    write(adapters / ".hid-den_adapter.py", ADAPTER_BODY)

    roster = read_roster(adapters)

    assert roster.refused == tuple(sorted(ANOMALY_NAMES | {".hid-den"})), roster.refused
    assert roster.accepted == {"cmdb": (adapters / "cmdb_adapter.py").resolve()}


def test_read_roster_refuses_a_directory_it_cannot_read_naming_it(tmp_path):
    """M1 — the cannot-read arms that need no privilege: an ABSENT directory and a REGULAR
    FILE at the path each raise `RegistryError` naming the path (`os.scandir` raises for both
    where `Path.glob` answers `[]`); a symlink loop named like an adapter, which `Path.resolve`
    spells as `RuntimeError` on 3.11/3.12, is `RegistryError` too, never the untyped raise
    (on 3.13+ the loop entry is dropped and the answer is the control's). The positive control
    is the same call over the readable tree with the loop removed.

    Observed failing by (today): `ImportError` — the primitive does not exist."""
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
    """M1 — the two privilege-dependent arms, driven as `nobody`: mode `0o400` (listable, not
    searchable — the `lstat` guard's own arm) and mode `0o000` (not listable) each raise
    `RegistryError` naming the directory; the SAME child over the SAME tree at `0o755`
    answers `{"cmdb"}`, so the refusals are the mode's and not the instrument's. The
    registry's own 0o400/0o000 pins (`test_1031_roster_snapshot`) are `skipif`-root, so on
    this gate they never run; this one does.

    Observed failing by (today): `ImportError` — the primitive does not exist."""
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

    # The `lstat` guard's OWN arm, which the tree above cannot see: with a well-formed
    # `cmdb_adapter.py` inside, the filter's `is_file` raises `PermissionError` on 3.11
    # and the wrap converts it, so a body with the guard deleted greens the arm above. A
    # directory holding ONLY a shape-refused name never reaches the disk through
    # the filter (`is_system_name` short-circuits first), so without the guard the
    # 0o400 answer is a clean empty roster with `.hidden` refused — the silent shape O1
    # names, on CI's own version. Only the `lstat` can see the missing search bit here.
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


# ---------------------------------------------------------------------------------------
# P1 / P2 — the resolver (O1, O5)
# ---------------------------------------------------------------------------------------


def test_the_resolver_reports_an_unreadable_directory_as_its_own_fault_as_nobody(tmp_path):
    """P1 (O1, O5) — `adapter_systems_under(d)` — the public spelling of `_adapter_names` —
    over a mode-`0o400` directory raises `LeadAuthorError`, never a raw `PermissionError` and
    never an empty set, and over mode `0o000` likewise; each message names the directory and
    carries `not a directory this process can read`, the ONE phrase M2 unifies both cannot-read
    arms onto (`test_hardening_772` matches the absent arm on it). The SAME child over the
    SAME tree at `0o755` answers `{"cmdb"}`. The absent-directory arm needs no privilege and
    is the O5 positive control: it already names the directory with that phrase today.

    Observed failing by (today, 3.11): `PermissionError(13, ...)` out of the `0o400` arm —
    the listing check passes and the filter's `is_file` raises; and the `0o000` arm's
    message reads "is not readable (...)", not the unified phrase."""
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

    # The `lstat` arm through the resolver (see the primitive's own test for why a tree
    # holding only a shape-refused name is the one that discriminates): never `frozenset()`
    # with `.hidden` logged as anomalous — that is a permission fault rendered as a
    # name-shape fault, the silent shape O1 forbids on every version.
    shape_only = root / "shape-only"
    write(shape_only / ".hidden_adapter.py", ADAPTER_BODY)

    def probe_shape_only():
        return declared_systems.adapter_systems_under(shape_only)

    with handed_to_nobody(root, shape_only, 0o400):
        verdict = run_as_nobody(probe_shape_only, expected=LeadAuthorError)
    _expect_raised(verdict, LeadAuthorError)
    assert f"{shape_only} is {CANNOT_READ}" in verdict.message, verdict.describe()


def test_the_resolver_logs_each_refused_name_once_in_sorted_order(tmp_path, capsys):
    """P5 / M2 (O3, O4) — the resolver's per-refusal log is rendered FROM the primitive's
    `refused` tuple, which is per derived NAME, sorted: over the anomaly fixture plus two
    filenames deriving one refused name (`.hid_den_adapter.py`, `.hid-den_adapter.py` ->
    `.hid-den`), `adapter_systems_under(d)` answers `{"cmdb"}` and logs EXACTLY ONE line per
    refused name naming the directory, in sorted-name order. `test_869_resolver` pins that
    each refusal is logged with its directory (P5, kept); this pins the count and the order,
    which is what separates "consumes the primitive's record" from "kept the old per-path
    loop and wrapped its faults" — the two agree on every set and differ only here.

    Also the one structural line in this suite, on the 1031 D4 precedent that absence is the
    claim: the three names M2 says stop being imported into `declared_systems`
    (`ADAPTER_SUFFIX`, `_system_of`, `_adapter_path_under`) are gone from it. `is_system_name`
    stays — the marker half screens on it.

    Observed failing by (today): `.hid-den` refused on TWO lines (one per path)."""
    adapters = _anomaly_adapters(tmp_path / "adapters")
    write(adapters / ".hid_den_adapter.py", ADAPTER_BODY)
    write(adapters / ".hid-den_adapter.py", ADAPTER_BODY)
    refused = sorted(ANOMALY_NAMES | {".hid-den"})

    capsys.readouterr()
    assert declared_systems.adapter_systems_under(adapters) == frozenset({"cmdb"})
    lines = capsys.readouterr().err.splitlines()

    first_line_of: dict[str, int] = {}
    for name in refused:
        hits = [i for i, ln in enumerate(lines) if repr(name) in ln and str(adapters) in ln]
        assert len(hits) == 1, (
            f"{name!r} is refused on {len(hits)} line(s) naming the directory, not one: {lines}"
        )
        first_line_of[name] = hits[0]
    assert [first_line_of[n] for n in refused] == sorted(first_line_of.values()), (
        f"the refusals are not logged in sorted-name order: {lines}"
    )

    for name in ("ADAPTER_SUFFIX", "_system_of", "_adapter_path_under"):
        assert not hasattr(declared_systems, name), (
            f"declared_systems still imports {name}: a second roster reader survives there"
        )


#: What a directory read looks like in source, by ORIGIN: a call whose callee resolves
#: (through `_astlib`, the gates' own scope-aware resolver) to one of these module-level
#: functions — however the module spelled it (`os.scandir(...)`, `from os import scandir`,
#: `import os as _o; _o.listdir(...)`) — or a duck-typed method call by one of these names
#: on a value (`adapters_dir.glob(...)`, `Path(...).iterdir()`), which `_astlib` deliberately
#: leaves unresolved and which is therefore matched on the attribute.
_DIRECTORY_READ_ORIGINS = frozenset({"os.scandir", "os.listdir", "glob.glob", "glob.iglob"})
_DIRECTORY_READ_METHODS = frozenset({"scandir", "glob", "rglob", "iterdir", "listdir"})
#: The names only the primitive may reach: its private filter helpers and the suffix a
#: re-spelled adapters glob would have to name.
_PRIMITIVE_ONLY = frozenset({"_adapter_path_under", "_system_of", "ADAPTER_SUFFIX"})


def _names_in(node: ast.AST) -> set[str]:
    return {
        n.id if isinstance(n, ast.Name) else n.attr
        for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute))
    }


def _mentions_adapters(call: ast.Call) -> bool:
    """Does this directory read touch the ADAPTERS tree — a receiver or argument named for
    it, a string constant carrying the adapter suffix, or the suffix constant itself?"""
    for n in ast.walk(call):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "_adapter" in n.value:
            return True
    return any("adapter" in name.lower() for name in _names_in(call))


def _is_directory_read(call: ast.Call, env) -> bool:
    astlib = import_lint_lib("_astlib")
    resolved = astlib.callee(call, env)
    if resolved is not None:
        return resolved in _DIRECTORY_READ_ORIGINS
    return isinstance(call.func, ast.Attribute) and call.func.attr in _DIRECTORY_READ_METHODS


def _roster_reads_in(module, *, any_directory: bool) -> list[str]:
    """Every roster read in `module`'s source, as `line: text` — callees resolved through
    `_astlib.callee` against the scope each call sits in, so an aliased or `from`-imported
    `scandir` is seen the same as `os.scandir`, where a spelling match is not. With
    `any_directory`, EVERY directory read counts; without it, only one that mentions the
    adapters tree (the audit legitimately globs the skills tree for its read surfaces)."""
    astlib = import_lint_lib("_astlib")
    source = Path(module.__file__).read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source)
    env = astlib.module_env(tree)
    hits: list[str] = []
    for node in ast.walk(tree):
        hit = False
        if isinstance(node, ast.Call):
            hit = _is_directory_read(node, env) and (any_directory or _mentions_adapters(node))
        elif isinstance(node, (ast.Name, ast.Attribute)):
            hit = bool(_names_in(node) & _PRIMITIVE_ONLY)
        elif isinstance(node, ast.ImportFrom):
            hit = any(alias.name in _PRIMITIVE_ONLY for alias in node.names)
        if hit:
            hits.append(f"{node.lineno}: {lines[node.lineno - 1].strip()}")
    return sorted(set(hits))


def test_no_consumer_reads_the_directory_itself():
    """O4, by construction and MEASURED rather than trusted to the anomaly fixture — which
    cannot tell one reader from five that agree on it. Each consumer module of the roster
    (`declared_systems`, the invlang gate, the read-surface audit) contains NO directory read
    (`scandir`/`glob`/`iterdir`/`listdir` call) and NO reference to the primitive's private
    filter helpers, however it spells the import; and the registry has no `_read_roster` of
    its own left to consume instead of the primitive. The positive control is the primitive's
    own module, which DOES read the directory — so the detector would fire on a reader that
    moved rather than went.

    The workspace map joins the consumer list: it used to list `*_adapter.py` filenames off
    its own `iterdir`, and now renders the roster's systems handed to it.

    Observed failing by (today): `declared_systems` globs and calls `_adapter_path`; the
    gate and the audit each glob and call `_system_of`; the registry has `_read_roster`."""
    for module, any_directory in (
        (declared_systems, True), (_gating, True), (verb_roster, False), (workspace_map, False),
    ):
        hits = _roster_reads_in(module, any_directory=any_directory)
        assert not hits, f"{module.__name__} still reads the adapters directory itself: {hits}"
    assert not hasattr(ModuleVerbRegistry, "_read_roster"), (
        "the registry kept its own roster read beside the primitive"
    )
    assert any("scandir" in hit for hit in _roster_reads_in(verbs, any_directory=False)), (
        "the detector sees no adapters-directory read even in the primitive's own module"
    )


def test_a_symlink_loop_named_like_an_adapter_never_escapes_the_resolver_untyped(tmp_path):
    """P2 (O1) — over a tree holding a real `cmdb_adapter.py` and `loop_adapter.py -> itself`,
    `adapter_systems_under(d)` either raises `LeadAuthorError` naming the directory or returns
    EXACTLY `{"cmdb"}` — never a `RuntimeError` (3.11/3.12's spelling of ELOOP out of
    `Path.resolve`), never an empty set. The disjunction is deliberate: 3.11 raises and 3.13+
    drops the loop entry, and the pin is "no untyped escape", not one version's answer. The
    `cmdb` control inside the return arm is what stops a `return frozenset()` from greening
    it; the same tree with the loop removed answers `{"cmdb"}` on every version.

    Observed failing by (today, 3.11): `RuntimeError("Symlink loop from ...")`."""
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


# ---------------------------------------------------------------------------------------
# P4 — the drain seam (O2)
# ---------------------------------------------------------------------------------------


def test_an_unsearchable_adapters_directory_is_not_a_successful_pitfalls_tick(
    tmp_path, monkeypatch,
):
    """P4 (O2) — the `0o400` twin of `test_a_resolver_failure_is_not_a_successful_tick`,
    driven as `nobody` through the REAL drain seam: `drains._invoke_pitfalls(paths)` over a
    tree whose adapters directory is listable but not searchable RAISES `LeadAuthorError`
    whose message is the RESOLVER's ("… is not a directory this process can read"), rather
    than returning rc 0; the swallow's "(continuing)" line never appears; the two queued rows
    are still queued and nothing is stamped consumed.

    The message assertion is load-bearing: a resolver that swallowed the `PermissionError`
    into an empty set would ALSO end in `LeadAuthorError` here — the curator's own "declares
    no systems" refusal — with the queue equally untouched, so exit code and queue state alone
    cannot tell the fix from that mutant. The positive control is the same drive, same child,
    same tree at `0o755`: the tick gets past the resolver, finds the `mcpsys` rows name no
    declared system, and rotates them out (rc 0, queue empty) — so the negative arm's refusal
    is the mode's. The rows name `mcpsys` so that no arm can reach a live curator spawn.

    The state directory lives UNDER the repo (gitignored `state/`), because the child must
    own it to take the queue's append lock.

    Observed failing by (today, 3.11): rc 0 returned, `pitfalls_curator crashed:
    PermissionError(13, 'Permission denied') (continuing)` logged, rows still 2 — a green
    tick over a stalled queue, on every tick."""
    assert not issubclass(LeadAuthorError, OSError)
    # Imported in the PARENT (above) so the forked child inherits it: `_run_curator_module`
    # imports the curator lazily, and a child that has dropped to `nobody` may not be able to
    # read the checkout — a `ModuleNotFoundError` there would be a setup failure wearing the
    # "raised something other" verdict.
    assert drains._CURATOR_MODULES["pitfalls_curator"] == pitfalls_curator.__name__
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")
    repo = seed_tree(tmp_path, adapters=("cmdb",), markers=("elastic",), skills=("elastic",),
                     catalog=())
    adapters = _repo_adapters(repo)
    paths = LoopPaths(repo_root=repo, state_dir=repo / "state")
    persist.append_pitfalls(
        [pitfall_row("r:l-000:0", "mcpsys"), pitfall_row("r:l-001:0", "mcpsys")], paths=paths,
    )
    assert len(persist.read_pitfalls(paths)) == 2

    def probe():
        return drains._invoke_pitfalls(paths, on_curated=lambda _d: None)

    with handed_to_nobody(repo, adapters, 0o400):
        verdict = run_as_nobody(probe, expected=LeadAuthorError)
    _expect_raised(verdict, LeadAuthorError)
    assert f"{adapters} is {CANNOT_READ}" in verdict.message, (
        f"the raise is not the resolver's own refusal; {verdict.describe()}"
    )
    assert CONTINUING not in verdict.log, f"the drain seam swallowed the fault: {verdict.log!r}"
    assert len(persist.read_pitfalls(paths)) == 2, "the queue was rotated on a failed tick"
    assert not paths.pitfalls.consumed.exists(), "rows were stamped consumed on a failed tick"

    with handed_to_nobody(repo, adapters, 0o755):
        control = run_as_nobody(probe, expected=LeadAuthorError)
    _expect_returned(control, 0)
    assert CONTINUING not in control.log, control.log
    assert CANNOT_READ not in control.log, control.log
    assert persist.read_pitfalls(paths) == [], (
        "the readable control did not get past the resolver to rotate the unattributable rows"
    )


# ---------------------------------------------------------------------------------------
# P6 — the `nothing-to-try` gate (O6)
# ---------------------------------------------------------------------------------------
#
# The gate does not READ. It HOLDS the roster the process's composition root read
# (`hold_capabilities`), and answers from that value or refuses to answer at all. So "never
# answers from a roster it could not read" holds by construction — there is no read in the
# gate to fail — and what is pinned instead is the two halves of that construction: an unheld
# gate raises rather than answering (P6a), and the composition root reads the checkout's
# roster at the run's own frame, once, reusing the run's read when the run's tree IS the
# checkout (P6b) and raising `RegistryError` naming the checkout's directory when it cannot
# be read (P6c, and the whole-run drive in P9).


def _redirect_repo_root(monkeypatch, root: Path) -> None:
    """Point the checkout at `root`. `_adapters_at_run_start` reads `_git.REPO_ROOT` at call
    time to find the checkout's adapters directory, so the module constant is the address
    to redirect."""
    monkeypatch.setattr(_git, "REPO_ROOT", root)  # lint-monkeypatch: ok — a module constant read at call time; the checkout root has no other seam


def test_the_nothing_to_try_gate_never_answers_without_a_held_roster(tmp_path):
    """P6a (O6) — `_capability_exists("cmdb")` with no roster held raises
    `CapabilitiesNotRead` rather than answering `False` (under which EVERY `cap` "does not
    exist" and every `nothing-to-try` receipt pays) and rather than reading the tree for
    itself (which was the lazy `lru_cache` this replaces: whichever guard on the document's
    path asked first caught the host's fault and re-filed it as the document's). Positive
    control: the same question, with a roster read over a readable tree held, answers —
    `cmdb` and `cmdb.query` exist, `nosuch` and `cmdb.nosuch` do not. And the holder is
    nominally typed: a `verbs` map or a path handed to it is a `TypeError`, so a caller that
    still spells the read for itself cannot slip its result in.

    Observed failing by (today): `False` returned over an unreadable checkout."""
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


def test_the_run_hands_the_gate_its_own_roster_when_the_run_tree_is_the_checkout(
    tmp_path, monkeypatch,
):
    """P6b (O6) — with `REPO_ROOT` and the run's `defender_dir` naming ONE tree (production's
    shape: `run.py` passes `DEFENDER_DIR`), `_adapters_at_run_start` reads the tree once and
    the roster the gate holds IS the roster the run's registry was built over — identity,
    not agreement — so the tree is read once per process and the two cannot disagree. With
    the two naming DIFFERENT trees (the hermetic suite's shape), the gate holds a roster
    read over the CHECKOUT's, and the run's registry one over the run's."""
    at_run_start = _run_start()
    root = tmp_path / "tree"
    adapters = _repo_adapters(root)
    write(adapters / "cmdb_adapter.py", QUERY_ADAPTER)
    _redirect_repo_root(monkeypatch, root)

    # A registry is injected (any value; it is never called here) so the gather grant's
    # load check is not run against a fixture that declares one verb of one system.
    injected = object()
    _gating.release_capabilities()
    roster, registry = at_run_start(root / "defender", None, injected,
                                    _tenants1106.playground_run_tenant())
    assert registry is injected
    assert _gating.known_capabilities() is roster.verbs, (
        "the run's tree is the checkout, and the gate holds a second read of it"
    )
    assert set(_gating.known_capabilities()) == {"cmdb"}

    other = tmp_path / "other"
    write(_repo_adapters(other) / "elastic_adapter.py", QUERY_ADAPTER)
    _gating.release_capabilities()
    roster, _ = at_run_start(other / "defender", None, injected,
                             _tenants1106.playground_run_tenant())
    assert set(roster.accepted) == {"elastic"}, "the run's registry is not over the run's tree"
    assert set(_gating.known_capabilities()) == {"cmdb"}, (
        "the gate is not priced against the CHECKOUT's roster"
    )


def test_the_run_refuses_an_absent_checkout_adapters_directory_at_its_own_frame(
    tmp_path, monkeypatch,
):
    """P6c (O6), the absent arm — the directory is the process's OWN checkout's, and
    "absent" is a fault there, not an empty roster. Over a repo root with no
    `defender/scripts/adapters`, `_adapters_at_run_start` (the run's tree readable) raises
    `RegistryError` naming the checkout's directory, and the gate is left holding NOTHING —
    not the previous roster, not `{}`. Needs no privilege.

    Observed failing by (today): `False` returned from `_capability_exists`."""
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
        at_run_start(run_tree / "defender", None, object(), _tenants1106.playground_run_tenant())
    assert str(adapters) in str(exc.value), f"does not name the directory: {exc.value}"
    with pytest.raises(_gating.CapabilitiesNotRead):
        _gating._capability_exists("cmdb")


# ---------------------------------------------------------------------------------------
# P7 — the read-surface audit (O7)
# ---------------------------------------------------------------------------------------


def _audit_tree(root: Path, *, skill_body: str) -> Path:
    """`<root>/defender` with one `cmdb` adapter declaring `query` and one `cmdb` SKILL.md —
    the minimal tree `audit_read_surfaces` scans."""
    tree = root / "defender"
    write(tree / "scripts" / "adapters" / "cmdb_adapter.py", QUERY_ADAPTER)
    write(tree / "skills" / "cmdb" / "SKILL.md", f"---\nname: cmdb\n---\n\n{skill_body}\n")
    return tree


def test_the_read_surface_audit_never_reports_a_tree_it_could_not_read_as_clean(tmp_path):
    """P7 (O7) — `audit_read_surfaces(tree, {})` over a mode-`0o000` adapters directory
    raises `RosterError` naming it, rather than reporting the tree clean (`()`); over
    mode `0o400` likewise, rather than leaking `PermissionError`. Both as `nobody`. Positive
    controls, root and `nobody` alike over the readable tree: a SKILL.md advertising
    `cmdb.query` under an empty grant map is ONE hit naming that file (the audit demonstrably
    read the roster it scored the prose against), and a clean SKILL.md is `()`.

    Observed failing by (today, 3.11): `()` over `0o000` — `Path.glob` swallows the
    `PermissionError` and the audit finds no systems and no offence; `PermissionError` over
    `0o400` out of `declared_verb_names`' `is_file`."""
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
    """P7 (O7), the absent arm — `audit_read_surfaces(<tree>/nowhere, {})` raises
    `RosterError` naming the missing adapters directory, matching `generate_roster`'s own
    "does not exist — refusing" posture for an absent tree; the `if adapters_dir.is_dir()
    else []` branch goes. Needs no privilege. The positive control is the readable clean tree.

    Observed failing by (today): `()` — the tree reported clean."""
    tree = _audit_tree(tmp_path, skill_body="nothing advertised here")
    assert audit_read_surfaces(tree, {}) == ()

    nowhere = tree / "nowhere"
    assert not nowhere.exists()
    with pytest.raises(RosterError) as exc:
        audit_read_surfaces(nowhere, {})
    assert str(nowhere / "scripts" / "adapters") in str(exc.value), (
        f"does not name the missing adapters directory: {exc.value}"
    )


# ---------------------------------------------------------------------------------------
# P3 / P8 — one set, measured (O4)
# ---------------------------------------------------------------------------------------


def test_every_consumer_declares_the_registrys_set_over_the_anomaly_fixture(
    tmp_path, capsys,
):
    """P3 / P8 (O4) — over the anomaly fixture the registry declares exactly `("cmdb",)`,
    and each consumer's system set is that set: the resolver's `adapter_systems_under(d)`
    (P3) and the `nothing-to-try` gate's `known_capabilities()` keys once it holds the
    roster read over the fixture (P8), with the gate's per-name answers as the observable — `cmdb` exists,
    `change-mgmt` and `dir` do NOT, though today both "exist" because the gate's
    `is_system_name`-only glob admits a name the dispatch seam cannot resolve. The audit's
    system set is NOT measured here, and the docstring says why: its only observable is the
    hit list, and a name it admits with no resolvable adapter declares no verbs and so can
    never produce a hit — on this fixture the audit's set is behaviourally invisible, and its
    consumption of the primitive is pinned by its fault arms (P7) instead.

    The resolver still logs one line per refused name naming the directory, which
    `test_869_resolver` pins per line; asserted here only as "one line per anomaly name" so
    a consolidation that kept the set and dropped the log is caught by two suites, not one.

    Observed failing by (today): the gate's set is `{"change-mgmt", "cmdb", "dir"}`, and
    `_capability_exists("change-mgmt")` is True."""
    root = tmp_path / "tree"
    adapters = _anomaly_adapters(_repo_adapters(root))
    capsys.readouterr()
    expected = ModuleVerbRegistry(read_roster(adapters), DENY_ALL).systems()
    assert expected == ("cmdb",), "the anchor is not the filtered roster, so the equalities are vacuous"
    assert read_roster(adapters).refused == tuple(sorted(ANOMALY_NAMES))
    # `refused` is DATA, rendered by the resolver alone (the design's stated non-obligation:
    # the registry does not start logging). A primitive that printed the resolver's line
    # itself would green the per-line pins below while every registry construction — the
    # scaffold rules, the skill-description hook, every `VerbResolver` — logged refusals its
    # callers never asked for.
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


# ---------------------------------------------------------------------------------------
# P9 — loud one frame up: the guard above each consumer does not re-file the fault
# ---------------------------------------------------------------------------------------
#
# P4, P6 and the close's own tests pin what each consumer RAISES. These pin what the frame
# ABOVE each consumer does with that raise, because every one of them sits under a guard that
# was written for the document's or the batch's own faults and would otherwise re-file a tree
# this process cannot read as one of those: the drain's dead-letter guard bumps every queued
# row's lifetime `attempts`; the close's price wrap tells the model to "repair the document";
# the write gate's fail-closed wrap refuses the write with "simplify the invlang". Under each,
# the operator never sees the directory named as the cause, and the run or the queue pays.
#
# The runtime's guards are not taught the fault one by one. The roster is read ONCE, at
# `run_investigation`'s own frame, before the budget opens or any model exists — the run's
# tree for the registry and the catalogs, the checkout's for the `nothing-to-try` gate — so
# the read that can fail fails there, and a guard on the document's path only ever meets the
# cached value. `test_the_run_reads_the_roster_before_any_model_call` pins the frame;
# `test_no_guard_on_the_documents_path_names_the_fault` pins that the per-guard arms are gone
# rather than merely redundant.


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
        [pitfall_row("r:l-000:0", "mcpsys"), pitfall_row("r:l-001:0", "mcpsys")], paths=paths,
    )
    assert queue_ids(paths) == ["r:l-000:0", "r:l-001:0"]
    return repo, paths


def test_the_pitfalls_drain_does_not_spend_the_queue_on_an_unreadable_adapters_tree(
    tmp_path, monkeypatch,
):
    """P9, the drain — `_drain_pitfalls(paths, _invoke_pitfalls)` over a repo whose adapters
    directory is ABSENT raises the resolver's fault out of the tick, and the queue is exactly
    as it was: both rows still queued, neither row's `attempts` bumped, nothing in the
    graveyard. The ceiling is set to ONE attempt so that a guard which still treats the fault
    as a batch failure retires both rows on this single tick and the loss is visible here,
    not after `author_max_attempts()` ticks nobody drives.

    The fault is systemic (`SYSTEMIC_FAULTS`), so `run_or_dead_letter` re-raises it and
    `_run_stage` renders it as `[loop] FATAL:` + exit 2 — "fix the deployment", which is what
    a checkout with no readable adapters directory is. The positive control is the same drive
    over the readable tree: the tick gets past the resolver, finds the rows name no declared
    system, and rotates them out.

    Observed failing by (today): `LeadAuthorError` swallowed by the dead-letter guard; both
    rows retired to the graveyard as `batch-error:LeadAuthorError` on the first tick."""
    repo, paths = _seed_pitfalls_queue(tmp_path, monkeypatch)
    adapters = _repo_adapters(repo)
    shutil.rmtree(adapters)

    with pytest.raises(LeadAuthorError) as exc:
        drains._drain_pitfalls(paths, drains._invoke_pitfalls)
    assert f"{adapters} is {CANNOT_READ}" in str(exc.value), (
        f"the raise is not the resolver's own refusal: {exc.value}"
    )
    assert isinstance(exc.value, SYSTEMIC_FAULTS), (
        "the resolver's fault is not systemic, so `run_or_dead_letter` files it as the "
        "batch's own failure"
    )
    assert queue_ids(paths) == ["r:l-000:0", "r:l-001:0"], "the queue was spent on a host fault"
    assert all(int(r.get("attempts") or 0) == 0 for r in persist.read_pitfalls(paths)), (
        "a queued row's lifetime `attempts` was bumped for a tree this process cannot read"
    )
    assert graveyard_by_id(paths) == {}, "rows were retired for a host fault"

    # The tick's own `finally` (`_discard_worktree_changes`: `reset --hard` + `clean`) has
    # already put the committed adapters directory back, so the control needs no rebuild.
    assert (adapters / "cmdb_adapter.py").is_file()
    drains._drain_pitfalls(paths, drains._invoke_pitfalls)
    assert queue_ids(paths) == [], (
        "the readable control did not get past the resolver to rotate the unattributable rows"
    )


def _never_called(messages, info):  # pragma: no cover — reached only by a regressed run
    raise AssertionError("the model was called before the roster was read")


def test_the_run_reads_the_roster_before_any_model_call(tmp_path, monkeypatch):
    """P9, the run — `run_investigation` over a checkout whose adapters directory this process
    cannot read raises `RegistryError` naming the directory OUT of its own frame: before the
    budget file opens (`budget.json` is absent from the run dir afterwards), before the wire
    log opens, and before any model is asked anything (the injected main model raises if it
    is ever called). The run's OWN tree is the readable real checkout here; it is the
    CHECKOUT roster the `nothing-to-try` gate reads that is pointed at a repo root with no
    adapters directory — the one arm of the price that reads a roster at all — so what is
    pinned is that the gate is primed at run start and not on the first close.

    Never a `ModelRetry` out of the close, never a `Decision(False)` out of the write gate,
    never `()` out of the repair window: none of those frames is reached. Before this, the
    first of them to run read the roster lazily under its own guard and re-filed the host's
    fault as the document's."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import GOLDEN_AB3, drive, materialize

    root = tmp_path / "tree"
    root.mkdir()
    assert not _repo_adapters(root).exists()
    _redirect_repo_root(monkeypatch, root)
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3)
    with pytest.raises(RegistryError) as exc:
        drive(run_dir, run_id="r-1035", main=_never_called)
    assert str(_repo_adapters(root)) in str(exc.value), exc.value
    assert not (run_dir / "budget.json").exists(), "the budget opened before the roster was read"
    assert not (run_dir / "wire_logs").exists(), "the wire log opened before the roster was read"


def test_an_unreadable_adapter_file_is_the_hosts_fault_not_an_empty_declaration(tmp_path):
    """M1, one level down — an adapter FILE this process cannot open is the same fault as a
    directory it cannot list, and `read_roster` raises `RegistryError` naming the directory
    for it, as `nobody` over a mode-`0o000` `cmdb_adapter.py`. It used to be swallowed one
    reader down: the directory listed fine (`stat` needs no read bit), the roster accepted
    `cmdb`, and the cold verb read answered `frozenset()` — "declares no verbs" — under which
    a `nothing-to-try cap=cmdb.query` receipt PAID, the audit scored no `cmdb` verb, and the
    registry refused the shipped grant as a `GrantError` naming verbs "the adapters do not
    declare": a host fault re-filed as a grant fault. Positive control through the same
    child over the readable file: `{"cmdb": {"query"}}`."""
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
    """M1, the CONTENT arm — an adapter file this process CAN read but whose bytes do not
    parse is neither the host's fault nor "declares no verbs" with nothing said: the roster
    accepts the system, its `verbs` are empty, and `unparsed` carries the parser's reason
    against its name. Three shapes, none of which may escape `read_roster` as anything: a
    Latin-1 byte inside a string literal (the earlier shape decoded the file as UTF-8 first,
    and `UnicodeDecodeError` — a `ValueError`, neither `OSError` nor `SyntaxError` nor
    `RuntimeError` — left every consumer untyped), a null byte, and an unbalanced literal.

    Two more adapters PARSE, and the pin is that the cold reader agrees with the IMPORTER
    about them, since `ModuleVerbRegistry.verbs()` is an import: a `# coding: latin-1` line
    over the same byte, and — the surprise — the same byte in a COMMENT with no declaration,
    which `python file.py` refuses but `compile(bytes)` and the import system accept. A
    reader that decoded strictly declared nothing for a table the runtime would dispatch.
    Positive control beside them: `cmdb` declares `query`.

    The consequence the registry draws is the one it always drew — an adapter that declares
    nothing fails a grant naming its verbs as `GrantError` — but the census lint can now
    tell that arm from an annotated-assignment table, because the reason is on the record."""
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


def test_no_guard_on_the_documents_path_names_the_fault():
    """P9, structural, on the 1031 D4 precedent that absence is the claim — the five
    `except RegistryError: raise` arms that once sat on the document path's guards (the
    write gate's fail-closed wrap, the close's structure check, the close's price wrap, the
    two prepare-time readers) are GONE, not kept as belt and braces: an arm that stays is an
    arm every future guard on that path must remember to copy, and two sibling guards were
    missed the first time for exactly that reason. The fault is closed one frame up instead,
    by the read happening before any of these frames exists. Resolved through `_astlib`, so
    an aliased import of the class is seen the same as a direct one."""
    from defender import _artifact_schema
    from defender.runtime import close_tool
    from defender.runtime.tools import _document

    astlib = import_lint_lib("_astlib")
    for module in (_artifact_schema, close_tool, _document):
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        env = astlib.module_env(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or node.type is None:
                continue
            named = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
            for expr in named:
                origin = astlib.origin(expr, env)
                assert origin != "defender.runtime.verbs.RegistryError", (
                    f"{module.__name__}:{node.lineno} still carries a per-guard "
                    f"`RegistryError` arm"
                )
