"""#995 verb-disposition table: one authored answer for who may call what, total over the systems that exist. Planted-system tests demand the census gate go red; the loader fails loud on a malformed or missing table; role grants are projected from the rows; an ungranted system's refusal differs from a typo's."""
from __future__ import annotations

import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from defender._paths import PATHS, adapters_under
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry, read_roster
from defender.tests._dispositions995 import (
    GATHER_CENSUS,
    DispositionError,
    DispositionWarning,
    census_gaps,
    dispositions_path,
    grant_for,
    load_dispositions,
    planted_tree,
    write_table,
)
from defender.tests._repo import HOSTILE_NAMES, plant_named_dirs, seed_repo
from defender.tests import _tenants1106 as T1106

REPO_ROOT = PATHS.repo_root
DEFENDER = PATHS.defender_dir
ADAPTERS = PATHS.adapters_dir
SETTINGS = T1106.FIXTURE_SETTINGS

#: A minimal well-formed row, for tests whose subject is some OTHER row's malformation.
OK = {"roles": ["gather"]}


def _walk(defender_dir: Path, systems: tuple[str, ...]) -> dict[str, frozenset[str]]:
    """The walked census as `census_gaps` takes it: system -> declared verb names, read cold."""
    roster = read_roster(adapters_under(defender_dir))
    return {s: roster.declared_verbs(s) for s in systems}


def test_a_planted_system_with_no_disposition_turns_the_gate_red():
    """THE demand. A system declared by both halves the resolver reads, mentioned nowhere in
    the table, is residue — and residue is a finding naming the pair."""
    planted = ("newsystem", "health-check")
    walked = {"newsystem": frozenset({"lookup", "health-check"})}
    # A table that decides one of the planted system's two verbs and is silent about the
    # other. Both the silence and its exact identity must be reported.
    table = write_table(_tmp(), {("newsystem", "lookup"): OK})
    gaps = census_gaps(walked, load_dispositions(table))
    assert planted[0] in {s for s, _ in gaps.undecided}, \
        "a walked system whose verb the table never mentions must be reported as undecided"
    assert ("newsystem", "health-check") in gaps.undecided, \
        f"the undecided pair must be named, got {sorted(gaps.undecided)}"
    assert not gaps.phantom, "nothing here is a phantom — every row names a walked verb"


def test_the_gate_is_clean_on_a_table_that_decides_every_walked_verb():
    """The positive control on the demand above. Without it, `census_gaps` returning a
    finding for everything would satisfy the red test and be useless."""
    walked = {"newsystem": frozenset({"lookup", "health-check"})}
    table = write_table(_tmp(), {
        ("newsystem", "lookup"): {"roles": ["gather"]},
        ("newsystem", "health-check"): {"roles": ["gather"]},
    })
    gaps = census_gaps(walked, load_dispositions(table))
    assert not gaps.undecided, f"undecided on a total table: {sorted(gaps.undecided)}"
    assert not gaps.phantom, f"phantom on a total table: {sorted(gaps.phantom)}"
    assert not gaps.unreasoned, f"unreasoned on a total table: {sorted(gaps.unreasoned)}"


def test_a_disposition_naming_a_verb_no_adapter_declares_is_a_phantom():
    walked = {"newsystem": frozenset({"lookup", "health-check"})}
    table = write_table(_tmp(), {
        ("newsystem", "lookup"): OK,
        ("newsystem", "health-check"): OK,
        ("newsystem", "removed-verb"): OK,
    })
    gaps = census_gaps(walked, load_dispositions(table))
    assert ("newsystem", "removed-verb") in gaps.phantom
    assert not gaps.undecided


def test_a_whole_system_absent_from_the_table_reports_every_one_of_its_verbs():
    """The reported case, at system granularity. The gate must not stop at "system unknown" —
    the maintainer's next action is to write a row per verb, so every verb is named."""
    walked = {"solo": frozenset({"a", "b", "health-check"})}
    table = write_table(_tmp(), {("other", "x"): OK})
    gaps = census_gaps(walked, load_dispositions(table))
    assert {("solo", "a"), ("solo", "b"), ("solo", "health-check")} <= set(gaps.undecided)


def test_deleting_a_row_from_the_SHIPPED_table_is_caught():
    """A mutation test on the real file, not a synthetic one."""
    from defender.learning.leads.declared_systems import declared_systems

    systems = tuple(sorted(declared_systems(REPO_ROOT)))
    walked = _walk(DEFENDER, systems)
    victim = "host-state"
    deleted = {(victim, v) for v in walked[victim]}

    rows = load_dispositions(dispositions_path(SETTINGS))
    survivors = tuple(r for r in rows if r.system != victim)
    assert len(survivors) < len(rows), "the fixture deleted nothing"

    gaps = census_gaps(walked, survivors)
    assert set(gaps.undecided) == deleted, (
        f"deleting {victim}'s rows must report exactly its verbs as undecided; "
        f"got {sorted(gaps.undecided)}"
    )


def test_a_system_gather_reaches_but_cannot_health_check_warns_on_load():
    """The invariant the move from code to table made merely UNWRITTEN rather than impossible."""
    table = write_table(_tmp(), {
        ("alpha", "lookup"): OK,
        ("alpha", "health-check"): {"roles": [], "reason": "not needed here"},
    })
    with pytest.warns(DispositionWarning) as caught:
        rows = load_dispositions(table)
    assert any("alpha" in str(w.message) for w in caught), \
        f"the warning must name the system, got {[str(w.message) for w in caught]}"
    assert rows, "the table still LOADS — a withheld health-check is not a reason to refuse it"


def test_a_system_gather_does_not_reach_at_all_does_not_warn():
    table = write_table(_tmp(), {
        ("alpha", "lookup"): {"roles": [], "reason": "withheld on purpose"},
        ("alpha", "health-check"): {"roles": [], "reason": "withheld with it"},
    })
    with warnings.catch_warnings():
        warnings.simplefilter("error", DispositionWarning)
        load_dispositions(table)


def test_the_lint_gate_exits_nonzero_on_a_tree_with_residue():
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup", "beta": "lookup"})
    T1106.plant_census_settings(
        repo, {("alpha", "lookup"): OK, ("alpha", "health-check"): OK},
    )
    seed_repo(repo, add="-A", message="table")
    gate = REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"
    proc = subprocess.run(
        [sys.executable, str(gate), "--root", str(repo)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert proc.returncode != 0, (
        f"the gate passed on a tree where 'beta' is declared and undecided\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    assert "beta" in (proc.stdout + proc.stderr), "the failure must name the offending system"


def test_a_hostile_system_directory_name_does_not_blind_the_gate():
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup"})
    plant_named_dirs(repo / "defender" / "skills", HOSTILE_NAMES)
    T1106.plant_census_settings(
        repo, {("alpha", "lookup"): OK, ("alpha", "health-check"): OK},
    )
    seed_repo(repo, add="-A", message="hostile")
    from defender.learning.leads.declared_systems import declared_systems

    resolved = declared_systems(repo)
    assert "alpha" in resolved, "a well-formed system beside hostile names must survive"
    assert not (set(HOSTILE_NAMES) & resolved)

    gate = REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"
    proc = subprocess.run(
        [sys.executable, str(gate), "--root", str(repo)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, (
        "the hostile names declare nothing, so a table total over `alpha` is total — the "
        f"gate must be clean, not red or crashed\nstdout={proc.stdout}\nstderr={proc.stderr}"
    )
    assert "1 system" in proc.stdout, (
        f"the gate covered a system count that is not just `alpha`: {proc.stdout}"
    )


def test_a_withheld_pair_with_no_reason_is_rejected():
    with pytest.raises(DispositionError) as caught:
        load_dispositions(write_table(_tmp(), {("cmdb", "list-roles"): {"roles": []}}))
    assert "list-roles" in str(caught.value), "the refusal must name the offending pair"


@pytest.mark.parametrize("reason", ["", "   ", "\n\t "])
def test_a_blank_reason_does_not_satisfy_the_requirement(reason: str):
    """A reason field present but empty is the cheapest way to defeat the requirement while
    passing a `"reason" in row` check."""
    with pytest.raises(DispositionError):
        load_dispositions(write_table(
            _tmp(), {("cmdb", "list-roles"): {"roles": [], "reason": reason}}
        ))


def test_a_withheld_pair_with_a_reason_loads():
    """Positive control: the requirement is a reason, not a prohibition on withholding."""
    rows = load_dispositions(write_table(_tmp(), {
        ("cmdb", "list-roles"): {"roles": [], "reason": "in the registry, exercised by nothing"},
    }))
    assert len(rows) == 1
    assert rows[0].roles == frozenset()
    assert "exercised" in (rows[0].reason or "")


def test_a_role_outside_the_known_set_raises_rather_than_projecting_nothing():
    """A misspelled role at a CALL SITE is the deny-all-by-accident state, one level up."""
    rows = load_dispositions(dispositions_path(SETTINGS))
    with pytest.raises(DispositionError) as caught:
        grant_for("gathr", rows)
    assert "gathr" in str(caught.value), "the refusal must name the role it was handed"


def test_the_grant_is_not_a_function_of_what_is_on_disk():
    table = write_table(_tmp(), {("alpha", "lookup"): OK, ("alpha", "health-check"): OK})
    rows = load_dispositions(table)
    before = grant_for("gather", rows).entries
    planted_tree(_tmp_dir(), {"alpha": "lookup", "later": "lookup"})
    after = grant_for("gather", load_dispositions(table)).entries
    assert before == after


@pytest.mark.parametrize("role", ["gather", "lead-zero-correlation"])
def test_the_projection_is_exactly_the_rows_that_name_the_role(role: str):
    """The total statement of "authored, not derived", in one line per holder."""
    rows = load_dispositions(dispositions_path(SETTINGS))
    assert {(s, v) for s, v, _ in grant_for(role, rows).entries} == \
        {(r.system, r.verb) for r in rows if role in r.roles}


def test_the_shipped_definitions_carry_the_projected_grants():
    # #1106 M4: the grants are per RUN, projected from the run's tenant table — no longer
    # module constants on `GATHER_DEF` / `lead_zero`. The wiring is `run_grants`.
    grants = T1106.run_grants(SETTINGS)
    rows = load_dispositions(dispositions_path(SETTINGS))
    assert set(grants.gather.entries) == set(grant_for("gather", rows).entries)
    # The second grant the table projects (#999): the turn-zero correlation lead's.
    assert set(grants.correlation.entries) == set(grant_for("lead-zero-correlation", rows).entries)


def test_every_projected_pair_survives_registry_construction():
    rows = load_dispositions(dispositions_path(SETTINGS))
    grant = grant_for("gather", rows)
    assert grant.entries, "an empty grant would pass every phantom check vacuously"
    ModuleVerbRegistry(read_roster(ADAPTERS), grant)  # raises GrantError if any pair is phantom


def test_a_missing_table_raises_rather_than_granting_nothing():
    with pytest.raises(DispositionError):
        load_dispositions(_tmp_dir() / "absent.yaml")


def test_an_unparseable_table_raises():
    path = _tmp()
    path.write_text("dispositions:\n  cmdb:\n   - [unclosed\n", encoding="utf-8")
    with pytest.raises(DispositionError):
        load_dispositions(path)


def test_a_table_with_no_dispositions_raises():
    for text in ("dispositions: {}\n", "dispositions:\n", "{}\n", ""):
        path = _tmp()
        path.write_text(text, encoding="utf-8")
        with pytest.raises(DispositionError):
            load_dispositions(path)


def test_an_unknown_role_raises_and_names_it():
    """A typo'd role silently grants nothing to the role that was meant — the mute failure
    again, one level down."""
    with pytest.raises(DispositionError) as caught:
        load_dispositions(write_table(_tmp(), {("cmdb", "get-host"): {"roles": ["gathr"]}}))
    assert "gathr" in str(caught.value)


def test_a_row_with_no_roles_key_raises():
    """Distinct from `roles: []`. An absent key is an unfinished row, not a withholding, and
    treating it as one would let a half-written table silently withhold."""
    with pytest.raises(DispositionError):
        load_dispositions(write_table(_tmp(), {("cmdb", "get-host"): {"reason": "hm"}}))


def test_a_malformed_system_name_raises():
    path = _tmp()
    path.write_text(
        'dispositions:\n  "Not A System":\n    get-host: {roles: [gather]}\n', encoding="utf-8"
    )
    with pytest.raises(DispositionError):
        load_dispositions(path)


_DUPLICATE_SPELLINGS = {
    "block-4-space": (
        "dispositions:\n"
        "  cmdb:\n"
        "    get-host: {roles: [gather]}\n"
        "    get-host: {roles: []}\n"
    ),
    "block-2-space": (
        "dispositions:\n"
        " cmdb:\n"
        "  get-host: {roles: [gather]}\n"
        "  get-host: {roles: []}\n"
    ),
    "block-6-space": (
        "dispositions:\n"
        "   cmdb:\n"
        "      get-host: {roles: [gather]}\n"
        "      get-host: {roles: []}\n"
    ),
    "flow-verbs": (
        "dispositions:\n"
        "  cmdb: {get-host: {roles: [gather]}, get-host: {roles: []}}\n"
    ),
    "quoted-key": (
        "dispositions:\n"
        "  cmdb:\n"
        '    "get-host": {roles: [gather]}\n'
        "    get-host: {roles: []}\n"
    ),
    "duplicate-system-block": (
        "dispositions:\n"
        "  cmdb:\n    get-host: {roles: [gather]}\n"
        "  cmdb:\n    list-hosts: {roles: [gather]}\n"
    ),
    "duplicate-system-flow": (
        "dispositions: {cmdb: {get-host: {roles: [gather]}}, "
        "cmdb: {list-hosts: {roles: [gather]}}}\n"
    ),
    "merge-key-shadowed": (
        "dispositions:\n"
        "  cmdb:\n"
        "    <<: {get-host: {roles: [gather]}}\n"
        "    get-host: {roles: [judge]}\n"
    ),
}


@pytest.mark.parametrize("spelling", sorted(_DUPLICATE_SPELLINGS))
def test_a_repeated_key_raises_rather_than_letting_one_row_win(spelling: str):
    path = _tmp()
    path.write_text(_DUPLICATE_SPELLINGS[spelling], encoding="utf-8")
    with pytest.raises(DispositionError) as caught:
        load_dispositions(path)
    assert "cmdb" in str(caught.value)


def test_a_key_written_three_times_is_named_once():
    path = _tmp()
    path.write_text(
        "dispositions:\n"
        "  cmdb:\n"
        "    get-host: {roles: [gather]}\n"
        "    get-host: {roles: [judge]}\n"
        "    get-host: {roles: [gather]}\n",
        encoding="utf-8",
    )
    with pytest.raises(DispositionError) as caught:
        load_dispositions(path)
    assert str(caught.value).count("cmdb.get-host") == 1, \
        f"the repeated pair must be named once, got {caught.value}"


def test_the_duplicate_check_agrees_with_an_independent_oracle():
    """The check, cross-examined against a differently-built answer."""
    import yaml

    class _NoDupes(yaml.SafeLoader):
        pass

    def _mapping(loader, node, deep=False):  # noqa: ANN001
        loader.flatten_mapping(node)
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError(f"duplicate key {key!r}")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    _NoDupes.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping,
    )

    for text in [_DUPLICATE_SPELLINGS[k] for k in sorted(_DUPLICATE_SPELLINGS)]:
        with pytest.raises(yaml.YAMLError, match="duplicate key"):
            yaml.load(text, Loader=_NoDupes)  # noqa: S506 — a SafeLoader subclass
        path = _tmp()
        path.write_text(text, encoding="utf-8")
        with pytest.raises(DispositionError):
            load_dispositions(path)

    # And the oracle agrees the SHIPPED table is clean, so the agreement above is not two
    # things both refusing everything.
    yaml.load(
        dispositions_path(SETTINGS).read_text(encoding="utf-8"), Loader=_NoDupes,
    )  # noqa: S506


def test_an_ungranted_systems_real_verb_keeps_the_unresolvable_label():
    """The LABEL is not #995's to change, and this pins that it did not."""
    grant = VerbGrant(
        role="gather",
        entries=tuple((s, v, "r") for s, v in GATHER_CENSUS if s != "cmdb"),
    )
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), grant)
    assert reg.decide("cmdb", "list-hosts").outcome == "UNDECLARED"


def test_the_ungranted_system_refusal_differs_from_a_typo_refusal():
    grant = VerbGrant(
        role="gather",
        entries=tuple((s, v, "r") for s, v in GATHER_CENSUS if s != "cmdb"),
    )
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), grant)
    real = reg.decide("cmdb", "list-hosts")   # declared by the adapter, granted to nobody
    typo = reg.decide("cmdb", "list-hostz")   # declared by nothing

    assert real.outcome == typo.outcome == "UNDECLARED"
    assert real.refusal != typo.refusal, (
        "a declared verb on an ungranted system is still reported exactly like a typo"
    )
    # Named, not merely different: a refusal that differs by a random token would satisfy an
    # inequality while telling the reader nothing.
    assert "verb-grants.yaml" in (real.refusal or ""), (
        "the refusal for an ungranted system should point at the table that fixes it"
    )
    assert "verb-grants.yaml" not in (typo.refusal or ""), (
        "a typo must not be blamed on a missing grant — that sends the reader to the wrong file"
    )
    assert real.refusal.strip() != typo.refusal.strip()
    assert "unknown" not in (real.refusal or ""), (
        "the refusal for a declared verb still calls it unknown"
    )
    assert "unknown" in (typo.refusal or "")


def test_a_typo_on_a_granted_system_is_told_apart_from_a_typo_on_an_ungranted_one():
    """The third case, which the two above do not cover between them: an unreal verb on a
    system the grant DOES reach. It must not borrow the ungranted-system wording either."""
    rows = load_dispositions(dispositions_path(SETTINGS))
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), grant_for("gather", rows))
    near_miss = reg.decide("cmdb", "list-hostz")
    assert near_miss.outcome == "UNDECLARED"
    assert "verb-grants.yaml" not in (near_miss.refusal or "")


def test_a_withheld_verb_on_a_granted_system_is_still_denied():
    """Unchanged behaviour, pinned so the O2 fix does not reshuffle the existing taxonomy."""
    rows = load_dispositions(dispositions_path(SETTINGS))
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), grant_for("gather", rows))
    assert reg.decide("cmdb", "list-roles").outcome == "DENIED"


def test_an_unknown_system_entirely_is_still_undeclared():
    """The boundary of the O2 change: a system with no adapter at all must not be reported as
    'denied', which would tell a caller it exists."""
    rows = load_dispositions(dispositions_path(SETTINGS))
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), grant_for("gather", rows))
    assert reg.decide("nosuchsystem", "anything").outcome == "UNDECLARED"


def test_the_table_loads_from_a_read_only_file():
    src = dispositions_path(SETTINGS).read_bytes()
    ro = _tmp_dir() / "verb-grants.yaml"
    ro.write_bytes(src)
    ro.chmod(0o444)
    try:
        rows = load_dispositions(ro)
        assert rows, "the read-only copy loaded nothing"
        assert grant_for("gather", rows).entries
    finally:
        ro.chmod(0o644)


# --- tmp helpers ---------------------------------------------------------------------

_TMP: list[Path] = []


@pytest.fixture(autouse=True)
def _tmp_root(tmp_path: Path):
    _TMP.clear()
    _TMP.append(tmp_path)
    yield
    _TMP.clear()


def _tmp_dir() -> Path:
    d = _TMP[0] / f"d{len(list(_TMP[0].iterdir()))}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _tmp() -> Path:
    return _tmp_dir() / "table.yaml"
