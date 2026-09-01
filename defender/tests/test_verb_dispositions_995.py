"""#995 — the verb-disposition table: one authored answer for who may call what, total over
the systems that actually exist.

THE DEFECT. `/connect` promises that adding a system needs no shared-file edit. It does need
one: a system absent from the gather grant is connected and mute. Worse than mute — probed
against the base commit, a real declared verb on an ungranted system comes back `UNDECLARED`
with a refusal byte-identical to a typo's, so the maintainer is sent hunting a spelling
mistake in an adapter that is correct.

AND THE GUARD CANNOT FAIL. What looks like it watches the grant compares two hand-written
copies of the same list (`driver/_build.py:GATHER_PAIRS` against
`tests/_verb_authorization_632.py`'s duplicate). That catches the copies drifting. It cannot
catch a system missing from BOTH — which is the reported case.

So the load-bearing tests in this file are the ones that PLANT a system the table does not
mention and demand the gate go red. `test_the_shipped_table_is_total` alone would pass
against the broken world, because the shipped tree is currently complete by luck.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from defender._paths import PATHS
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry, declared_verb_names
from defender.tests._dispositions995 import (
    GATHER_CENSUS,
    JUDGE_CENSUS,
    WITHHELD_CENSUS,
    DispositionError,
    census_gaps,
    dispositions_path,
    grant_for,
    load_dispositions,
    planted_tree,
    plant_system,
    write_table,
)
from defender.tests._repo import HOSTILE_NAMES, plant_named_dirs, seed_repo

REPO_ROOT = PATHS.repo_root
DEFENDER = PATHS.defender_dir
ADAPTERS = DEFENDER / "scripts" / "adapters"

#: A minimal well-formed row, for tests whose subject is some OTHER row's malformation.
OK = {"roles": ["gather"]}


def _walk(defender_dir: Path, systems: tuple[str, ...]) -> dict[str, frozenset[str]]:
    """The walked census as `census_gaps` takes it: system -> declared verb names, read cold.

    Handed the system names explicitly rather than resolved, so a test states which systems
    it planted and the assertion is against that statement.
    """
    adapters = defender_dir / "scripts" / "adapters"
    return {s: declared_verb_names(adapters, s) for s in systems}


# =========================================================================================
# O1 — a connected system is reachable, or the connection fails loudly.
# =========================================================================================

def test_a_planted_system_with_no_disposition_turns_the_gate_red():
    """THE demand. A system declared by both halves the resolver reads, mentioned nowhere in
    the table, is residue — and residue is a finding naming the pair.

    This is the test the base commit's guard cannot express: its census compares the shipped
    grant to a second hand-written copy of the shipped grant, so a system in neither is
    invisible to it. Asserted against the pair this test PLANTED, never against a re-walk."""
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
    assert not gaps.undecided and not gaps.phantom and not gaps.unreasoned, (
        f"a total table must be clean, got undecided={sorted(gaps.undecided)} "
        f"phantom={sorted(gaps.phantom)} unreasoned={sorted(gaps.unreasoned)}"
    )


def test_a_disposition_naming_a_verb_no_adapter_declares_is_a_phantom():
    """Residue in the other direction. A row surviving a deleted verb keeps asserting an
    opinion about something that no longer exists, and the runtime would fail at registry
    construction — the gate should say so first, in CI, naming the pair."""
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


def test_the_shipped_table_is_total_over_the_real_tree():
    """The shipped deployment, checked live. Passes today by luck; after #995 it passes by
    construction, and the tests above are what make the difference observable."""
    from defender.learning.leads.declared_systems import declared_systems

    systems = tuple(sorted(declared_systems(REPO_ROOT)))
    gaps = census_gaps(_walk(DEFENDER, systems), load_dispositions(dispositions_path(DEFENDER)))
    assert not gaps.undecided, f"shipped systems with no disposition: {sorted(gaps.undecided)}"
    assert not gaps.phantom, f"dispositions naming no declared verb: {sorted(gaps.phantom)}"
    assert not gaps.unreasoned, f"withheld with no reason: {sorted(gaps.unreasoned)}"


def test_the_lint_gate_exits_nonzero_on_a_tree_with_residue():
    """The wiring, not the logic. `census_gaps` going red is worth nothing if the CI entry
    point does not propagate it — probed by running the gate as CI runs it, against a planted
    repo whose table is silent about a system that repo declares."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup", "beta": "lookup"})
    write_table(
        repo / "defender" / "knowledge" / "environment" / "verb-grants.yaml",
        {("alpha", "lookup"): OK, ("alpha", "health-check"): OK},
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


def test_the_lint_gate_is_clean_on_the_real_tree():
    """Positive control on the entry point: a gate that exits nonzero unconditionally would
    satisfy the test above."""
    gate = REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"
    proc = subprocess.run(
        [sys.executable, str(gate)], capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"


def test_a_hostile_system_directory_name_does_not_blind_the_gate():
    """A name a filesystem accepts and a naive reader mangles must not silently drop a system
    from the walk — the #869/#908 class. These names are not well-formed system names, so the
    correct behaviour is that they declare nothing; what is forbidden is CRASHING, or
    swallowing the well-formed system planted beside them."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup"})
    plant_named_dirs(repo / "defender" / "skills", HOSTILE_NAMES)
    seed_repo(repo, add="-A", message="hostile")
    from defender.learning.leads.declared_systems import declared_systems

    resolved = declared_systems(repo)
    assert "alpha" in resolved, "a well-formed system beside hostile names must survive"
    assert not (set(HOSTILE_NAMES) & resolved)


# =========================================================================================
# O5 — every withholding is on the record, with a reason.
# =========================================================================================

def test_a_withheld_pair_with_no_reason_is_rejected():
    """The residue list is the gate's own escape hatch: if adding a name to it costs nothing,
    the gate silences itself exactly the way the current guard does. A reason is what makes
    the silence a decision someone has to write down and a reviewer can read."""
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


def test_every_withheld_pair_in_the_shipped_table_carries_a_reason():
    """Live, on the deployment. Checked separately from totality because a table can be total
    and still withhold three verbs for no stated cause."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    withheld = {(r.system, r.verb): r for r in rows if not r.roles}
    assert set(withheld) == set(WITHHELD_CENSUS), (
        "the set of pairs granted to nobody changed; if that is intended, update "
        f"WITHHELD_CENSUS deliberately. got={sorted(withheld)}"
    )
    for pair, row in sorted(withheld.items()):
        assert (row.reason or "").strip(), f"{pair} is withheld with no reason"


# =========================================================================================
# O3 — presence on disk never confers access.
# =========================================================================================

def test_planting_an_adapter_grants_it_nothing():
    """The property the enumeration exists to hold, and the one the 'just derive it from the
    filesystem' repair would destroy. A system declared by both halves, with the table not
    mentioning it, yields zero granted pairs for that system in either role."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup", "intruder": "exfiltrate"})
    table = write_table(
        repo / "defender" / "knowledge" / "environment" / "verb-grants.yaml",
        {("alpha", "lookup"): OK, ("alpha", "health-check"): OK},
    )
    rows = load_dispositions(table)
    for role in ("gather", "judge"):
        granted = {(s, v) for s, v, _ in grant_for(role, rows).entries}
        assert not any(s == "intruder" for s, _ in granted), (
            f"role {role!r} was granted something on a system the table never mentions: "
            f"{sorted(p for p in granted if p[0] == 'intruder')}"
        )


def test_the_grant_is_not_a_function_of_what_is_on_disk():
    """Sharper than the above: the same table over two different trees must project the same
    grant. An implementation that unions the table with the walk — a plausible reading of
    'make it total' — fails here while passing every totality test above."""
    table = write_table(_tmp(), {("alpha", "lookup"): OK, ("alpha", "health-check"): OK})
    rows = load_dispositions(table)
    before = grant_for("gather", rows).entries
    planted_tree(_tmp_dir(), {"alpha": "lookup", "later": "lookup"})
    after = grant_for("gather", load_dispositions(table)).entries
    assert before == after


# =========================================================================================
# Conservation — moving the table out of code changed no permission.
# =========================================================================================

def test_the_projected_gather_grant_is_exactly_the_historical_census():
    """The refactor's whole risk is that it quietly widens or narrows access. Compared against
    a census written independently in `_dispositions995.py` from the grants as they stood
    before the move, not against the file under test."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    granted = {(s, v) for s, v, _ in grant_for("gather", rows).entries}
    assert granted == set(GATHER_CENSUS), (
        f"gained={sorted(granted - GATHER_CENSUS)} lost={sorted(GATHER_CENSUS - granted)}"
    )


def test_the_projected_judge_grant_is_exactly_the_historical_census():
    rows = load_dispositions(dispositions_path(DEFENDER))
    granted = {(s, v) for s, v, _ in grant_for("judge", rows).entries}
    assert granted == set(JUDGE_CENSUS), (
        f"gained={sorted(granted - JUDGE_CENSUS)} lost={sorted(JUDGE_CENSUS - granted)}"
    )


def test_the_shipped_definitions_carry_the_projected_grants():
    """The wiring: the driver's gather definition and the judge's definition must be BUILT
    from the table, not merely accompanied by it. Checked by identity of content against the
    projection, so a leftover hardcoded literal that happens to agree today would still be
    caught the first time the table changes — and is caught now by the phantom/undecided
    gates, which a literal cannot satisfy."""
    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    from defender.runtime.driver import GATHER_DEF

    rows = load_dispositions(dispositions_path(DEFENDER))
    assert set(GATHER_DEF.verb_grant.entries) == set(grant_for("gather", rows).entries)
    assert set(JUDGE_DEF.verb_grant.entries) == set(grant_for("judge", rows).entries)


def test_every_projected_pair_survives_registry_construction():
    """The existing cross-check, still holding after the move: a grant naming a verb no
    adapter declares raises at construction. This is the positive control proving the
    projection produces real pairs rather than an empty grant that trivially passes."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    grant = grant_for("gather", rows)
    assert grant.entries, "an empty grant would pass every phantom check vacuously"
    ModuleVerbRegistry(ADAPTERS, grant)  # raises GrantError if any pair is phantom


def test_all_shipped_dispositions_are_read_class():
    """No shipped verb is granted write. The table has no class field by design — a write
    grant should cost a schema change and its own review — so this pins that the projection
    cannot mint one."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    for role in ("gather", "judge"):
        assert all(k == "r" for _, _, k in grant_for(role, rows).entries)


# =========================================================================================
# M3 — a missing or malformed table fails loud, never silently deny-all.
# =========================================================================================

def test_a_missing_table_raises_rather_than_granting_nothing():
    """An empty grant reports every verb as unknown — probed on the base commit. So a config
    that fails to load and degrades to empty reproduces this issue's exact symptom across the
    whole product, silently. It must raise."""
    with pytest.raises(DispositionError):
        load_dispositions(_tmp_dir() / "absent.yaml")


def test_an_unparseable_table_raises():
    path = _tmp()
    path.write_text("dispositions:\n  cmdb:\n   - [unclosed\n", encoding="utf-8")
    with pytest.raises(DispositionError):
        load_dispositions(path)


def test_a_table_with_no_dispositions_raises():
    """A syntactically valid file granting nothing is indistinguishable, at runtime, from a
    deployment whose config never loaded. Deny-all must be reached by deciding, never by
    parsing something empty."""
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


def test_a_duplicate_pair_raises_rather_than_letting_one_row_win():
    """YAML takes the LAST of two identical keys, silently. For a permission table that is the
    same defect this issue is about: two rows in the file, one honoured, and a reviewer who
    reads both. The parse must refuse rather than pick."""
    path = _tmp()
    path.write_text(
        "dispositions:\n"
        "  cmdb:\n"
        "    get-host: {roles: [gather]}\n"
        "    get-host: {roles: []}\n",
        encoding="utf-8",
    )
    with pytest.raises(DispositionError) as caught:
        load_dispositions(path)
    assert "get-host" in str(caught.value)


def test_a_duplicate_system_block_raises():
    """The same collapse one level up — two `cmdb:` blocks, the second silently replacing the
    first wholesale rather than merging."""
    path = _tmp()
    path.write_text(
        "dispositions:\n"
        "  cmdb:\n    get-host: {roles: [gather]}\n"
        "  cmdb:\n    list-hosts: {roles: [gather]}\n",
        encoding="utf-8",
    )
    with pytest.raises(DispositionError) as caught:
        load_dispositions(path)
    assert "cmdb" in str(caught.value)


# =========================================================================================
# O2 — a refusal names its real reason.
# =========================================================================================

def test_a_declared_verb_on_an_ungranted_system_is_denied_not_unknown():
    """THE onboarding symptom. Before #995 this returned UNDECLARED with wording identical to
    a typo's, sending the maintainer to look for a spelling mistake in a correct adapter."""
    grant = VerbGrant(
        role="gather",
        entries=tuple((s, v, "r") for s, v in GATHER_CENSUS if s != "cmdb"),
    )
    reg = ModuleVerbRegistry(ADAPTERS, grant)
    decision = reg.decide("cmdb", "list-hosts")
    assert decision.outcome == "DENIED", (
        f"a real, declared verb on an ungranted system must be DENIED, got {decision}"
    )


def test_the_ungranted_system_refusal_differs_from_a_typo_refusal():
    """The discriminating half. `DENIED` on its own could be reached by denying everything;
    what O2 demands is that the two cases be TOLD APART in what the caller sees."""
    grant = VerbGrant(
        role="gather",
        entries=tuple((s, v, "r") for s, v in GATHER_CENSUS if s != "cmdb"),
    )
    reg = ModuleVerbRegistry(ADAPTERS, grant)
    real = reg.decide("cmdb", "list-hosts")
    typo = reg.decide("cmdb", "list-hostz")
    assert typo.outcome == "UNDECLARED", "a name no adapter declares stays UNDECLARED"
    assert real.refusal != typo.refusal
    assert real.outcome != typo.outcome


def test_a_withheld_verb_on_a_granted_system_is_still_denied():
    """Unchanged behaviour, pinned so the O2 fix does not reshuffle the existing taxonomy."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    reg = ModuleVerbRegistry(ADAPTERS, grant_for("gather", rows))
    assert reg.decide("cmdb", "list-roles").outcome == "DENIED"


def test_an_unknown_system_entirely_is_still_undeclared():
    """The boundary of the O2 change: a system with no adapter at all must not be reported as
    'denied', which would tell a caller it exists."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    reg = ModuleVerbRegistry(ADAPTERS, grant_for("gather", rows))
    assert reg.decide("nosuchsystem", "anything").outcome == "UNDECLARED"


# =========================================================================================
# M7 — the lint scanner's per-system exclusions are derived, not remembered.
# =========================================================================================

def test_the_shippable_surface_scanner_excludes_every_declared_system():
    """The adjacent instance of the same defect: a hand-kept list of `skills/<system>/` dirs
    that is already stale (seven entries, eight systems) and fails silently because the
    missing name is not a vendor word."""
    sys.path.insert(0, str(REPO_ROOT / "scripts" / "lint"))
    try:
        import lint_shippable_surface as mod
    finally:
        sys.path.pop(0)
    from defender.learning.leads.declared_systems import declared_systems

    excluded = set(mod.excluded_prefixes(REPO_ROOT))
    for system in sorted(declared_systems(REPO_ROOT)):
        assert f"defender/skills/{system}/" in excluded, (
            f"{system} is a declared system whose skill dir the scanner does not exclude"
        )


def test_the_scanner_exclusions_track_a_planted_system():
    """Derived, not merely correct today. A system planted in a synthetic tree must be
    excluded there — which a hand-written tuple cannot do."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup"})
    sys.path.insert(0, str(REPO_ROOT / "scripts" / "lint"))
    try:
        import lint_shippable_surface as mod
    finally:
        sys.path.pop(0)
    assert "defender/skills/alpha/" in set(mod.excluded_prefixes(repo))


# =========================================================================================
# M5 / O4 — the table is read-only on every run path.
# =========================================================================================

def test_no_module_under_defender_writes_the_disposition_table():
    """A writer census. The table's authority rests on every row tracing to a human commit —
    the same provenance argument the tacit-knowledge registry makes (#983) — which a run path
    that could rewrite it would void."""
    rel = "verb-grants.yaml"
    offenders: list[str] = []
    referencing: list[str] = []
    for path in sorted(DEFENDER.rglob("*.py")):
        parts = path.parts
        if ".venv" in parts or "tests" in parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if rel not in text:
            continue
        referencing.append(str(path.relative_to(REPO_ROOT)))
        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            if rel not in line:
                continue
            window = "\n".join(lines[max(0, lineno - 4):lineno + 4])
            if any(w in window for w in ("write_text(", "open(", "w+", '"w"', "'w'")):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{lineno}")

    # NON-VACUITY. Without this the census passes on a tree where nothing mentions the table
    # at all — including the pre-implementation tree, and any implementation that spells the
    # path differently. A scan that found nothing to scan has not cleared anything.
    assert referencing, (
        f"no module under defender/ names {rel} — either the table is not wired up, or it is "
        "spelled differently and this census is looking at nothing"
    )
    assert not offenders, f"a run-path module appears to write the table: {offenders}"


# =========================================================================================
# O6 — the documented onboarding path is complete.
# =========================================================================================

def test_the_connect_skill_names_the_table_as_a_step():
    """The skill's own test step is the one that fails when the edit is missing, so the edit
    has to appear before it."""
    text = (DEFENDER / "skills" / "connect" / "SKILL.md").read_text(encoding="utf-8")
    assert "verb-grants.yaml" in text, "the onboarding skill never mentions the table"


def test_the_connect_lane_permits_the_table_edit():
    """The lane rule is a positive allowlist. Naming the step while the lane still forbids it
    leaves the skill unable to complete the job it documents."""
    text = (DEFENDER / "skills" / "connect" / "SKILL.md").read_text(encoding="utf-8")
    lane = text.split("Stay in your lane", 1)
    assert len(lane) == 2, "the lane rule moved; this test needs re-anchoring"
    clause = lane[1].split("- **", 1)[0]
    assert "verb-grants.yaml" in clause, "the lane rule does not permit the table edit"


def test_the_handbook_no_longer_claims_no_shared_file_is_edited():
    """The false sentence, corrected at its source."""
    text = (
        DEFENDER / "skills" / "handbook" / "content" / "knowledge-and-skills.md"
    ).read_text(encoding="utf-8")
    assert "needs no edit to the loop, the gather subagent, or any shared file" not in text
    assert "verb-grants.yaml" in text, (
        "the handbook should point at the one shared edit rather than deleting the claim"
    )


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
