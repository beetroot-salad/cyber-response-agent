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
import warnings
from pathlib import Path

import pytest

from defender._paths import PATHS, adapters_under
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry, declared_verb_names
from defender.tests._dispositions995 import (
    GATHER_CENSUS,
    JUDGE_CENSUS,
    WITHHELD_CENSUS,
    Disposition,
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

REPO_ROOT = PATHS.repo_root
DEFENDER = PATHS.defender_dir
ADAPTERS = PATHS.adapters_dir

#: A minimal well-formed row, for tests whose subject is some OTHER row's malformation.
OK = {"roles": ["gather"]}


def _walk(defender_dir: Path, systems: tuple[str, ...]) -> dict[str, frozenset[str]]:
    """The walked census as `census_gaps` takes it: system -> declared verb names, read cold.

    Handed the system names explicitly rather than resolved, so a test states which systems
    it planted and the assertion is against that statement.
    """
    return {s: declared_verb_names(adapters_under(defender_dir), s) for s in systems}


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
    assert not gaps.undecided, f"undecided on a total table: {sorted(gaps.undecided)}"
    assert not gaps.phantom, f"phantom on a total table: {sorted(gaps.phantom)}"
    assert not gaps.unreasoned, f"unreasoned on a total table: {sorted(gaps.unreasoned)}"


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


def test_deleting_a_row_from_the_SHIPPED_table_is_caught():
    """A mutation test on the real file, not a synthetic one.

    Every other O1 test builds its table through `write_table`, so all of them are blind to
    anything the shipped table can express and the helper cannot — a top-level key, a
    smuggled attribute on the returned value, a magic marker. An adversarial implementer got
    a fully green suite through exactly that gap: a `residue: settled` key on the real table
    that made `census_gaps` return nothing while the shipped file was missing six verbs.

    So: take the shipped table, delete one system's rows, and demand exactly that system's
    verbs come back. The expectation is the set this test DELETED, never a re-walk."""
    from defender.learning.leads.declared_systems import declared_systems

    systems = tuple(sorted(declared_systems(REPO_ROOT)))
    walked = _walk(DEFENDER, systems)
    victim = "host-state"
    deleted = {(victim, v) for v in walked[victim]}

    rows = load_dispositions(dispositions_path(DEFENDER))
    survivors = tuple(r for r in rows if r.system != victim)
    assert len(survivors) < len(rows), "the fixture deleted nothing"

    gaps = census_gaps(walked, survivors)
    assert set(gaps.undecided) == deleted, (
        f"deleting {victim}'s rows must report exactly its verbs as undecided; "
        f"got {sorted(gaps.undecided)}"
    )


def test_the_census_is_a_function_of_the_row_values_alone():
    """No side channel. `census_gaps` must depend on nothing but the `(system, verb, roles,
    reason)` of each row — not on the type of the container, not on an attribute riding along
    on it, not on a key the loader stashed somewhere.

    Rebuilding every row as a plain `Disposition` in a plain tuple and demanding an identical
    verdict is what makes that testable without enumerating the channels."""
    from defender.learning.leads.declared_systems import declared_systems

    systems = tuple(sorted(declared_systems(REPO_ROOT)))
    walked = _walk(DEFENDER, systems)
    rows = load_dispositions(dispositions_path(DEFENDER))

    assert type(rows) is tuple, (
        f"the loader returned {type(rows).__name__}, not a plain tuple — a subclass can carry "
        "state that the census reads and no test can see"
    )
    rebuilt = tuple(
        Disposition(system=r.system, verb=r.verb, roles=frozenset(r.roles), reason=r.reason)
        for r in rows
    )
    assert census_gaps(walked, rebuilt) == census_gaps(walked, rows)
    # And with one row dropped, the rebuilt copy must go red exactly like the original would.
    assert census_gaps(walked, rebuilt[1:]).undecided == census_gaps(walked, rows[1:]).undecided


def test_an_unreasoned_withholding_is_reported_by_the_census():
    """The negative control on `unreasoned`, which every other test only ever asserts EMPTY.

    Without this the field can be a hardcoded empty set: three tests assert it is empty, the
    gate's branch that prints it is unreachable, and nothing notices. Built by constructing
    the row directly rather than through the loader, because the loader rejects this shape —
    which is correct, and is also why the census's own handling of it would otherwise never
    be exercised."""
    walked = {"x": frozenset({"y"})}
    rows = (Disposition(system="x", verb="y", roles=frozenset(), reason="   "),)
    gaps = census_gaps(walked, rows)
    assert ("x", "y") in gaps.unreasoned
    assert not gaps.undecided, "the row IS present — it is the reason that is missing"


def test_a_system_gather_reaches_but_cannot_health_check_warns_on_load():
    """The invariant the move from code to table made merely UNWRITTEN rather than impossible.

    Before #995 the gather grant was built as `entries += ((s, "health-check", "r") for s in
    systems)` — health-check was appended for every system the grant reached, so "gather can
    query this system but not health-check it" was a state no author could express.

    A WARNING on load, not a CI finding. This file is per-deployment data: the operator who
    edits their own copy is the only person who can author this mistake, and is the one person
    a gate over our repo never reaches. Warning where the table is READ covers every one of
    them."""
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
    """The negative control, and the reason the rule is not "every system grants health-check".

    A system withheld from gather entirely is a legal, reviewed decision; warning on it would
    turn the rule into a complaint that gather does not reach everything."""
    table = write_table(_tmp(), {
        ("alpha", "lookup"): {"roles": [], "reason": "withheld on purpose"},
        ("alpha", "health-check"): {"roles": [], "reason": "withheld with it"},
    })
    with warnings.catch_warnings():
        warnings.simplefilter("error", DispositionWarning)
        load_dispositions(table)


def test_the_shipped_table_loads_without_a_health_check_warning():
    """The real table against the rule. This is the state the code rule used to guarantee."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DispositionWarning)
        load_dispositions(dispositions_path(DEFENDER))


def test_the_census_gate_says_nothing_about_health_check():
    """The rule's ABSENCE from the repo-time gate, pinned.

    A table gather cannot health-check is a warning at every load and NOT a CI finding — the
    gate walks a tree, so it only ever runs here, which is where the mistake cannot be made.
    Re-adding it there would make the shipped repo the only place the rule is enforced."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup"})
    write_table(
        repo / "defender" / "knowledge" / "environment" / "verb-grants.yaml",
        {
            ("alpha", "lookup"): OK,
            ("alpha", "health-check"): {"roles": [], "reason": "not needed here"},
        },
    )
    seed_repo(repo, add="-A", message="table")
    gate = REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"
    proc = subprocess.run(
        [sys.executable, str(gate), "--root", str(repo)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, (
        "the census gate must stay silent on a withheld health-check — that rule lives in the "
        f"loader now\nstdout={proc.stdout}\nstderr={proc.stderr}"
    )


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


def test_the_lint_gate_is_clean_on_the_real_tree_and_says_what_it_covered():
    """Positive control on the entry point — and proof it LOOKED.

    Exit 0 alone is satisfied by a gate that checks nothing, and an adversarial implementer
    shipped exactly that: a no-arg early return reading "shipped tree covered elsewhere", so
    the census ran only under the `--root` the red test supplies and never on the path CI
    uses. The gate must report the size of what it covered, and that number must match the
    tree."""
    from defender.learning.leads.declared_systems import declared_systems

    gate = REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"
    proc = subprocess.run(
        [sys.executable, str(gate)], capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"

    out = proc.stdout + proc.stderr
    rows = load_dispositions(dispositions_path(DEFENDER))
    why = ("the gate reported success without saying what it covered, so it cannot be "
           f"distinguished from one that checked nothing: {out}")
    assert str(len(rows)) in out, why
    assert str(len(declared_systems(REPO_ROOT))) in out, why


def test_the_no_arg_and_explicit_root_invocations_check_the_same_thing():
    """The two entry paths must not diverge. CI runs the gate with no arguments; every red
    test above runs it with `--root`. A gate whose no-arg path is a stub would pass both."""
    gate = REPO_ROOT / "scripts" / "lint" / "lint_verb_disposition_census.py"
    bare = subprocess.run(
        [sys.executable, str(gate)], capture_output=True, text=True, cwd=REPO_ROOT,
    )
    explicit = subprocess.run(
        [sys.executable, str(gate), "--root", str(REPO_ROOT)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert bare.returncode == explicit.returncode
    assert bare.stdout == explicit.stdout


def test_a_hostile_system_directory_name_does_not_blind_the_gate():
    """A name a filesystem accepts and a naive reader mangles must not silently drop a system
    from the walk — the #869/#908 class. These names are not well-formed system names, so the
    correct behaviour is that they declare nothing; what is forbidden is CRASHING, or
    swallowing the well-formed system planted beside them.

    Asserted on the RESOLVER and then on the GATE. The resolver half alone leaves the claim
    in the test's own name unmade: a gate that crashed, or that dropped `alpha` on its way
    from the resolver to the census, would still pass a test that only ever called
    `declared_systems`."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup"})
    plant_named_dirs(repo / "defender" / "skills", HOSTILE_NAMES)
    write_table(
        repo / "defender" / "knowledge" / "environment" / "verb-grants.yaml",
        {("alpha", "lookup"): OK, ("alpha", "health-check"): OK},
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
    # SUBSTANCE, not presence. `.strip()` truthiness is satisfied by `-`, `tbd`, `n/a` — an
    # adversarial implementer shipped exactly those. The reason's only job is to let a
    # reviewer judge whether the withholding still holds, which one token cannot do.
    placeholder = {"tbd", "n/a", "na", "-", "--", "none", "todo", "x", "?", "wip"}
    for pair, row in sorted(withheld.items()):
        reason = (row.reason or "").strip()
        assert reason, f"{pair} is withheld with no reason"
        assert reason.lower().rstrip(".") not in placeholder, \
            f"{pair} is withheld with a placeholder reason {reason!r}"
        assert len(reason.split()) >= 4, \
            f"{pair}'s reason is too short to be reviewable: {reason!r}"


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


def test_a_role_outside_the_known_set_raises_rather_than_projecting_nothing():
    """A misspelled role at a CALL SITE is the deny-all-by-accident state, one level up.

    `load_dispositions` already refuses a typo'd role written in the TABLE. It cannot see the
    role the projection is ASKED for, and an empty grant is indistinguishable at every reader
    from a deliberate withholding: every verb then decides UNDECLARED with "this role holds no
    grant reaching it", which is #995's original symptom applied product-wide."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    with pytest.raises(DispositionError) as caught:
        grant_for("gathr", rows)
    assert "gathr" in str(caught.value), "the refusal must name the role it was handed"


def test_a_known_role_no_row_names_still_projects_an_empty_grant():
    """The other half, and the reason the guard is membership rather than emptiness.

    A role that legitimately appears in no row is a filter matching nothing, not an error —
    the distinction `grant_for`'s docstring draws. Only an unknown NAME is the typo."""
    rows = load_dispositions(write_table(_tmp(), {
        ("alpha", "lookup"): OK, ("alpha", "health-check"): OK,
    }))
    assert grant_for("judge", rows) == VerbGrant(role="judge", entries=())


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


@pytest.mark.parametrize("role", ["gather", "judge"])
def test_the_projection_is_exactly_the_rows_that_name_the_role(role: str):
    """The total statement of "authored, not derived", in one line per role.

    The two tests above vary a temp tree that a synthesizing implementation has no reason to
    read — an adversarial one derived eight of gather's pairs from `PATHS.adapters_dir`, which
    those tests never touch, and passed both. This closes it by construction: the projection
    is a FILTER over the rows and may invent nothing. Anything synthesized, from anywhere,
    breaks the equality."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    assert {(s, v) for s, v, _ in grant_for(role, rows).entries} == \
        {(r.system, r.verb) for r in rows if role in r.roles}


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


#: The same duplicate, written the ways YAML allows it to be written. Parametrized rather than
#: pinned as one string because a line-oriented duplicate check keyed on one indentation and
#: one block style passes the single case and admits every other — an adversarial implementer
#: shipped a regex matching exactly `write_table`'s output, and flow style, 3-space and
#: 6-space indents all sailed through it, silently widening a reviewed withholding into a
#: grant. The property is "the parse refuses a repeated key", not "the parse refuses this
#: text".
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
    # The spelling a node-tree scan misses unless it expands merges first. `<<` is resolved
    # while the mapping is CONSTRUCTED, so before flattening the two `get-host` keys sit in
    # different nodes and neither looks repeated — while `safe_load` merges them and keeps the
    # explicit one. Same silent collapse as every spelling above, reached the one way a reader
    # of the composed tree cannot see without asking for the merge to be applied.
    "merge-key-shadowed": (
        "dispositions:\n"
        "  change-mgmt: &d\n"
        "    get-host: {roles: [gather]}\n"
        "  cmdb:\n"
        "    <<: *d\n"
        "    get-host: {roles: [judge]}\n"
    ),
}


@pytest.mark.parametrize("spelling", sorted(_DUPLICATE_SPELLINGS))
def test_a_repeated_key_raises_rather_than_letting_one_row_win(spelling: str):
    """YAML takes the LAST of two identical keys, silently. For a permission table that is the
    same defect this issue is about: two rows in the file, one honoured, and a reviewer who
    reads both. The parse must refuse rather than pick — however the repeat is spelled."""
    path = _tmp()
    path.write_text(_DUPLICATE_SPELLINGS[spelling], encoding="utf-8")
    with pytest.raises(DispositionError) as caught:
        load_dispositions(path)
    assert "cmdb" in str(caught.value)


def test_a_key_written_three_times_is_named_once():
    """`duplicate_key_paths` promises a set of repeated KEYS, and `_systems_block` renders it
    into the refusal verbatim. One entry per surplus occurrence makes a key written three
    times read as two separate defects in a message a human is meant to act on."""
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
    """The check, cross-examined against a differently-built answer.

    A duplicate-refusing `SafeLoader` subclass is the standard way to ask PyYAML this
    question, and it is built here from the loader's own construction hook rather than from
    the text — a different mechanism from whatever the implementation uses, so the two cannot
    be wrong together the way a shared primitive would be."""
    import yaml

    class _NoDupes(yaml.SafeLoader):
        pass

    def _mapping(loader, node, deep=False):  # noqa: ANN001
        # FLATTENED FIRST, exactly as `SafeConstructor.construct_mapping` does below. Without
        # it the oracle agrees with the implementation on `merge-key-shadowed` for the WRONG
        # reason: `<<` is an unregistered tag on `SafeConstructor`, so `construct_object`
        # raises `ConstructorError` ("could not determine a constructor for the tag
        # ...:merge") before any key is compared — a `YAMLError`, which `pytest.raises`
        # accepts. The one spelling this oracle exists to cross-examine was the one it never
        # examined, and a `duplicate_key_paths` with no merge handling at all would still have
        # passed this half of the test.
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
        # `match=`, not a bare `YAMLError`: the oracle must refuse for the reason it exists to
        # give. A bare catch is satisfied by the tag error an unflattened `<<` raises before
        # any key is compared, which is how the merge spelling passed while being the one
        # spelling neither side examined.
        with pytest.raises(yaml.YAMLError, match="duplicate key"):
            yaml.load(text, Loader=_NoDupes)  # noqa: S506 — a SafeLoader subclass
        path = _tmp()
        path.write_text(text, encoding="utf-8")
        with pytest.raises(DispositionError):
            load_dispositions(path)

    # And the oracle agrees the SHIPPED table is clean, so the agreement above is not two
    # things both refusing everything.
    yaml.load(
        dispositions_path(DEFENDER).read_text(encoding="utf-8"), Loader=_NoDupes,
    )  # noqa: S506


# =========================================================================================
# O2 — a refusal names its real reason.
# =========================================================================================

def test_an_ungranted_systems_real_verb_keeps_the_unresolvable_label():
    """The LABEL is not #995's to change, and this pins that it did not.

    The first draft of this suite demanded DENIED here. That was wrong: §7 R11 read literally
    makes a wholly ungranted system UNRESOLVABLE, RS14 records the accounting that follows
    (no denial record, retry coaching, agent-fixable), and six demands across the 632 suite
    reason from that split. It is agent-visible behaviour, not wording. #995's complaint is
    that the two UNDECLARED cases were INDISTINGUISHABLE, which is a message defect and is
    fixed as one below."""
    grant = VerbGrant(
        role="gather",
        entries=tuple((s, v, "r") for s, v in GATHER_CENSUS if s != "cmdb"),
    )
    reg = ModuleVerbRegistry(ADAPTERS, grant)
    assert reg.decide("cmdb", "list-hosts").outcome == "UNDECLARED"


def test_the_ungranted_system_refusal_differs_from_a_typo_refusal():
    """THE onboarding symptom, and the demand that closes it. Before #995 these two produced
    byte-identical text, so a correctly built adapter on a system nobody had granted read
    exactly like a spelling mistake — and the maintainer at `/connect`'s test step went
    looking for the typo that was not there.

    Both remain UNRESOLVABLE. What must differ is what the reader is told to DO."""
    grant = VerbGrant(
        role="gather",
        entries=tuple((s, v, "r") for s, v in GATHER_CENSUS if s != "cmdb"),
    )
    reg = ModuleVerbRegistry(ADAPTERS, grant)
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
    # Not merely different TEXT. An adversarial implementer satisfied the inequality above by
    # appending a single trailing space to the unchanged "unknown" wording — the maintainer
    # still read "unknown" and still went hunting a spelling mistake.
    assert real.refusal.strip() != typo.refusal.strip()
    assert "unknown" not in (real.refusal or ""), (
        "the refusal for a declared verb still calls it unknown"
    )
    assert "unknown" in (typo.refusal or "")


def test_a_typo_on_a_granted_system_is_told_apart_from_a_typo_on_an_ungranted_one():
    """The third case, which the two above do not cover between them: an unreal verb on a
    system the grant DOES reach. It must not borrow the ungranted-system wording either."""
    rows = load_dispositions(dispositions_path(DEFENDER))
    reg = ModuleVerbRegistry(ADAPTERS, grant_for("gather", rows))
    near_miss = reg.decide("cmdb", "list-hostz")
    assert near_miss.outcome == "UNDECLARED"
    assert "verb-grants.yaml" not in (near_miss.refusal or "")


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

def _lint_shippable_surface():
    """The lint module, imported off `scripts/lint/` without leaving that dir on `sys.path`.

    Removed BY VALUE, never `pop(0)`: the module itself inserts the repo root at index 0 when
    it is not already there, so on any tree where the two spellings differ (a symlinked
    checkout, an import mode that does not prepend the rootdir) a positional pop drops the
    repo root and leaves `scripts/lint/` on the path for the rest of the session — where its
    `_baseline` / `_gitscope` / `_astlib` shadow anything later-imported by those names.
    """
    lint_dir = str(REPO_ROOT / "scripts" / "lint")
    sys.path.insert(0, lint_dir)
    try:
        import lint_shippable_surface as mod
    finally:
        if lint_dir in sys.path:
            sys.path.remove(lint_dir)
    return mod


def test_the_shippable_surface_scanner_excludes_every_declared_system():
    """The adjacent instance of the same defect: a hand-kept list of `skills/<system>/` dirs
    that is already stale (seven entries, eight systems) and fails silently because the
    missing name is not a vendor word."""
    mod = _lint_shippable_surface()
    from defender.learning.leads.declared_systems import declared_systems

    excluded = set(mod.excluded_prefixes(REPO_ROOT))
    systems = sorted(declared_systems(REPO_ROOT))
    for system in systems:
        assert f"defender/skills/{system}/" in excluded, (
            f"{system} is a declared system whose skill dir the scanner does not exclude"
        )

    # THE COMPLEMENT, which membership alone never checks. An adversarial implementer widened
    # this to every directory under skills/, carving `gather/`, `invlang/`, `handbook/`,
    # `judge/`, `connect/` and `advisory/` out of the vendor-token gate entirely — the largest
    # part of the shipped surface silently stopped being scanned, and both membership tests
    # still passed. The carve-out is for SYSTEMS; a role skill is shipped product.
    skill_dirs = {
        p for p in excluded
        if p.startswith("defender/skills/") and p.count("/") == 3
    }
    assert skill_dirs == {f"defender/skills/{s}/" for s in systems}, (
        f"the scanner excludes skill dirs that are not systems: "
        f"{sorted(skill_dirs - {f'defender/skills/{s}/' for s in systems})}"
    )


def test_the_scanner_exclusions_track_a_planted_system():
    """Derived, not merely correct today. A system planted in a synthetic tree must be
    excluded there — which a hand-written tuple cannot do."""
    repo = planted_tree(_tmp_dir(), {"alpha": "lookup"})
    assert "defender/skills/alpha/" in set(_lint_shippable_surface().excluded_prefixes(repo))


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


def test_exercising_the_run_paths_leaves_the_table_byte_identical():
    """The behavioural half of O4, because the census above is a text scan and text scans are
    defeatable.

    An adversarial implementer wrote to the table from a module that never spelled its name —
    the path was assembled from two constants — and appended rows to the real file on every
    load. The grep saw nothing. Bytes see everything: snapshot the file, run every path that
    touches it in a real process (load, both projections, and building the two agent
    definitions that read them at import), and compare."""
    table = dispositions_path(DEFENDER)
    before = table.read_bytes()

    rows = load_dispositions(table)
    grant_for("gather", rows)
    grant_for("judge", rows)
    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    from defender.runtime.driver import GATHER_DEF

    ModuleVerbRegistry(ADAPTERS, GATHER_DEF.verb_grant)
    assert JUDGE_DEF.verb_grant is not None

    assert table.read_bytes() == before, "a run path rewrote the disposition table"


def test_the_table_loads_from_a_read_only_file():
    """Read-only by construction, not by convention. If any load path writes — a cache, a
    normalisation, an 'autoheal' — this raises instead of silently succeeding on a tree where
    the file happens to be writable."""
    src = dispositions_path(DEFENDER).read_bytes()
    ro = _tmp_dir() / "verb-grants.yaml"
    ro.write_bytes(src)
    ro.chmod(0o444)
    try:
        rows = load_dispositions(ro)
        assert rows, "the read-only copy loaded nothing"
        assert grant_for("gather", rows).entries
    finally:
        ro.chmod(0o644)


# =========================================================================================
# O6 — the documented onboarding path is complete.
# =========================================================================================

def test_the_connect_skill_names_the_table_as_a_step():
    """The skill's own test step is the one that fails when the edit is missing, so the edit
    has to appear before it."""
    text = (DEFENDER / "skills" / "connect" / "SKILL.md").read_text(encoding="utf-8")
    assert "verb-grants.yaml" in text, "the onboarding skill never mentions the table"


def test_the_connect_lane_permits_the_table_edit():
    """The lane rule is a positive allowlist: a `Write only ...` sentence, then a `Never ...`
    sentence. The table must appear in the FIRST.

    Anchored on the allowlist sentence rather than on the clause as a whole, because "the
    filename appears somewhere in the lane rule" is satisfied by prose that forbids the edit —
    an adversarial implementer wrote "You do not edit knowledge/environment/verb-grants.yaml"
    into the same clause and this test passed, which is verbatim the failure its own docstring
    warns about.

    This is still a prose assertion and prose assertions are weak. What would replace it is a
    machine-readable allowlist in the skill that a real lane checker parses; that is a bigger
    change than #995 and is recorded here rather than pretended away."""
    text = (DEFENDER / "skills" / "connect" / "SKILL.md").read_text(encoding="utf-8")
    lane = text.split("Stay in your lane", 1)
    assert len(lane) == 2, "the lane rule moved; this test needs re-anchoring"
    clause = lane[1].split("- **", 1)[0]

    allow, _, forbid = clause.partition("Never ")
    assert "verb-grants.yaml" in allow, (
        "the table is not in the lane's `Write only ...` allowlist — naming it only in the "
        "`Never ...` half leaves the skill forbidden from finishing the job it documents"
    )
    assert "verb-grants.yaml" not in forbid, "the lane both permits and forbids the table edit"


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
