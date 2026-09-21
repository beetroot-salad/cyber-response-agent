"""#1077 — D6's gate rewrite, and the two sibling lints coupled to the owners.

Carries 28 demands of `spec-flow/specs/spec_graph_1077.yaml`. D6 replaces `lint_run_records`'s
call-site census — which proved page == table and never table == tree — with two name-keyed
checks: (a) a negative, root-agnostic literal pass over record names and composed PARTS, plus
any `/` whose RIGHT operand is such a string, and (b) an accessor-derived pass in `_astlib`
that tags owner-derived values and reports a join onto one, or an accessor read it cannot
trace.

Every finding here is produced by planting a REAL Python source file in a tmp tree and running
the REAL sweep over it — no fake gate, no canned finding list. The three trees the sweep never
enters are driven the same way, so decision 5's carve-out is observed rather than asserted.

The rewritten sweep is reached through `S.gate_findings(root, rel, source)`, the one helper
that names D6's entry point, so a differently-named implementation costs one edit rather than
twenty-eight.
"""
from __future__ import annotations

import inspect
from pathlib import Path


from defender.tests import _spec1077 as S
from defender.tests._by_path import DEFENDER, load_lint_gate

NAME_LITERAL = "executed_queries.jsonl"


# ---------------------------------------------------------------------------------------
# D6(a) — the negative, name-keyed, root-agnostic literal pass
# ---------------------------------------------------------------------------------------

def test_gate_flags_a_record_name_literal_outside_the_owners(tmp_path: Path):
    """A record name spelled as a string constant, an f-string piece or a glob argument outside
    the owner modules is reported as a finding."""
    found = S.gate_findings(tmp_path, "runtime/spells.py", f'''
from pathlib import Path

def constant(run_dir: Path) -> Path:
    return run_dir / "{NAME_LITERAL}"

def fstring_piece(run_dir: Path, run_id: str) -> str:
    return f"{{run_dir}}/{NAME_LITERAL}"

def globbed(run_dir: Path):
    return list(run_dir.glob("*{NAME_LITERAL}"))

def rglobbed(run_dir: Path):
    return list(run_dir.rglob("{NAME_LITERAL}"))
''')
    displays = S.displays(found)
    assert len(found) >= 4, f"only {len(found)} of the four spellings were reported:\n{displays}"
    for spelling in ("constant", "fstring_piece", "globbed", "rglobbed"):
        assert spelling in displays, f"the {spelling} spelling went unreported:\n{displays}"


def test_gate_flags_a_join_by_right_operand_whatever_the_left_is_called(tmp_path: Path):
    """A `/` whose right operand is a record name is reported whatever the left operand is
    called — `child`, `dst_dir`, `source`, `runs` and `lead_dir` all produce the same finding."""
    body = "\n".join(
        f"def joined_{name}({name}):\n    return {name} / \"{NAME_LITERAL}\"\n"
        for name in ("child", "dst_dir", "source", "runs", "lead_dir", "whatever"))
    found = S.gate_findings(tmp_path, "learning/joins.py", "from pathlib import Path\n\n" + body)
    displays = S.displays(found)
    for name in ("child", "dst_dir", "source", "runs", "lead_dir", "whatever"):
        assert f"joined_{name}" in displays, (
            f"the join under `{name}` went unreported — (a) is keyed on the RIGHT operand "
            f"precisely so there is no identifier list to guess:\n{displays}")


def test_the_gates_part_set_holds_only_the_discriminating_fragments(tmp_path: Path):
    """The gate's composed-part set is exactly the discriminating fragments — `.lead.json`,
    `review_record.`, `.trace.jsonl`, `_trace.jsonl`, `served/` — and carries no generic
    suffix."""
    parts = frozenset(S.gate().COMPOSED_PARTS)
    assert parts == frozenset(S.DISCRIMINATING_PARTS), (
        f"fork D-F5 closed on reading 1; the part set is {sorted(parts)}")
    for generic in (".json", ".db", ".jsonl", ".md", ".yaml"):
        assert generic not in parts, (
            f"{generic!r} alone matches ~1065 non-test literals (claim R3) — D6(a) as spelled "
            "was unimplementable, and the generic suffixes were dropped for exactly that")
    # Driven: each kept fragment IS reported, and a dropped one is NOT.
    for part in S.DISCRIMINATING_PARTS:
        found = S.gate_findings(
            tmp_path / part.replace("/", "_").replace(".", "_"), "runtime/part.py",
            f'def f(d):\n    return d / "{part}x"\n')
        assert found, f"the kept fragment {part!r} was not reported"
    quiet = S.gate_findings(
        tmp_path / "generic", "runtime/generic.py", 'def f(d):\n    return d / "other.json"\n')
    assert quiet == [], (
        "the cost decision 6 accepted: `payload(lead_id, seq)` and `session_db(...)` lose their "
        "part-level guard, so a hand-rolled suffix is caught only by check (b)")


def test_gate_admits_a_quoted_name_only_under_an_inline_suppression(tmp_path: Path):
    """A record name quoted inside a message string is reported unless the line carries the
    inline `# lint-…: ok — reason` suppression."""
    unsuppressed = S.gate_findings(
        tmp_path / "a", "runtime/msg.py",
        f'def explain():\n    raise ValueError("no {NAME_LITERAL} here")\n')
    assert unsuppressed, "a name quoted in a message is a finding without the escape"

    suppressed = S.gate_findings(
        tmp_path / "b", "runtime/msg.py",
        f'def explain():\n'
        f'    raise ValueError("no {NAME_LITERAL} here")'
        f'  # lint-run-records: ok — a diagnostic naming the record for the operator\n')
    assert suppressed == [], (
        f"the inline suppression is the ONLY escape D6(a) admits, and it did not: "
        f"{S.displays(suppressed)}")


def test_gate_suppression_comment_missing_reason(tmp_path: Path):
    """A reasonless suppression does not suppress: D6(a) defines the escape by its literal form
    `# lint-…: ok — reason`, so a comment carrying the marker with no reason text after it does
    not match that form, is not honoured, and the underlying finding is still reported."""
    for comment in ("# lint-run-records: ok", "# lint-run-records: ok —", "# lint-run-records:"):
        found = S.gate_findings(
            tmp_path / comment.replace(" ", "_").replace(":", ""), "runtime/msg.py",
            f'def explain():\n    raise ValueError("no {NAME_LITERAL}")  {comment}\n')
        assert found, (
            f"{comment!r} carries the marker with no reason after it and must not suppress; "
            "the UNDERLYING finding is what this asserts — no second malformed-suppression "
            "diagnostic is demanded (§7 non-material item 6)")
    # Positive control: the well-formed suppression still admits the line (demand d5).
    ok = S.gate_findings(
        tmp_path / "wellformed", "runtime/msg.py",
        f'def explain():\n    raise ValueError("no {NAME_LITERAL}")'
        f'  # lint-run-records: ok — the operator needs the name\n')
    assert ok == []


def test_gate_reports_nothing_inside_the_owner_modules(tmp_path: Path):
    """The owner modules and the handle spell every record name they own and produce no finding.

    NEGATIVE. Positive control inline (and demand d1): the SAME source outside the owner set
    is reported, so the observation channel can see the difference.
    """
    source = (
        "from pathlib import Path\n\n"
        f'EXECUTED_QUERIES = "{NAME_LITERAL}"\n'
        'LEAD_CLAIM_SUFFIX = ".lead.json"\n\n'
        "def resolve(run_dir: Path) -> Path:\n"
        "    return run_dir / EXECUTED_QUERIES\n")
    assert set(S.gate().OWNER_MODULES) == set(S.OWNER_MODULE_FILES), (
        f"D6(a)'s exempt owner set is {sorted(S.gate().OWNER_MODULES)}; it must be the four "
        "owner modules and nothing else")
    for owner in S.OWNER_MODULE_FILES:
        found = S.gate_findings(tmp_path / owner.replace(".", "_"), owner, source)
        assert found == [], f"{owner} is an owner and reported {S.displays(found)}"
    outside = S.gate_findings(tmp_path / "outside", "runtime/copy.py", source)
    assert outside, "positive control: the same source outside the owner set IS reported"


def test_a_record_name_that_reaches_a_path_without_ever_being_a_literal(tmp_path: Path):
    """A record name that reaches a path without ever being a literal — from a data file, an env
    var, a message or a table row — is an accepted, out-of-scope gap and not a finding: D6(a)
    is a literal-shaped check and is structurally blind to it, D6(b)'s data-flow pass closes
    only the narrower literal-free-join-onto-a-tagged-owner-value case, and O1's 'no code spells
    a name outside the owner' is therefore a claim about literal spellings only.

    NEGATIVE, with its positive control inline: a name that IS a literal is reported.
    """
    found = S.gate_findings(tmp_path / "nonliteral", "runtime/indirect.py", '''
import os
from pathlib import Path


def from_env(run_dir: Path) -> Path:
    return run_dir / os.environ["DEFENDER_TABLE_NAME"]


def from_a_row(run_dir: Path, row: dict) -> Path:
    return run_dir / row["kind"]


def from_a_data_file(run_dir: Path, names: list[str]) -> Path:
    return run_dir / names[0]
''')
    assert found == [], (
        f"the gate reported a non-literal composition it is structurally blind to: "
        f"{S.displays(found)} — claiming coverage it does not have is worse than the gap")
    literal = S.gate_findings(
        tmp_path / "literal", "runtime/direct.py",
        f'def f(d):\n    return d / "{NAME_LITERAL}"\n')
    assert literal, "positive control: a name that IS a literal is reported"


def test_the_gate_sees_a_composed_name_that_carries_a_literal_and_not_one_that_splits_it(
        tmp_path: Path):
    """The gate reports nothing for a record name assembled so that no whole part is ever a
    literal — whichever of string concatenation, `%`-formatting, `.format`, `os.path.join` or a
    multi-argument `Path()` does the assembling — and says so in its own scope statement; the
    same five forms carrying the name as ONE literal ARE reported.

    NEGATIVE, with its positive control inline AND load-bearing. §7 decision 6 declared those
    five syntactic forms "the gate structurally cannot see"; an executed probe of D6(a)'s own
    rule reports a finding in all five (93-safety-claim-sweep.md finding A), because (a) keys on
    the `ast.Constant` and not on the syntax around it. The real blind spot is the narrower class
    settled premise s34 names — an assembly in which NO WHOLE PART is ever a literal — and this
    test pins THAT, in both directions. It must never become a licence to exclude the five forms:
    an exclusion would suppress real O1 violations the literal pass otherwise catches.
    """
    split = S.gate_findings(tmp_path / "split", "runtime/split.py", '''
import os
from pathlib import Path

STEM = "executed_queries"


def concat(run_dir: str) -> str:
    return run_dir + "/" + STEM + "." + "jsonl"


def percent(run_dir: str) -> str:
    return "%s/%s.jsonl" % (run_dir, STEM)


def formatted(run_dir: str) -> str:
    return "{}/{}.jsonl".format(run_dir, STEM)


def joined(run_dir: str) -> str:
    return os.path.join(run_dir, STEM + ".jsonl")


def multi_arg(run_dir: str) -> Path:
    return Path(run_dir, STEM + ".jsonl")
''')
    assert split == [], (
        f"the gate claimed coverage of the class it cannot see — no whole part of the record "
        f"name is ever a literal in this file: {S.displays(split)}")

    # POSITIVE CONTROL, and the half decision 6 got wrong: the SAME five forms carrying the
    # record name as one whole literal are every one of them reported.
    whole = S.gate_findings(tmp_path / "whole", "runtime/whole.py", f'''
import os
from pathlib import Path


def concat(run_dir: str) -> str:
    return run_dir + "/" + "{NAME_LITERAL}"


def percent(run_dir: str) -> str:
    return "%s/{NAME_LITERAL}" % run_dir


def formatted(run_dir: str) -> str:
    return "{{}}/{NAME_LITERAL}".format(run_dir)


def joined(run_dir: str) -> str:
    return os.path.join(run_dir, "{NAME_LITERAL}")


def multi_arg(run_dir: str) -> Path:
    return Path(run_dir, "{NAME_LITERAL}")
''')
    displays = S.displays(whole)
    for form in S.COMPOSITION_FORMS:
        assert form in displays, (
            f"the {form} form carries the whole record name as an `ast.Constant` and went "
            f"unreported — D6(a) keys on the literal, so a gate that excused these five forms "
            f"would drop real O1 findings:\n{displays}")

    statement = S.gate().SCOPE_STATEMENT
    assert "literal" in statement, (
        f"decision 6 declares the gap OUT OF SCOPE IN WRITING, and the gap is the one settled "
        f"premise s34 names: a record name that never reaches the AST as a whole literal. The "
        f"statement must say that, not that the five composition forms go unseen — they do not. "
        f"It says: {statement!r}")


# ---------------------------------------------------------------------------------------
# D6(b) — the accessor-derived pass in `_astlib`
# ---------------------------------------------------------------------------------------

def test_gate_flags_a_literal_free_join_onto_an_owner_derived_value(tmp_path: Path):
    """A join onto a value the accessor pass traced back to an owner —
    `RunPaths(run_dir).gather_raw / lead_id` — is reported even though it carries no literal."""
    found = S.gate_findings(tmp_path, "scripts/gather_tools/record_query.py", '''
from pathlib import Path

from defender._run_paths import RunPaths


def direct(run_dir: Path, lead_id: str) -> Path:
    return RunPaths(run_dir).gather_raw / lead_id


def via_a_local(run_dir: Path, lead_id: str) -> Path:
    paths = RunPaths(run_dir)
    lead_dir = paths.gather_raw
    return lead_dir / lead_id


def via_an_annotated_parameter(paths: RunPaths, lead_id: str) -> Path:
    return paths.gather_raw / lead_id
''')
    displays = S.displays(found)
    for site in ("direct", "via_a_local", "via_an_annotated_parameter"):
        assert site in displays, (
            f"{site} joins onto an owner-derived value with NO literal, which check (a) cannot "
            f"see; that is the whole reason (b) exists (claim G2, record_query.py:264):"
            f"\n{displays}")


def test_gate_reports_an_untraceable_accessor_read_rather_than_skipping_it(tmp_path: Path):
    """An accessor-named attribute read on a value the pass cannot trace is reported as
    `unresolvable accessor use` rather than skipped."""
    found = S.gate_findings(tmp_path, "learning/opaque.py", '''
def from_a_container(bag) -> object:
    return bag["paths"].gather_raw


def from_a_call(make) -> object:
    return make().executed_queries


def from_an_unannotated_parameter(p) -> object:
    return p.wire_log
''')
    displays = S.displays(found)
    assert "unresolvable accessor use" in displays, (
        f"claim C2: `_astlib.origin` returns None for exactly this shape today, and D6(b)'s own "
        f"words are 'never a skip' — the pass reported:\n{displays}")
    assert len(found) >= 3, f"one of the three untraceable reads was skipped:\n{displays}"


def test_the_shared_ast_pass_seen_from_its_other_consumer(tmp_path: Path):
    """`lint_hand_rolled_name_resolution.py` learns the accessor pass belongs to `_astlib`: the
    pass becomes shared infrastructure other lints depend on, and it answers the same way from
    that second consumer."""
    from defender.tests._by_path import import_lint_lib
    astlib = import_lint_lib("_astlib")
    assert hasattr(astlib, "owner_derived"), (
        "D6(b)'s narrow opt-in pass belongs to `_astlib`, not to the gate — that is what makes "
        "it shared infrastructure a second lint can depend on")
    sibling = load_lint_gate("lint_hand_rolled_name_resolution")
    assert "owner_derived" in inspect.getsource(sibling), (
        "the sibling lint still re-derives the resolution D6(b) moved into `_astlib`")
    # The same source, the same answer, from the second consumer.
    import ast
    tree = ast.parse(
        "from defender._run_paths import RunPaths\n"
        "def f(run_dir, lead_id):\n"
        "    return RunPaths(run_dir).gather_raw / lead_id\n")
    env = astlib.module_env(tree)
    joins = [n for n in ast.walk(tree) if isinstance(n, ast.BinOp)]
    assert joins, "the fixture lost its join"
    assert astlib.owner_derived(joins[0].left, env), (
        "`_astlib.owner_derived` did not tag `RunPaths(x).gather_raw`, so neither consumer can")


def test_the_gate_reports_a_finding_for_a_source_file_it_cannot_parse(tmp_path: Path):
    """A swept Python file the gate cannot parse is reported as a finding, never skipped and
    never a crash of the whole sweep."""
    S.plant(tmp_path, "runtime/broken.py", "def f(:\n    pass\n")
    S.plant(tmp_path, "runtime/spells.py", f'def g(d):\n    return d / "{NAME_LITERAL}"\n')
    found = S.gate_findings(tmp_path)
    displays = S.displays(found)
    assert "broken.py" in displays, (
        f"the unparseable file was skipped or crashed the sweep instead of being reported, "
        f"which D6(b)'s own stated 'never a skip' forbids:\n{displays}")
    assert "spells.py" in displays, (
        "the unparseable file took the rest of the sweep down with it — the sweep continues")


# ---------------------------------------------------------------------------------------
# O1's scope — what the checker does and does not enter
# ---------------------------------------------------------------------------------------

def test_the_written_obligation_names_the_three_trees_the_checker_does_not_scan(tmp_path: Path):
    """O1's written obligation names the three trees the checker does not scan —
    `defender/skills/`, top-level `scripts/`, top-level `experiments/` — so the claim it makes is
    the one the observer can keep."""
    statement = S.gate().SCOPE_STATEMENT
    for tree in S.UNSCANNED_TREES:
        assert tree in statement, (
            f"{tree} holds live record-name use today (claims S10/G1/G3) and the sweep never "
            f"enters it; O1's wording must say so. It says: {statement!r}")
    # Driven: a literal in each unscanned tree produces no finding; the same literal inside the
    # swept set does.
    for rel in ("defender/skills/invlang/corpus.py", "scripts/testing/tool.py",
                "experiments/probe.py"):
        quiet = S.gate_findings(tmp_path / rel.replace("/", "_"), rel,
                                f'def f(d):\n    return d / "{NAME_LITERAL}"\n')
        assert quiet == [], f"{rel} is outside the sweep, and the gate reported {S.displays(quiet)}"
    assert S.gate_findings(tmp_path / "inside", "runtime/inside.py",
                           f'def f(d):\n    return d / "{NAME_LITERAL}"\n'), (
        "positive control: inside the swept set the same literal IS reported")


def test_the_swept_directory_set_never_shrinks_below_todays(tmp_path: Path):
    """The checker's scanned directory set never shrinks below today's, and a change that
    removes one is reported.

    NEGATIVE. Positive control inline (and demand d1): the sweep DOES report inside the set it
    does cover.
    """
    todays = ("runtime", "learning", "scripts", "evals", "hooks")
    gate = S.gate()
    assert set(todays) <= set(gate.SWEEP_DIRS), (
        f"the swept set shrank to {sorted(gate.SWEEP_DIRS)}; decision 5 narrows the written "
        "OBLIGATION and adds a standing check that the scanned set never shrinks further")
    assert "defender/*.py" in gate.SCOPE_STATEMENT or gate.SWEEP_TOP_LEVEL, (
        "the top level of `defender/` is swept too, and the statement must say so")
    for d in todays:
        found = S.gate_findings(tmp_path / d, f"{d}/spells.py",
                                f'def f(p):\n    return p / "{NAME_LITERAL}"\n')
        assert found, f"{d} is in the swept set and produced no finding"


def test_a_production_module_under_a_path_the_sweep_treats_as_tests(tmp_path: Path):
    """The exclusion is name-keyed and the consequence is accepted: the sweep skips any directory
    literally named `tests`, so a PRODUCTION module living under a `tests/`-named path is
    excluded from O1's sweep exactly as real test code is and may spell record names freely — an
    acknowledged consequence of a name-keyed rather than role-keyed exclude list, not a finding
    and not a defect the gate must detect."""
    assert "tests" in S.gate().EXCLUDED_DIRS, "claims C6/G3: the exclusion is by DIRECTORY NAME"
    production = S.gate_findings(
        tmp_path, "runtime/tests/a_production_module.py",
        f'"""Not a test module at all."""\n\n\ndef ship(d):\n    return d / "{NAME_LITERAL}"\n')
    assert production == [], (
        f"a production module under a `tests/`-named path is skipped exactly as real test code "
        f"is — the accepted consequence of a name-keyed exclude list: {S.displays(production)}")
    assert S.gate_findings(tmp_path / "sibling", "runtime/a_production_module.py",
                           f'def ship(d):\n    return d / "{NAME_LITERAL}"\n'), (
        "positive control: the same module one directory up IS reported")


def test_the_owner_stays_importable_from_tests_and_the_sweep_skips_them(tmp_path: Path):
    """The owner module stays importable from the test suite and the gate's sweep reports nothing
    under `tests/`.

    NEGATIVE. Positive control inline (and demand d1): the same sweep DOES report outside tests.
    """
    from defender._run_paths import RunPaths  # noqa: F401 — the import IS the assertion (N3)
    importers = [
        p.relative_to(DEFENDER).as_posix() for p in (DEFENDER / "tests").rglob("*.py")
        if "_run_paths" in p.read_text(encoding="utf-8", errors="replace")]
    assert len(importers) > 20, (
        f"claim C6: 48 test files import the owner and N3 says 'private' means LINT-FENCED, not "
        f"Python-private; only {len(importers)} found")
    quiet = S.gate_findings(tmp_path, "tests/test_something.py",
                            f'def test_x(d):\n    assert d / "{NAME_LITERAL}"\n')
    assert quiet == [], f"the sweep entered tests/: {S.displays(quiet)}"
    assert S.gate_findings(tmp_path / "prod", "runtime/something.py",
                           f'def x(d):\n    return d / "{NAME_LITERAL}"\n'), "positive control"


def test_the_gates_own_data_files_spell_every_name_it_bans(tmp_path: Path):
    """The kinds TSV and the rendered page spell every record name the gate bans elsewhere and
    produce no finding.

    NEGATIVE. Positive control inline: the same names in a swept Python module ARE reported.
    """
    docs = tmp_path / "defender" / "docs"
    docs.mkdir(parents=True)
    (docs / "run-records-kinds.tsv").write_bytes(S.KINDS_TSV.read_bytes())
    if S.PAGE.is_file():
        (docs / "run-records.md").write_bytes(S.PAGE.read_bytes())
    found = S.gate_findings(tmp_path)
    assert found == [], (
        f"the gate reported its own data files, which spell every name by design: "
        f"{S.displays(found)}")
    # Red flag 6, KEPT AS A FORWARD GUARD, not as a live hazard. The gate's own SOURCE is not in
    # D6's exempt owner list, but at today's location it cannot report itself for a reason that
    # has nothing to do with imports: `scripts/lint/lint_run_records.py` lives at REPO-ROOT
    # `scripts/lint/`, outside the sweep root set entirely (`sweep_files` roots at `defender/`
    # and walks runtime, learning, scripts=`defender/scripts`, evals, hooks — :56-57,67,194-196).
    # §7 non-material item 5 closed red flag 6 on "already true via its existing imports"; there
    # are no such imports and no owner constant is spelled (93-safety-claim-sweep.md finding B).
    # This assertion therefore bites only if the D6 rewrite moves the gate under
    # `defender/scripts/`, which IS swept — which is exactly when it would be needed.
    gate_src = (DEFENDER.parent / "scripts" / "lint" / "lint_run_records.py").read_text(
        encoding="utf-8")
    for part in S.DISCRIMINATING_PARTS:
        spells_it = (
            f"`lint_run_records.py` spells {part!r} itself and is NOT an exempt owner module, "
            "so the gate reports itself")
        assert f'"{part}"' not in gate_src, spells_it
        assert f"'{part}'" not in gate_src, spells_it
    assert S.gate_findings(tmp_path / "py", "runtime/names.py",
                           f'X = "{NAME_LITERAL}"\n'), "positive control"


# ---------------------------------------------------------------------------------------
# The allow-list and the migration's intermediate states
# ---------------------------------------------------------------------------------------

def test_gate_passes_with_an_empty_allow_list():
    """The gate passes over the whole swept tree — the five `defender/` directories plus its top
    level, per §7 decision 5's carve-out — with an empty allow-list.

    SEQUENCING MARKER (cluster O, §7 non-material item 2): this is the ONE demand that cannot be
    green at any intermediate commit of D7's order. It goes green only when D7 step 4 lands and
    the last package has migrated; every earlier step leaves sites in the allow-list on purpose.
    """
    gate = S.gate()
    assert dict(gate.ALLOW_LIST) == {}, (
        f"D7 step 4's terminal state is an EMPTY allow-list; {len(gate.ALLOW_LIST)} modules are "
        f"still admitted: {sorted(gate.ALLOW_LIST)[:10]}")
    found = gate.scan(DEFENDER)
    assert list(found) == [], (
        f"the gate reports {len(list(found))} findings over the swept tree:\n"
        f"{S.displays(found)[:4000]}")


def test_the_allow_list_is_empty_and_the_suppressions_are_not_counted(tmp_path: Path):
    """The design's stated terminal state is an empty allow-list with the suppression comment
    still an admitted, uncounted escape: d5 requires only that the escape works, not that it is
    bounded."""
    gate = S.gate()
    assert dict(gate.ALLOW_LIST) == {}, "the terminal state is an empty allow-list"
    many = "\n".join(
        f'def f{i}(d):\n'
        f'    return d / "{NAME_LITERAL}"  # lint-run-records: ok — migration escape {i}\n'
        for i in range(25))
    found = S.gate_findings(tmp_path, "runtime/many.py", "from pathlib import Path\n\n" + many)
    assert found == [], "twenty-five suppressions are twenty-five admitted lines"
    unbounded = (
        "a documented gap, not a hedge: d5 requires the escape to WORK and states no counting "
        "or ratcheting mechanism for it")
    assert not hasattr(gate, "SUPPRESSION_BUDGET"), unbounded
    assert not hasattr(gate, "MAX_SUPPRESSIONS"), unbounded


def test_one_package_migrated_while_another_still_spells_the_name(tmp_path: Path):
    """A mixed-route intermediate state is expected during D7 steps 2-3 and is observable as the
    unmigrated literal still sitting in the allow-list."""
    gate = S.gate()
    S.plant(tmp_path, "runtime/migrated.py",
            "from defender._run_handle import Run\n\n\n"
            "def write(run):\n    run.tables.queries.append([{'a': 1}])\n")
    S.plant(tmp_path, "learning/unmigrated.py",
            f'def read(run_dir):\n    return (run_dir / "{NAME_LITERAL}").read_text()\n')
    found = gate.scan(tmp_path)
    displays = S.displays(found)
    assert "migrated.py" not in displays, "the migrated route is not a finding"
    assert "learning/unmigrated.py" in displays, (
        f"the unmigrated literal is what the allow-list admits at steps 2-3, and it is what "
        f"shrinks as each package migrates:\n{displays}")
    admitted = gate.scan(tmp_path, allow_list={"learning/unmigrated.py": 1})
    assert list(admitted) == [], (
        "an allow-listed module is admitted, which is how a mixed-route state passes CI while "
        "the migration is in flight")


# ---------------------------------------------------------------------------------------
# The two tables and the page
# ---------------------------------------------------------------------------------------

def test_kinds_tsv_carries_the_tenant_row_and_a_subcollection_for_circuit_breaker():
    """`run-records-kinds.tsv` carries a `tenant` row filed under table 2 and a non-empty
    `subcollection` cell for `circuit_breaker`."""
    rows = {r["kind"]: r for r in S.kinds_rows()}
    assert "tenant" in rows, (
        "D2 mints a new kind; a kind with no row is a kind with no accessor, and O2's count "
        "would silently fall one short")
    assert rows["tenant"]["table"] == "2", (
        "table 2 holds the records that live BESIDE the run dir under the runs base — the "
        "heading D2's placement fits")
    assert rows["tenant"]["path"] == S.TENANT_RECORD_NAME
    assert rows["circuit_breaker"]["subcollection"].strip(), (
        "circuit_breaker's subcollection cell is empty today and d8 fills it")
    appendix = S.appendix_only()
    for kind, row in rows.items():
        if kind in appendix:
            continue
        cell = row["subcollection"].strip()
        assert cell, f"{kind} has no subcollection"
        if cell.startswith("run."):
            assert cell.split(".")[1] in S.GROUPS, (
                f"{kind}'s subcollection cell is {cell!r}; D5 replaces the handoff's table 7 "
                f"with the five groups {S.GROUPS}, addressed group-then-kind")


def test_the_sites_table_is_gone_and_the_kinds_table_still_renders():
    """`run-records.tsv` and the page's tables 1–4 are gone while `run-records-kinds.tsv` still
    renders."""
    assert not S.SITES_TSV.exists(), (
        "the sites table retires when the allow-list empties: readers and writers are no longer "
        "derived from accessor callers (N6)")
    assert S.KINDS_TSV.is_file(), "the kinds table stays (N6)"
    rendered = S.gate().render(S.kinds_rows())
    assert rendered.strip(), "the kinds table no longer renders"
    for kind in ("alert", "provenance", "session_db", "tenant"):
        assert kind in rendered, f"{kind} is missing from the rendered page"
    page = S.PAGE.read_text(encoding="utf-8")
    for retired in ("Table 1", "Table 2", "Table 3", "Table 4"):
        assert retired not in page, f"{retired} retires with the sites table"


def test_no_reader_writer_census_is_derived_from_accessor_callers():
    """Neither the kinds table nor the rendered page carries a reader/writer census derived from
    accessor callers, and the `via` column is gone.

    NEGATIVE. Positive control: demand d9 — the kinds table still renders, so the observation
    channel is not merely looking at an absent artifact.
    """
    header = S.KINDS_TSV.read_text(encoding="utf-8").splitlines()[0].split("\t")
    assert "via" not in header, (
        f"the `via` column is a hand-maintained reader census the accessor-derived gate makes "
        f"unnecessary (N6); the header is {header}")
    for row in S.kinds_rows():
        assert "via" not in row or not (row.get("via") or "").strip()
    page = S.PAGE.read_text(encoding="utf-8")
    for census_word in ("read through", "written through", "callers resolved"):
        assert census_word not in page, (
            f"the page still derives a reader/writer census from accessor callers: {census_word}")
    assert S.kinds_rows(), "positive control: the kinds table is still there and still readable"


def test_every_kind_in_the_tsv_has_exactly_one_accessor_that_owns_its_name(tmp_path: Path):
    """Walking `run-records-kinds.tsv` — excluding the appendix-only kinds — finds exactly one
    owner accessor per kind."""
    appendix = S.appendix_only()
    base = S.make_runs_base(tmp_path)
    run_dir = S.seed_run_tree(S.make_run_dir(base))
    episode_dir = S.make_episode_dir(tmp_path)
    by_kind = {a.kind: a for a in S.ACCESSOR_FOR_KIND}

    walked, homeless = 0, []
    for row in S.kinds_rows():
        kind = row["kind"]
        if kind in appendix:
            continue
        acc = by_kind.get(kind)
        if acc is None:
            homeless.append(kind)
            continue
        try:
            got = S.resolve(acc, run_dir=run_dir, runs_base=base, episode_dir=episode_dir)
        except AttributeError:
            homeless.append(f"{kind} (no {acc.owner}.{acc.attr})")
            continue
        assert Path(got).name, f"{kind} resolved nothing"
        walked += 1
    assert homeless == [], (
        f"O2: every kind has exactly one accessor that owns its name, and a kind with none "
        f"forces a literal somewhere. Homeless: {homeless}")
    assert walked >= 40, f"the walk only reached {walked} kinds"
    assert appendix == frozenset({"tool_seam"}), (
        "the exclusion set is IMPORTED from the gate rather than re-spelled here (fork D-F7), "
        f"and it is {sorted(appendix)}")


def test_exactly_one_accessor_per_kinds_table_row_and_the_archive_spelling_is_a_projection(
        tmp_path: Path):
    """'Exactly one method owns each record kind' is scoped per row of the kinds table, and the
    archive's renamed spelling is a property of the `ArchivedWorld` projection rather than a
    second kind."""
    rows = S.kinds_rows()
    kinds = [r["kind"] for r in rows]
    assert len(kinds) == len(set(kinds)), (
        f"two rows name one kind, so the per-kind walk cannot say which owns it: "
        f"{[k for k in kinds if kinds.count(k) > 1]}")
    owners = {}
    for acc in S.ACCESSOR_FOR_KIND:
        key = (acc.owner, acc.attr)
        assert key not in owners, f"{acc.owner}.{acc.attr} owns two kinds: {owners[key]}, {acc.kind}"
        owners[key] = acc.kind

    # The renamed archive spellings are the PROJECTION's, not second kinds.
    renamed = {r["kind"]: r["archived_as"] for r in rows
               if (r.get("archived_as") or "").strip() not in ("", "—")}
    assert "scrub_verdict.json" in renamed.get("scrub_verdict", ""), renamed
    assert "run_end.json" in renamed.get("run_end", ""), renamed
    for renamed_kind in ("scrub_verdict", "run_end"):
        assert sum(1 for k in kinds if k == renamed_kind) == 1, (
            f"{renamed_kind}'s archived spelling minted a second row; it is a property of the "
            "ArchivedWorld projection (N5), not a second kind")
    world = tmp_path / "worlds" / S.LABEL
    world.mkdir(parents=True)
    aw = S.ArchivedWorld().at(world)
    assert aw.scrub_verdict.path.name == "scrub_verdict.json"
    assert aw.run_end.path.name == "run_end.json", (
        "the projection is where the rename lives — the kinds table keeps one row per kind")


# ---------------------------------------------------------------------------------------
# The two sibling lints coupled to the owners
# ---------------------------------------------------------------------------------------

def test_the_tenant_writer_is_hard_gated_by_the_unguarded_write_lint(tmp_path: Path):
    """The tenant record's writer and its containing module both carry a census row in the
    unguarded-write lint, and the lint's module list still matches the spec-771 census set for
    set.

    Written against the REAL structure, not the design's: claim R12 is REFUTED — the lint has no
    tree set, it gates by MODULE (`LINT_HARD_GATED_MODULES`), so the security dive's "add the
    tenant path to the tree set" names a structure that does not exist.
    """
    from defender.tests.e2e import _spec771
    lint = load_lint_gate("lint_unguarded_tree_write")

    tenant_rows = [w for w in _spec771.CENSUS
                   if S.TENANT_RECORD_NAME in str(getattr(w, "artifact", ""))]
    assert tenant_rows, (
        "decision 16, reading 1: a census row for the tenant WRITER joins the #771 census — "
        f"the census names {sorted({str(getattr(w, 'artifact', '')) for w in _spec771.CENSUS})}")
    modules = {w.module for w in tenant_rows}
    assert modules <= set(_spec771.LINT_HARD_GATED_MODULES), (
        f"the writer's containing module {modules} is not hard-gated")
    assert frozenset(lint.LINT_HARD_GATED_MODULES) == frozenset(
        _spec771.LINT_HARD_GATED_MODULES), (
        "the lint's hand-typed copy and the census's derived set have drifted; the existing "
        "set-for-set test is what holds the two edits in step")

    # Driven: an unguarded write in that module is HARD-gated, bypassing the ratchet entirely.
    module = sorted(modules)[0]
    S.plant(tmp_path, module,
            "from pathlib import Path\n\n\n"
            "def write(p: Path) -> None:\n    p.write_text('x')\n")
    found = lint._scan(tmp_path)
    assert found, f"an unguarded write in the hard-gated {module} produced no finding"


def test_a_new_accessor_that_the_write_lint_does_not_know_by_name(tmp_path: Path):
    """Every accessor D1 adds is invisible to `lint_ungated_artifact_write` until its hand-kept
    bare-attribute list grows, and D6's rewrite names only `_astlib` and
    `lint_hand_rolled_name_resolution.py`."""
    lint = load_lint_gate("lint_ungated_artifact_write")
    accessors = frozenset(lint.ARTIFACT_ACCESSORS)

    # The mechanism is NAME-KEYED, which is the whole coupling: a write through an attribute in
    # the list is reported; the identical write through an attribute that is not is invisible.
    named = sorted(accessors)[0]
    S.plant(tmp_path, "runtime/known.py",
            "def w(paths, text):\n"
            f"    paths.{named}.write_text(text)\n")
    S.plant(tmp_path, "runtime/unknown.py",
            "def w(paths, text):\n"
            "    paths.not_a_record_accessor_at_all.write_text(text)\n")
    displays = S.displays(lint._scan(tmp_path))
    assert "runtime/known.py" in displays, f"the known accessor was not reported:\n{displays}"
    assert "runtime/unknown.py" not in displays, (
        "the lint is name-keyed — an attribute it does not know by name is invisible, which is "
        f"why decision 19 gives this issue the list edit:\n{displays}")

    # D6's rewrite names only the two coupled consumers; a third would be an unowned coupling.
    gate_src = (DEFENDER.parent / "scripts" / "lint" / "lint_run_records.py").read_text(
        encoding="utf-8")
    named_lints = {n for n in ("_astlib", "lint_hand_rolled_name_resolution")
                   if n in gate_src}
    assert named_lints == {"_astlib", "lint_hand_rolled_name_resolution"}, (
        f"D6(b) names exactly these two as the pass's home and its second consumer: {named_lints}")


def test_the_write_lints_accessor_list_is_held_in_step_with_the_owners_method_set(tmp_path: Path):
    """The second lint's accessor list covers every one of the owner's methods, and a test keeps
    that list and the owner's actual method set in step automatically."""
    lint = load_lint_gate("lint_ungated_artifact_write")
    owner_methods = {
        name for name in dir(S.run_paths_mod().RunPaths)
        if not name.startswith("_")}
    listed = frozenset(lint.ARTIFACT_ACCESSORS)
    assert owner_methods <= listed, (
        f"these owner accessors are invisible to the write lint: {sorted(owner_methods - listed)}"
        " — decision 19 grows the hand-kept two-name list to ALL of them, held in step "
        "automatically the way `_spec771` holds the sibling write-safety lint's copy")
    assert listed <= owner_methods | frozenset(
        n for n in dir(S.episode_paths().EpisodePaths) if not n.startswith("_")), (
        f"the list names something no owner method answers: {sorted(listed - owner_methods)}")
    # Driven: an accessor the list gained is now reported where it was invisible before.
    for gained in ("budget", "tool_trace", "lessons_loaded"):
        if gained not in owner_methods:
            continue
        root = tmp_path / gained
        S.plant(root, "runtime/w.py",
                f"def w(paths, text):\n    paths.{gained}.write_text(text)\n")
        assert lint._scan(root), f"an ungated write through .{gained} is still invisible"
