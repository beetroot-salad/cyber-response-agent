"""#1077 — D6's gate rewrite, and the two sibling lints coupled to the owners."""
from __future__ import annotations

from pathlib import Path


from defender.tests import _spec1077 as S

NAME_LITERAL = "executed_queries.jsonl"


# D6(a) — the negative, name-keyed, root-agnostic literal pass

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


def test_a_record_name_that_reaches_a_path_without_ever_being_a_literal(tmp_path: Path):
    """A record name that reaches a path without ever being a literal — from a data file, an env
    var, a message or a table row — is an accepted, out-of-scope gap and not a finding: D6(a) is
    a literal-shaped check and is structurally blind to it, D6(b)'s data-flow pass closes only
    the narrower literal-free-join-onto-a-tagged-owner-value case, and O1's 'no code spells a
    name outside the owner' is therefore a claim about literal spellings only."""
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


# D6(b) — the accessor-derived pass in `_astlib`

def test_gate_flags_a_literal_free_join_onto_an_owner_derived_value(tmp_path: Path):
    """A join onto a value the accessor pass traced back to an owner —
    `RunPaths(run_dir).gather_raw / lead_id` — is reported even though it carries no literal."""
    found = S.gate_findings(tmp_path, "scripts/gather_tools/record_query.py", '''
from pathlib import Path

from defender.run_repository import RunPaths


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


# O1's scope — what the checker does and does not enter


# The allow-list and the migration's intermediate states


# The two tables and the page


# The two sibling lints coupled to the owners


