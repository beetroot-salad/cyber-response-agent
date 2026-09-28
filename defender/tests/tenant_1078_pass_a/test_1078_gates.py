"""#1078 pass (A) — the gates D1/D2/D8 change: `lint_run_records` (TenantPaths as an owner
class, the tenant row's name banned outside the owner, the run-records page), the #1077 rename
proof, and `lint_ci_hygiene` (NO `/tmp/defender-data` allowance — §7 J01, "NO DEFAULT DATA
ROOT", corrected settled #106 — and the `/tmp/defender-runs` entries retired).

Every gate is DRIVEN: `lint_run_records.scan` over a tmp tree holding a planted module
(`_spec1077.gate_findings`, the way `test_1077_gate.py` reaches it), and `lint_ci_hygiene`'s
`check_hardcoded_paths` over a planted tree — a fresh copy of the program per call
(`_by_path.load_module` executes it anew), re-anchored at the tmp tree the way
`test_lessons_fm` re-anchors its fresh copy. Nothing here reads a pattern list and asserts
on its contents alone.
"""
from __future__ import annotations

import ast
import uuid
from pathlib import Path

from defender.tests import _spec1077 as S
from defender.tests._by_path import DEFENDER, LINT_DIR, load_module

JOIN_FINDING = "literal-free join onto an owner-derived value"


# ======================================================================================
# lint_run_records — TenantPaths is an owner class (D1, brief R4(a)/(c))
# ======================================================================================

def test_d1_tenantpaths_owner_class(tmp_path):
    """TenantPaths is a member of _OWNER_CLASS_ORIGINS, so the #1077 lint treats a join onto a
    TenantPaths accessor as owner-derived.

    Observed by DRIVING the join arm (G10, executed): a swept module that joins onto
    `TenantPaths(root, T).runs` — directly, and through a local bound to it — is reported, as
    the same shapes onto `EpisodePaths(ep).runs` already are (the control). The second
    hand-kept registration line brief R4(c) found, `_accessor_names()`, lists the new owner's
    accessors too."""
    source = (
        "from defender._tenant import TenantPaths\n"
        "from defender._episode_paths import EpisodePaths\n\n"
        "def direct(root, t, run_id):\n"
        "    return TenantPaths(root, t).runs / run_id\n\n"
        "def through_a_local(root, t, run_id):\n"
        "    runs = TenantPaths(root, t).runs\n"
        "    return runs / run_id\n\n"
        "def control(ep, run_id):\n"
        "    return EpisodePaths(ep).runs / run_id\n")
    found = S.gate_findings(tmp_path, "evals/joins.py", source)
    joins = [f.display for f in found if JOIN_FINDING in f.display]
    assert any("control()" in d for d in joins), f"the join arm is not live: {joins}"
    for fn in ("direct()", "through_a_local()"):
        assert any(fn in d for d in joins), (
            f"a join onto a TenantPaths accessor in {fn} is not owner-derived to the lint: "
            f"{joins}")
    accessors = S.gate()._accessor_names()
    missing = {"row", "episodes", "learning"} - set(accessors)
    assert not missing, f"_accessor_names() does not list TenantPaths' {sorted(missing)}"


def test_d1_row_constant_not_exempt(tmp_path):
    """The row-name constant is not in _OWNER_NON_RECORD_EXPORTS, so the lint flags a
    'tenant.json' literal outside the owner.

    The literal is banned once the registry carries kind `tenant_row` (G12: that row adds
    exactly 'tenant.json' to the ban); the import arm refuses any public `str` the owner binds
    to that name. Both are driven over a swept module."""
    found = S.gate_findings(tmp_path, "runtime/forges_the_row.py",
                            "from pathlib import Path\n\n"
                            "def row(root: Path, t: str) -> Path:\n"
                            "    return root / t / 'tenant.json'\n")
    assert S.reports(found, "forges_the_row.py"), (
        "a 'tenant.json' literal outside the owner is not flagged: " + S.displays(found))

    tenant = S.tenant()
    gate = S.gate()
    exported_row = [n for n in gate._OWNER_NON_RECORD_EXPORTS
                    if getattr(tenant, n, None) == "tenant.json"]
    assert exported_row == [], f"the row name is exported as a non-record: {exported_row}"
    public_row = [n for n, v in vars(tenant).items()
                  if v == "tenant.json" and not n.startswith("_")]
    for name in public_row:
        imported = S.gate_findings(tmp_path / f"imp-{name}", "runtime/imports_it.py",
                                   f"from defender._tenant import {name}\n")
        assert S.reports(imported, "imports_it.py"), (
            f"importing the row-name constant {name} outside the owner is not refused")


def test_d1_row_literal_owner_ok(tmp_path):
    """The owner's own TenantPaths.row usage passes the lint (the positive control).

    Planted: an owner module (`_tenant.py`, the exempt name) that spells 'tenant.json' and
    joins onto its own accessors, and a swept module that reaches the row only through
    `TenantPaths(root, T).row`. Neither is reported, while the same scan reports a record name
    spelled outside the owner (the channel is live)."""
    root = tmp_path
    S.plant(root, "_tenant.py",
            "from pathlib import Path\n\n_ROW = 'tenant.json'\n\n"
            "class TenantPaths:\n"
            "    def __init__(self, data_root: Path, tenant_id: str) -> None:\n"
            "        self.dir = Path(data_root) / tenant_id\n\n"
            "    @property\n"
            "    def row(self) -> Path:\n"
            "        return self.dir / _ROW\n")
    S.plant(root, "runtime/uses_the_row.py",
            "from defender._tenant import TenantPaths\n\n"
            "def row_of(root, t):\n    return TenantPaths(root, t).row\n")
    found = S.gate_findings(root, "runtime/spells_a_record.py",
                            "def alert(run_dir):\n    return run_dir / 'alert.json'\n")
    assert S.reports(found, "spells_a_record.py"), "the literal arm is not live"
    assert not S.reports(found, "_tenant.py"), S.displays(found)
    assert not S.reports(found, "uses_the_row.py"), S.displays(found)


def test_run_records_page_after_the_new_kind_row():
    """docs/run-records.md is re-rendered in the same change as the tenant_row TSV row, and its
    staleness check passes.

    Driven through the gate's own render (`render_page`), which is what `main` compares the
    committed page against."""
    gate = S.gate()
    kinds = gate.load_kinds()
    rows = [k for k in kinds if k["kind"] == "tenant_row"]
    assert rows, "docs/run-records-kinds.tsv has no tenant_row kind"
    assert rows[0]["path"].split("/")[-1] == "tenant.json", rows[0]
    page = gate.PAGE.read_text(encoding="utf-8")
    assert gate.render_page(kinds, page) == page, (
        "docs/run-records.md is stale against its kinds table — run "
        "`python scripts/lint/lint_run_records.py --render`")
    assert "tenant_row" in page


# ======================================================================================
# The #1077 rename proof (settled #108)
# ======================================================================================

def test_rename_proof_with_a_new_row_constant(tmp_path):
    """The #1077 rename proof keeps passing with the new _tenant.py constants in its renamed
    set; DEFAULT_TENANT_ID's _SKIP_NAMES entry goes with the constant.

    Drives the proof's own machinery (`tests/test_1077_rename_proof.py`): every upper-case
    string constant `_tenant.py` binds — the new ones included — is renamed by its rewrite,
    and the real archive round trip over the renamed tree still succeeds."""
    proof = load_module(DEFENDER / "tests" / "test_1077_rename_proof.py",
                        name=f"rename_proof_1078_{uuid.uuid4().hex}")
    assert "DEFAULT_TENANT_ID" not in proof._SKIP_NAMES, (
        "the rename proof still skips DEFAULT_TENANT_ID, which D2 deletes")
    source = (DEFENDER / "_tenant.py").read_text(encoding="utf-8")
    rewritten, _count = proof._rewrite_owner(source)
    before = _upper_str_constants(source)
    after = _upper_str_constants(rewritten)
    unrenamed = sorted(n for n, v in before.items()
                       if n not in proof._SKIP_NAMES and v not in proof._SKIP_VALUES
                       and after.get(n) == v)
    assert unrenamed == [], f"the rewrite leaves _tenant.py's {unrenamed} unrenamed"
    result = proof._round_trip(proof._renamed_tree(tmp_path), tmp_path / "work")
    assert result.returncode == 0, (
        f"the renamed tree's round trip failed:\n{result.stdout[-2000:]}\n"
        f"{result.stderr[-3000:]}")


def _upper_str_constants(source: str) -> dict[str, str]:
    out = {}
    for node in ast.parse(source).body:
        if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id.isupper() and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            out[node.targets[0].id] = node.value.value
    return out


# ======================================================================================
# lint_ci_hygiene (D8, corrected settled #106)
# ======================================================================================

#: The three default spellings `DEFAULT_PATTERNS` is written against, per root.
def _spellings(root: str) -> dict[str, str]:
    return {
        "path_constant": f'from pathlib import Path\nDEFAULT_ROOT = Path("{root}")\n',
        "str_constant": f'DEFAULT_ROOT = "{root}"\n',
        "env_default": f'import os\nROOT = os.environ.get("SOME_ROOT", "{root}")\n',
    }


def _hygiene_findings(tmp_path: Path, files: dict[str, str]) -> list[str]:
    """`check_hardcoded_paths` — the real lint, a fresh copy of it — over a tmp tree holding
    exactly `files` under `defender/`. Returns the flagged relative paths."""
    tree = tmp_path / f"hyg-{uuid.uuid4().hex[:8]}"
    for rel, text in files.items():
        S.plant(tree / "defender", rel, text)
    hygiene = load_module(LINT_DIR / "lint_ci_hygiene.py",
                          name=f"lint_ci_hygiene_1078_{uuid.uuid4().hex}", sys_path=(LINT_DIR,))
    hygiene.REPO_ROOT = tree
    hygiene.DEFENDER = tree / "defender"
    return sorted({f.fingerprint.split(":")[1] for f in hygiene.check_hardcoded_paths()})


def _flags_every_spelling(tmp_path: Path, root: str) -> list[str]:
    files = {f"planted/{name}.py": text for name, text in _spellings(root).items()}
    flagged = _hygiene_findings(tmp_path, files)
    return sorted(set(f"defender/{rel}" for rel in files) - set(flagged))


def test_d8_ci_hygiene_allowance(tmp_path):
    """lint_ci_hygiene flags every /tmp/defender-data default spelling (a DEFAULT_ constant
    assigned Path('/tmp/defender-data'), one assigned the bare string, and
    os.environ.get(..., '/tmp/defender-data')): no allowance is added, because there is no
    data-root default to permit."""
    missed = _flags_every_spelling(tmp_path, "/tmp/defender-data")
    assert missed == [], f"lint_ci_hygiene allows the /tmp/defender-data spelling in {missed}"


def test_d8_ci_hygiene_runs_entries_retired(tmp_path):
    """Once no production code carries a /tmp/defender-runs default (run_common's
    DEFAULT_RUNS_BASE goes with resolve_runs_base, and generate_case's env default goes with
    its --tenant), lint_ci_hygiene's three /tmp/defender-runs DEFAULT_PATTERNS entries are
    removed.

    Both halves observed: the lint FLAGS the three planted `/tmp/defender-runs` spellings (the
    entries that allowed them are gone), and no shipped production line carries one."""
    missed = _flags_every_spelling(tmp_path, "/tmp/defender-runs")
    assert missed == [], f"lint_ci_hygiene still allows /tmp/defender-runs in {missed}"
    carriers = _production_runs_defaults()
    assert carriers == [], f"production code still carries a /tmp/defender-runs default: {carriers}"


def _production_runs_defaults() -> list[str]:
    out = []
    for p in sorted(DEFENDER.rglob("*.py")):
        rel = p.relative_to(DEFENDER)
        if {"tests", ".venv", "__pycache__", "fixtures"} & set(rel.parts):
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            code = line.split("#", 1)[0]
            if "/tmp/defender-runs" in code and ("DEFAULT_" in code or "environ.get" in code):
                out.append(f"defender/{rel.as_posix()}:{n}")
    return out


def test_hygiene_allowance_and_the_retired_runs_spellings_in_one_commit(tmp_path):
    """lint_ci_hygiene gains NO allowance for the three /tmp/defender-data spellings — it flags
    them — and drops its /tmp/defender-runs entries once their last users leave: run_common's
    DEFAULT_RUNS_BASE and generate_case.py's own hardcoded DEFENDER_RUNS_BASE fallback
    (C-R16).

    One tree, both spellings, one lint copy: the state of a single commit."""
    files = {f"planted/data_{k}.py": v for k, v in _spellings("/tmp/defender-data").items()}
    files |= {f"planted/runs_{k}.py": v for k, v in _spellings("/tmp/defender-runs").items()}
    flagged = set(_hygiene_findings(tmp_path, files))
    allowed = sorted(f"defender/{rel}" for rel in files if f"defender/{rel}" not in flagged)
    assert allowed == [], f"lint_ci_hygiene allows {allowed}"
    run_common = (DEFENDER / "run_common.py").read_text(encoding="utf-8")
    assert "DEFAULT_RUNS_BASE" not in run_common, "run_common still defines DEFAULT_RUNS_BASE"
    generate_case = (DEFENDER / "evals" / "oracle_golden" / "generate_case.py").read_text(
        encoding="utf-8")
    assert "/tmp/defender-runs" not in generate_case, (
        "generate_case.py keeps its own hardcoded /tmp/defender-runs fallback (C-R16)")
