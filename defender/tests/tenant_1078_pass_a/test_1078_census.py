"""#1078 pass (A) — the production-code censuses: O1 (no default tenant, no tenant literal), O2
(one writer of the tenant row) and U6 (no tenant data written into the box-mounted `defender/`).

Each census is ONE scanner (`_census_1078.py`) driven twice: over the real tree — the negative —
and over a planted synthetic module — the positive control, proving the scanner can see the
violation it certifies absent. The scanners' grep floors are written down in that module; a
census is a floor, never a proof of absence below it.
"""
from __future__ import annotations

from pathlib import Path

from defender.tests.tenant_1078_pass_a import _census_1078 as C


def _plant(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ======================================================================================
# O1 — every run names its tenant; code holds no default and no literal
# ======================================================================================

def test_o1_no_default_tenant_census():
    """DEFAULT_TENANT_ID appears nowhere in defender/ production code nor under scripts/lint/,
    and no production module outside evals/ and the tests passes a string literal (such as
    'playground' or 'default') as a tenant id. The census scope is defender/**/*.py minus
    defender/tests and defender/evals, plus scripts/lint/ and any bin/ shell shim (vacuous at
    ed5386bc, C-R18); experiments/ is excluded (N10).

    The repo-root `bin/` does not exist (C-R18); `defender/bin/`'s shims do, and are scanned.
    At base this finds `_tenant.py`'s `DEFAULT_TENANT_ID` and `lint_run_records.py:365`'s
    exemption entry, both of which D2 deletes."""
    py, shims = C.o1_scope()
    assert any(p.name == "_tenant.py" for p in py), "the scope lost the tenant owner"
    assert any(p.name == "lint_run_records.py" for p in py), "the scope lost scripts/lint/"
    assert not any("tests" in p.relative_to(C.DEFENDER).parts[:1] for p in py
                   if C.DEFENDER in p.parents), "the scope includes the tests"
    assert not any(p.relative_to(C.REPO_ROOT).parts[0] == "experiments" for p in py)
    found = C.o1_census(py, shims, root=C.REPO_ROOT)
    assert found == [], "production code holds a default tenant or a tenant literal:\n  " + \
        "\n  ".join(found)


def test_o1_census_detects_planted_literal(tmp_path):
    """The census scanner run over a synthetic module that defines DEFAULT_TENANT_ID or passes
    tenant_id='playground' reports that module (the census's positive control)."""
    defines = _plant(tmp_path, "defender/defines.py", 'DEFAULT_TENANT_ID = "default"\n')
    passes = _plant(tmp_path, "defender/passes.py",
                    "def go(materialize, alert):\n"
                    "    return materialize(alert, None, tenant_id='playground')\n")
    clean = _plant(tmp_path, "defender/clean.py",
                   "def go(materialize, alert, t):\n"
                   "    return materialize(alert, None, tenant_id=t)\n")
    found = C.o1_census([defines, passes, clean], [], root=tmp_path)
    assert any(f.startswith("defender/defines.py:") for f in found), found
    assert any(f.startswith("defender/passes.py:") for f in found), found
    assert not any(f.startswith("defender/clean.py:") for f in found), (
        f"the census flags a threaded tenant: {found}")


def test_census_for_tenant_literals_beyond_keyword_arguments(tmp_path):
    """The O1 census catches a tenant literal in production Python spelled as an argv element,
    an argparse default or an f-string. Shell shims under bin/ ride demand fork F7 — §7 F7
    (auto) widened the scope to them, so a shim spelling one is caught too.

    Each spelling is planted in its own module, with a threaded control beside it."""
    argv = _plant(tmp_path, "defender/argv.py",
                  "import sys\nARGV = [sys.executable, 'run.py', '--tenant', 'playground']\n")
    argparse_default = _plant(
        tmp_path, "defender/argparse_default.py",
        "import argparse\np = argparse.ArgumentParser()\n"
        "p.add_argument('--tenant', default='playground')\n")
    fstring = _plant(tmp_path, "defender/fstring.py",
                     "def cmd(alert):\n    return f'python3 run.py {alert} --tenant playground'\n")
    eq_form = _plant(tmp_path, "defender/eq_form.py", "ARGV = ['run.py', '--tenant=acme']\n")
    shim = _plant(tmp_path, "bin/defender-x", '#!/bin/sh\nexec python3 run.py --tenant playground "$@"\n')
    threaded = _plant(tmp_path, "defender/threaded.py",
                      "def argv(t, alert):\n    return ['run.py', str(alert), '--tenant', t]\n"
                      "def cmd(t):\n    return f'run.py --tenant {t}'\n")
    found = C.o1_census([argv, argparse_default, fstring, eq_form, threaded], [shim],
                        root=tmp_path)
    for planted in ("defender/argv.py", "defender/argparse_default.py", "defender/fstring.py",
                    "defender/eq_form.py", "bin/defender-x"):
        assert any(f.startswith(planted + ":") for f in found), (
            f"the census misses the {planted} spelling: {found}")
    assert not any(f.startswith("defender/threaded.py:") for f in found), found


# ======================================================================================
# O2 — only create_tenant writes a row
# ======================================================================================

def _row_writers_allowed() -> set[str]:
    """`defender/_tenant.py::create_tenant` and any private helper of `_tenant.py` that only
    `create_tenant` calls (its own write, split out)."""
    owner = C.DEFENDER / "_tenant.py"
    return {"create_tenant", *C.private_helpers_only_called_from(owner, "create_tenant")}


def _writer_fn(entry: str) -> tuple[str, str]:
    rel, rest = entry.split("::", 1)
    return rel, rest.rsplit(":", 1)[0]


def test_o2_row_single_writer_census(tmp_path):
    """A writer census over production code finds no writer of the row name or of
    TenantPaths.row other than create_tenant.

    The scanner is first shown two planted rogue writers — one through the row's NAME, one
    through the `.row` accessor — so a clean real tree is a census that could have seen one.
    Floor (dropped premise #99): a write through a path value another helper returns is not
    seen."""
    by_name = _plant(tmp_path, "defender/by_name.py",
                     "from pathlib import Path\n\ndef forge(root: Path, t: str) -> None:\n"
                     "    (root / t / 'tenant.json').write_text('{}')\n")
    by_accessor = _plant(tmp_path, "defender/by_accessor.py",
                         "from defender._tenant import TenantPaths\n\ndef forge(root, t):\n"
                         "    row = TenantPaths(root, t).row\n"
                         "    with open(row, 'w') as fh:\n        fh.write('{}')\n")
    reader = _plant(tmp_path, "defender/reader.py",
                    "from defender._tenant import TenantPaths\n\ndef look(root, t):\n"
                    "    return TenantPaths(root, t).row.read_text()\n")
    planted = C.o2_row_writers([by_name, by_accessor, reader], root=tmp_path)
    assert {_writer_fn(e) for e in planted} == {("defender/by_name.py", "forge"),
                                                ("defender/by_accessor.py", "forge")}, planted

    allowed = _row_writers_allowed()
    rogue = [e for e in C.o2_row_writers(C.o2_scope(), root=C.REPO_ROOT)
             if _writer_fn(e) not in {("defender/_tenant.py", fn) for fn in allowed}]
    assert rogue == [], "the tenant row has a production writer besides create_tenant:\n  " + \
        "\n  ".join(rogue)


def test_o2_census_finds_create_tenant():
    """The same writer census reports create_tenant as the row's writer (the census's
    positive control)."""
    writers = {_writer_fn(e) for e in C.o2_row_writers(C.o2_scope(), root=C.REPO_ROOT)}
    allowed = {("defender/_tenant.py", fn) for fn in _row_writers_allowed()}
    assert writers & allowed, (
        "the census finds no write of the tenant row in create_tenant — either create_tenant "
        f"does not exist, or it writes the row where the census cannot see it (found {writers})")


# ======================================================================================
# U6 — no tenant data written into the box-mounted defender/ tree (C55's census)
# ======================================================================================

#: Every production write the census traces into `defender/`, classified (C55, re-probed at
#: ed5386bc). The two EXCEPTIONS U6 names — the queue page (N11) and the shared-corpus lessons
#: pages (N3) — are pinned to the files they write; the eval harnesses write their own
#: scenario scratch and results, never a tenant's state. A new site is a census finding until
#: it is classified here.
U6_CLASSIFIED: dict[str, tuple[str, tuple[str, ...] | None]] = {
    "defender/learning/frontend/build.py::main": (
        "N11 queue page + N3 lessons pages",
        ("'queues.json'", "'queues.html'", "'lessons.json'", "'lessons.html'")),
    "defender/learning/frontend/serialize.py::main": ("N3 lessons page", ("'lessons.json'",)),
    "defender/evals/harness.py::capture_results": ("eval harness results", None),
    "defender/evals/harness.py::main": ("eval harness scratch/results", None),
    "defender/evals/harness_lead.py::capture": ("eval harness results", None),
    "defender/evals/harness_lead.py::main": ("eval harness results", None),
    "defender/evals/harness_lead.py::materialize": ("eval harness scratch tree", None),
    "defender/evals/oracle_golden/record_held_out.py::main": (
        "the golden eval's own checked-in ledger", None),
}


def _unclassified(entries: list[str]) -> list[str]:
    bad = []
    for e in entries:
        rel, qual, dest = e.split("::", 2)
        cls = U6_CLASSIFIED.get(f"{rel}::{qual}")
        if cls is None or (cls[1] is not None and not any(t in dest for t in cls[1])):
            bad.append(e)
    return bad


def test_u6_defender_tree_writer_census(tmp_path, monkeypatch):
    """A writer census over production code finds no write of tenant data into the
    box-mounted defender/ tree except the queue page (build.py:543-546) and the shared-corpus
    lessons pages, and the run-page mirror is written outside defender/.

    The scanner is first shown a planted writer into `PATHS.defender_dir` (so the real tree's
    clean answer is one it could have contradicted), then run over production code, where every
    site it traces must be one C55 classified. The mirror's half is observed on the resolver
    itself: `visualize_run.mirror_root(<checkout>)` with the override unset resolves outside
    the checkout's `defender/` (C61) — resolved, never written."""
    rogue = _plant(tmp_path, "defender/rogue.py",
                   "from defender._paths import PATHS\n\ndef leak(run_id, body):\n"
                   "    (PATHS.defender_dir / 'tenant-cache' / run_id).write_text(body)\n")
    assert [e.split("::")[1] for e in C.u6_defender_tree_writes([rogue], root=tmp_path)] == \
        ["leak"]

    found = C.u6_defender_tree_writes(C.u6_scope(), root=C.REPO_ROOT)
    assert _unclassified(found) == [], (
        "a production write into defender/ that C55 never classified:\n  "
        + "\n  ".join(_unclassified(found)))

    from defender.scripts.visualize import visualize_run

    monkeypatch.delenv("DEFENDER_RUN_VISUALIZATIONS_DIR", raising=False)
    mirror = Path(visualize_run.mirror_root(C.REPO_ROOT)).resolve()
    defender = C.DEFENDER.resolve()
    assert mirror != defender, f"the run-page mirror resolves to defender/ itself: {mirror}"
    assert defender not in mirror.parents, (
        f"the run-page mirror resolves inside the box-mounted defender/ tree: {mirror}")


def test_u6_census_finds_queue_page():
    """The same census reports build.py's queue-page write (its positive control)."""
    found = C.u6_defender_tree_writes(C.u6_scope(), root=C.REPO_ROOT)
    queue = [e for e in found if e.startswith("defender/learning/frontend/build.py::main::")
             and ("'queues.json'" in e or "'queues.html'" in e)]
    assert len(queue) == 2, f"the census does not see the queue page's two writes: {found}"
