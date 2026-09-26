"""#1078 pass (A) — the setup command's row step (D10 step 1, O10) and the #1077 gate changes D1
names for the new row (`d1_1077_gate_registration`, §7 J60).

THE SETUP COMMAND IS DRIVEN AS THE OPERATOR RUNS IT: `python3 defender/scripts/tenant.py setup
<id>`, a process, against a data root the test owns (`_spec1078.run_setup`). Its exit status is
demand #0's observable (0: nothing refused; 1: refused), its output carries the owner's refusal
VERBATIM (F0/J29), and "writes nothing" is a before/after census of the data root taken around
the process — never a bare "exit 1", which a crash also satisfies.

O10's refusal text is the design's own ("the data root is not empty: …", naming its entries).
§7 J08/J09 (human, RECORD MEANS THE TENANT) overrides D10 step 1's literal text: a rowless
`<root>/<id>/` holding nothing but what `create_tenant` makes is "setup unfinished", completed by
a re-run; anything else, and any other id's entry, is still refused. §7 J60 (human): that
own-folder check ignores the row's own NAME, so an alias planted at `<root>/<id>/tenant.json`
reaches `create_tenant`'s real guarded write, which refuses it.

Every fault is real: the stray entries, rowless folders, `lost+found/`, dangling links and
planted aliases are made on disk here. See `_spec1078.py` for the coined names.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S
from defender.tests.tenant_1078_pass_a import _spec1078 as H

O10_TEXT = "the data root is not empty"
TID = H.VALID_ID


def _refused_writing_nothing(root: Path, tenant_id: str = TID, *, names: str) -> str:
    """Run setup against `root`, and assert it REFUSED (exit 1, output naming `names`) and
    wrote nothing (the census of `root` is unchanged). Returns the setup's output."""
    before = H.census(root)
    proc = H.run_setup(root, tenant_id)
    H.assert_setup_ran(proc)
    out = H.setup_output(proc)
    assert proc.returncode == 1, f"setup exited {proc.returncode}, not 1 (refused):\n{out}"
    assert names in out, f"the refusal does not name {names!r}:\n{out}"
    assert H.census(root) == before, "the refused setup wrote into the data root"
    return out


def _verbatim_owner(out: str, root: Path, tenant_id: str = TID) -> BaseException:
    """The setup output passed `create_tenant`'s own refusal through verbatim — the owner is
    asked AFTER the process, on the same untouched root, and must refuse the same way."""
    before = H.census(root)
    owner = H.owner_refusal(H.create_tenant, root, tenant_id)
    assert H.census(root) == before, "the refusing create_tenant wrote into the data root"
    H.assert_verbatim(out, owner, entry="tenant.py setup")
    return owner


# ======================================================================================
# O10 — tenant 1 only in a fresh data root
# ======================================================================================

def test_o10_other_row_refused(tmp_path):
    """Setup into a data root holding other/tenant.json is refused with 'the data root is not
    empty: ...' naming 'other', and writes nothing."""
    root = tmp_path / "data"
    H.plant_row(root, "other")
    out = _refused_writing_nothing(root, names="other")
    assert O10_TEXT in out, f"the refusal is not O10's:\n{out}"
    _verbatim_owner(out, root)
    assert not H.row_path(root, TID).exists()


@pytest.mark.parametrize("shape", ["empty", "populated"])
def test_o10_rowless_folder_refused(tmp_path, shape):
    """Setup into a data root holding a rowless old/ folder is refused naming 'old', and writes
    nothing.

    Both shapes of what an earlier tenant could leave: an empty `old/`, and one holding a runs
    base with a run in it. Another id's rowless folder is foreign whatever it holds — §7 J08's
    "setup unfinished" reading covers only the tenant's OWN folder."""
    root = tmp_path / "data"
    (root / "old").mkdir(parents=True)
    if shape == "populated":
        (root / "old" / "runs" / "r1").mkdir(parents=True)
        (root / "old" / "runs" / "r1" / "report.md").write_text("x\n", encoding="utf-8")
    out = _refused_writing_nothing(root, names="old")
    assert O10_TEXT in out, f"the refusal is not O10's:\n{out}"
    _verbatim_owner(out, root)


@pytest.mark.parametrize("shape", ["absent", "empty", "missing-parent"])
def test_o10_fresh_root_writes_exactly_row(tmp_path, shape):
    """Setup into an absent or empty data root creates exactly <root>/<id>/tenant.json and
    nothing else (no runs/). An absent root several levels below anything that exists is
    created whole (J07)."""
    top = tmp_path / "top"
    root = {"absent": top, "empty": top, "missing-parent": top / "a" / "b" / "c"}[shape]
    if shape == "empty":
        root.mkdir()
    proc = H.run_setup(root, TID)
    H.assert_setup_ran(proc)
    assert proc.returncode == 0, H.setup_output(proc)
    rel_root = root.relative_to(top).as_posix()
    prefix = "" if rel_root == "." else f"{rel_root}/"
    expected = {f"{prefix}{TID}", f"{prefix}{TID}/{H.ROW_NAME}"}
    if prefix:
        parts = rel_root.split("/")
        expected |= {"/".join(parts[:i]) for i in range(1, len(parts) + 1)}
    assert set(H.census(top)) == expected, (
        f"setup wrote more (or less) than the row: {sorted(H.census(top))}")
    assert H.census(top)[f"{prefix}{TID}/{H.ROW_NAME}"][0] == "file"
    row = json.loads(H.row_path(root, TID).read_text(encoding="utf-8"))
    assert row["tenant_id"] == TID


def test_o10_rerun_no_second_row(tmp_path):
    """A re-run of setup with the same id, where the root's only entry is <id>/ holding a valid
    row, succeeds and leaves that row byte-identical."""
    root = tmp_path / "data"
    first = H.run_setup(root, TID)
    H.assert_setup_ran(first)
    assert first.returncode == 0, H.setup_output(first)
    row_bytes = H.row_path(root, TID).read_bytes()
    before = H.census(root)
    again = H.run_setup(root, TID)
    assert again.returncode == 0, f"the same-id re-run was refused:\n{H.setup_output(again)}"
    assert H.row_path(root, TID).read_bytes() == row_bytes, "the re-run rewrote the row"
    assert H.census(root) == before, "the re-run wrote something"


def test_data_root_is_the_mount_point_of_a_dedicated_filesystem(tmp_path):
    """Setup into a data root whose only entry is lost+found/ is refused by O10, naming
    lost+found, and writes nothing."""
    root = tmp_path / "data"
    (root / "lost+found").mkdir(parents=True)
    out = _refused_writing_nothing(root, names="lost+found")
    assert O10_TEXT in out, out


def test_setup_re_run_after_the_tenant_already_has_runs(tmp_path):
    """A setup re-run with the same id after T has runs/ and sessions/ is accepted as a re-run
    (the root's only entry is <id>/ with a valid row): no second row, nothing under <T>/
    changes, success exit (F0)."""
    root = tmp_path / "data"
    first = H.run_setup(root, TID)
    H.assert_setup_ran(first)
    assert first.returncode == 0, H.setup_output(first)
    base = H.runs_dir(root, TID)
    (base / "r1").mkdir(parents=True)
    (base / "r1" / "report.md").write_text("disposition: benign\n", encoding="utf-8")
    H.plant_record(base, TID)
    H.sessions_dir(root, TID).mkdir()
    (H.sessions_dir(root, TID) / "case-1.db").write_bytes(b"SQLite format 3\x00")
    before = H.census(root)
    again = H.run_setup(root, TID)
    assert again.returncode == 0, f"a re-run over a used tenant was refused:\n{H.setup_output(again)}"
    assert H.census(root) == before, "the re-run changed something under <T>/"


def test_something_other_than_the_tenant_appears_at_the_data_root_top_level(tmp_path):
    """An entry beside <id>/ at the data root's top level makes a setup re-run refused by O10,
    naming the entry, with nothing written."""
    root = tmp_path / "data"
    first = H.run_setup(root, TID)
    H.assert_setup_ran(first)
    assert first.returncode == 0, H.setup_output(first)
    (root / "notes.txt").write_text("an operator's scratch file\n", encoding="utf-8")
    out = _refused_writing_nothing(root, names="notes.txt")
    assert O10_TEXT in out, out


def test_data_root_holds_a_dangling_symlink_entry(tmp_path):
    """A data root whose only entry is a dangling symlink: setup is refused by O10, naming the
    entry, and writes nothing."""
    root = tmp_path / "data"
    root.mkdir()
    (root / "ghost").symlink_to(tmp_path / "nowhere")
    out = _refused_writing_nothing(root, names="ghost")
    _verbatim_owner(out, root)
    assert (root / "ghost").is_symlink() and not (tmp_path / "nowhere").exists()  # noqa: PT018 — one fact: the link is left, dangling


def test_data_root_holds_a_stray_regular_file_at_top_level(tmp_path):
    """A data root whose only entry is a stray regular file: setup is refused by O10, naming
    the entry, and writes nothing."""
    root = tmp_path / "data"
    root.mkdir()
    (root / "README").write_text("stray\n", encoding="utf-8")
    out = _refused_writing_nothing(root, names="README")
    _verbatim_owner(out, root)


# ======================================================================================
# §7 J08/J09 — RECORD MEANS THE TENANT
# ======================================================================================

def test_s7_j08_setup_rerun_completes_rowless_own_folder(tmp_path):
    """A setup re-run for id T, over a data root whose only entry is a rowless <root>/T/ holding
    nothing but what create_tenant itself makes (an interrupted setup, or a disk-full row
    write), creates the row and succeeds: a tenant exists iff its row exists, and every setup
    step is idempotent. The control: a <root>/T/ holding anything setup did not make is still
    refused by O10, and any other id's entry is still refused.

    The leftover is the shape J09 names: `create_tenant`'s own `<id>/` mkdir predates the row
    write, so an interrupted or disk-full setup leaves an EMPTY own folder."""
    root = tmp_path / "data"
    H.tenant_dir(root, TID).mkdir(parents=True)
    done = H.run_setup(root, TID)
    H.assert_setup_ran(done)
    assert done.returncode == 0, f"the unfinished setup was not completed:\n{H.setup_output(done)}"
    assert set(H.census(root)) == {TID, f"{TID}/{H.ROW_NAME}"}
    assert H.require_tenant(root, TID).tenant_id == TID

    foreign = tmp_path / "foreign-in-own"
    H.tenant_dir(foreign, TID).mkdir(parents=True)
    (H.tenant_dir(foreign, TID) / "runs").mkdir()
    _refused_writing_nothing(foreign, names=TID)

    other = tmp_path / "other-id"
    H.tenant_dir(other, "other").mkdir(parents=True)
    _refused_writing_nothing(other, names="other")


# ======================================================================================
# §7 J60 — the row's own name does not short-circuit the guarded write
# ======================================================================================

@pytest.mark.parametrize("alias", ["symlink", "hardlink"])
def test_s7_j60_create_tenant_census_row_reaches_write(tmp_path, alias):
    """The #771 census's create_tenant row plants an alias at <root>/<id>/tenant.json and
    create_tenant's real O_NOFOLLOW-guarded write refuses it, the outside target untouched:
    setup's own-folder check ignores the row's own name when judging whether an entry is the
    tenant's, so O10 does not short-circuit the plant.

    Driven here at the owner and at the setup command, over the plant's real primitive
    (`os.symlink` / `os.link`); the census row itself is `test_d1_1077_gate_registration`'s.
    The refusal must be the WRITE's — not O10's "not empty" — and the outside target's bytes
    and link count unchanged. The control on the same address: the own folder without the
    plant is completed and the row written."""
    for driver in ("owner", "setup"):
        root = tmp_path / driver / "data"
        H.tenant_dir(root, TID).mkdir(parents=True)
        target = tmp_path / driver / "outside.json"
        target.write_text("ORIGINAL OUTSIDE\n", encoding="utf-8")
        plant = H.row_path(root, TID)
        if alias == "symlink":
            plant.symlink_to(target)
        else:
            os.link(target, plant)
        before = os.lstat(target)
        if driver == "owner":
            text = str(H.owner_refusal(H.create_tenant, root, TID))
        else:
            proc = H.run_setup(root, TID)
            H.assert_setup_ran(proc)
            text = H.setup_output(proc)
            assert proc.returncode == 1, f"setup accepted a planted row alias:\n{text}"
        assert O10_TEXT not in text, (
            f"O10 short-circuited the plant ({driver}); the guarded write was never reached:\n"
            f"{text}")
        assert target.read_text(encoding="utf-8") == "ORIGINAL OUTSIDE\n", (
            f"the {alias} plant was written through ({driver})")
        assert os.lstat(target).st_mtime_ns == before.st_mtime_ns
        assert os.path.lexists(plant), "the refusal removed the plant (sanitizing, D1)"

    control = tmp_path / "control" / "data"
    H.tenant_dir(control, TID).mkdir(parents=True)
    assert H.create_tenant(control, TID).tenant_id == TID
    assert not H.row_path(control, TID).is_symlink()


# ======================================================================================
# D10 — setup is the only production caller; its writes go through create_tenant
# ======================================================================================

def _create_tenant_callers(root: Path, *, skip: tuple[str, ...]) -> set[str]:
    """Every module under `root` (repo-relative to `root.parent`) that CALLS `create_tenant`,
    by any spelling an import can give it: `x.create_tenant(...)`, a bare name bound by
    `from ... import create_tenant`, or that import's `as` alias."""
    found: set[str] = set()
    for py in sorted(root.rglob("*.py")):
        rel = py.relative_to(root.parent).as_posix()
        if any(part in (".venv", "__pycache__") for part in py.parts) or rel.startswith(skip):
            continue
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        names = {"create_tenant"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names |= {a.asname for a in node.names if a.name == "create_tenant" and a.asname}  # lint-ast-resolve: ok — a negative census widens on purpose: an alias that is later shadowed only over-reports, the safe direction
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if (isinstance(f, ast.Attribute) and f.attr == "create_tenant") or (
                    isinstance(f, ast.Name) and f.id in names):
                found.add(rel)
    return found


_PRODUCTION_SKIP = ("defender/tests/", "defender/evals/")


def test_d10_setup_only_production_caller(tmp_path):
    """tenant.py setup is the only production caller of create_tenant; evals and fixtures call
    it only against a fresh tmp root.

    The census is an AST walk over `defender/` minus the tests and the evals (O1's production
    scope), catching the attribute, bare-name and aliased spellings. Its POSITIVE CONTROL is
    the same scanner: it must FIND `scripts/tenant.py`'s call (so it is not blind), and it
    must report a planted aliased caller in a synthetic tree."""
    callers = _create_tenant_callers(H.DEFENDER, skip=_PRODUCTION_SKIP)
    assert "defender/scripts/tenant.py" in callers, (
        "the census found no call of create_tenant in defender/scripts/tenant.py — the setup "
        "command is missing, or it does not create the row through the owner")
    assert callers == {"defender/scripts/tenant.py"}, (
        f"production code other than setup calls create_tenant: {sorted(callers - {'defender/scripts/tenant.py'})}")

    fake = tmp_path / "defender"
    (fake / "runtime").mkdir(parents=True)
    (fake / "runtime" / "sneaky.py").write_text(
        "from defender._tenant import create_tenant as mint\n\n"
        "def f(root):\n    return mint(root, 'x')\n", encoding="utf-8")
    assert _create_tenant_callers(fake, skip=_PRODUCTION_SKIP) == {"defender/runtime/sneaky.py"}


def test_setup_script_under_the_ratcheted_write_lint(tmp_path):
    """defender/scripts/tenant.py adds no raw mkdir or write (the ratcheted unguarded-write
    lint); its writes go through create_tenant.

    The lint's own scanner (`lint_unguarded_tree_write._scan`) over the real script finds
    nothing; the same scanner over a synthetic `scripts/tenant.py` with a raw `.mkdir(` reports
    it (the control). And the script's row write is a call of create_tenant."""
    assert H.TENANT_PY.is_file(), f"{H.TENANT_PY} does not exist — D10's setup command"
    lint = H.mod("tests._by_path").load_lint_gate("lint_unguarded_tree_write")
    real = tmp_path / "real"
    (real / "scripts").mkdir(parents=True)
    (real / "scripts" / "tenant.py").write_text(H.TENANT_PY.read_text(encoding="utf-8"),
                                                encoding="utf-8")
    findings = lint._scan(real)
    assert findings == [], "\n".join(f.display for f in findings)
    assert _create_tenant_callers(real, skip=()) == {"real/scripts/tenant.py"}, (
        "tenant.py does not write the row through create_tenant")

    raw = tmp_path / "raw"
    (raw / "scripts").mkdir(parents=True)
    (raw / "scripts" / "tenant.py").write_text(
        "from pathlib import Path\n\ndef setup(root, tid):\n    (Path(root) / tid).mkdir()\n",
        encoding="utf-8")
    assert [f.fingerprint for f in lint._scan(raw)] == ["scripts/tenant.py:setup"]


# ======================================================================================
# D1's #1077 gate changes: the kinds row, the accessor, resolve(), the #771 census
# ======================================================================================

def _tenant_census_rows():
    census = H.mod("tests.e2e._spec771")
    return census, [w for w in census.CENSUS if w.module == "_tenant.py"]  # lint-ast-resolve: ok — `w.module` is a #771 census row's field naming the writer's file, not an import


def _landed(tmp: Path, before: set[str]) -> set[str]:
    return {p.relative_to(tmp).as_posix() for p in tmp.rglob("*") if p.is_file()} - before


def test_d1_1077_gate_registration(tmp_path, monkeypatch):
    """docs/run-records-kinds.tsv carries kind tenant_row for tenant.json with its
    _spec1077.ACCESSOR_FOR_KIND entry and a data-root-and-tenant-aware _spec1077.resolve();
    kind tenant stays pinned to _tenant.json; and the #771 census names
    ensure_runs_base_record and create_tenant.

    DRIVEN, not inspected. `resolve()` is called for kind `tenant_row` with a data root and a
    tenant (the coined keywords `data_root=` / `tenant_id=`, the names the code threads) and
    must hand back `<root>/<T>/tenant.json` — the path the real `TenantPaths(root, T).row`
    gives; kind `tenant` still resolves to `<runs_base>/_tenant.json`. The #771 census's
    `_tenant.py` rows are each DRIVEN on a clean live tree: one must land the runs-base record
    and one the tenant row (so both writers are in the census by what they write, not by a row
    label); then each is driven again with an alias planted at its artifact and must refuse
    with the outside target untouched — the create_tenant row's refusal being the write's, not
    O10's (§7 J60)."""
    rows = {r["kind"]: r for r in S.kinds_rows()}
    assert "tenant_row" in rows, "docs/run-records-kinds.tsv has no kind tenant_row"
    assert rows["tenant_row"]["path"].split("/")[-1] == H.ROW_NAME
    assert rows["tenant"]["path"] == H.RECORD_NAME, "kind tenant moved off _tenant.json"
    by_kind = {a.kind: a for a in S.ACCESSOR_FOR_KIND}
    assert "tenant_row" in by_kind, "_spec1077.ACCESSOR_FOR_KIND has no tenant_row accessor"
    root, base = tmp_path / "data", tmp_path / "data" / TID / "runs"
    got = S.resolve(by_kind["tenant_row"], run_dir=base / "r1", runs_base=base,
                    data_root=root, tenant_id=TID)
    assert Path(got) == root / TID / H.ROW_NAME == H.TenantPaths(root, TID).row
    assert S.resolve(by_kind["tenant"], run_dir=base / "r1", runs_base=base) == \
        base / H.RECORD_NAME

    census, tenant_rows = _tenant_census_rows()
    assert len(tenant_rows) >= 2, (
        f"the #771 census has {len(tenant_rows)} _tenant.py writer row(s); D1 renames the "
        "ensure_tenant row and adds a create_tenant row")
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(tmp_path / "census-root"))
    landed_names: list[str] = []
    for i, writer in enumerate(tenant_rows):
        clean = tmp_path / f"clean-{i}"
        run = census.run_tree(clean)
        before = {p.relative_to(clean).as_posix() for p in clean.rglob("*") if p.is_file()}
        outcome = census.drive_writer(writer, run)
        assert not isinstance(outcome, BaseException), (
            f"census row {writer.id} failed on a clean tree: {outcome!r}")
        new = _landed(clean, before)
        landed_names += [n.split("/")[-1] for n in new]
    assert H.RECORD_NAME in landed_names, "no census row lands the runs-base record"
    assert H.ROW_NAME in landed_names, "no census row lands the tenant row (create_tenant)"

    for i, writer in enumerate(tenant_rows):
        planted = tmp_path / f"planted-{i}"
        run = census.run_tree(planted)
        target = census.outside(planted)
        census.plant_symlink(run / writer.artifact, target)
        outcome = census.drive_writer(writer, run)
        assert isinstance(outcome, BaseException), f"{writer.id} wrote through a planted alias"
        assert O10_TEXT not in str(outcome), (
            f"{writer.id}: O10 short-circuited the plant — the guarded write was never reached")
        assert target.read_text(encoding="utf-8") == "ORIGINAL OUTSIDE\n"
