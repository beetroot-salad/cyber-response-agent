"""#1078 pass (A) — the tenant OWNER, `defender/_tenant.py` (D1, D2): the grammar, `TenantPaths`
and O11a, the row (`create_tenant` / `require_tenant`), the data root (`resolve_data_root`, its
widened learning-state refusal) and `runs_base_for`.

Driven directly: these are the owner functions every entry point is built on, and demand #0
(`d0_return_contract`) pins their return values and their ONE refusal shape. Every input is
real — the rows, the stray entries, the symlinked roots are written to the filesystem here.
See `_spec1078.py` for the coined names and the refusal-pass-through observable.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime
from pathlib import Path

import pytest

from defender.tests.tenant_1078_pass_a import _spec1078 as H

GRAMMAR = re.compile(H.GRAMMAR)


# ======================================================================================
# The grammar (O3)
# ======================================================================================

@pytest.mark.parametrize("candidate", [
    "a", "playground", "defender", "default", "a-b-c", "a0", "z" * 63, "a" * 64, "", "A",
    "../x", "a/b", "1abc", "acme\n", "-a", "a_b", "a.b", " a", "a ", "\nacme", "acme\r",
    "ａ",  # a fullwidth letter: not [a-z]
])
def test_o3_grammar_seam(candidate):
    """is_valid_tenant_id returns True exactly when re.fullmatch('^[a-z][a-z0-9-]{0,62}$', id)
    matches, and refuse_bad_tenant_id raises on exactly the ids it returns False for."""
    tenant = H.tenant()
    expected = GRAMMAR.fullmatch(candidate) is not None
    assert tenant.is_valid_tenant_id(candidate) is expected, (
        f"is_valid_tenant_id({candidate!r}) disagrees with re.fullmatch of the grammar")
    if expected:
        tenant.refuse_bad_tenant_id(candidate)  # accepted: returns without raising
    else:
        refusal = H.owner_refusal(tenant.refuse_bad_tenant_id, candidate)
        assert str(refusal), "the grammar refusal carries no message"


def test_o3_trailing_newline_refused(tmp_path, monkeypatch):
    """'acme\\n', which re.match with a '$' anchor accepts, is refused at every entry because
    the check is re.fullmatch.

    The owner's three spellings are asked here (the predicate, the refusal, the
    TenantPaths constructor, create_tenant and require_tenant); the CLI entries are
    `test_o3_grammar_refusal_parity`'s."""
    assert re.match(H.GRAMMAR, "acme\n"), "the premise moved: re.match no longer accepts it"
    tenant = H.tenant()
    root = tmp_path / "root"
    assert tenant.is_valid_tenant_id("acme\n") is False
    H.owner_refusal(tenant.refuse_bad_tenant_id, "acme\n")
    H.owner_refusal(H.TenantPaths, root, "acme\n")
    H.owner_refusal(H.create_tenant, root, "acme\n")
    H.owner_refusal(H.require_tenant, root, "acme\n")
    assert H.entries(tmp_path) == [], "a refused id created a path"


def test_o3_length_boundary(tmp_path):
    """A 63-character id of the grammar is accepted and a 64-character one is refused."""
    root = tmp_path / "root"
    ok, too_long = "a" + "b" * 62, "a" + "b" * 63
    assert len(ok) == 63
    assert len(too_long) == 64
    assert H.tenant().is_valid_tenant_id(ok) is True
    assert H.TenantPaths(root, ok).dir == root / ok
    H.make_tenant(root, ok)
    assert H.require_tenant(root, ok).tenant_id == ok
    assert H.tenant().is_valid_tenant_id(too_long) is False
    H.owner_refusal(H.TenantPaths, tmp_path / "other", too_long)
    H.owner_refusal(H.create_tenant, tmp_path / "other", too_long)
    assert not (tmp_path / "other").exists(), "the refused 64-character id created a path"


@pytest.mark.parametrize("tenant_id", ["playground", "defender"])
def test_o3_valid_id_round_trip(tmp_path, monkeypatch, tenant_id):
    """A valid id ('playground', and 'defender' under a data root outside the checkout)
    round-trips: create_tenant writes it, require_tenant and TenantPaths accept it, and
    tenant_of_run_dir on a run dir under its runs base returns it."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    written = H.create_tenant(root, tenant_id)
    assert written.tenant_id == tenant_id
    assert json.loads(H.row_path(root, tenant_id).read_text(encoding="utf-8"))["tenant_id"] == \
        tenant_id
    assert H.require_tenant(root, tenant_id).tenant_id == tenant_id
    assert H.TenantPaths(root, tenant_id).runs == root / tenant_id / "runs"
    base = H.runs_dir(root, tenant_id)
    H.plant_record(base, tenant_id)
    run_dir = base / "r1"
    run_dir.mkdir()
    assert H.tenant_of_run_dir(run_dir) == tenant_id


def test_tenant_id_at_domain_minimum_length(tmp_path):
    """The one-letter id 'a' round-trips through create_tenant, require_tenant and TenantPaths
    like any valid id."""
    root = tmp_path / "data"
    row = H.create_tenant(root, "a")
    assert row.tenant_id == "a"
    assert H.row_path(root, "a").is_file()
    assert H.require_tenant(root, "a").tenant_id == "a"
    paths = H.TenantPaths(root, "a")
    assert (paths.dir, paths.row, paths.runs) == (root / "a", root / "a" / H.ROW_NAME,
                                                  root / "a" / "runs")


# ======================================================================================
# TenantPaths (D1) and O11a
# ======================================================================================

def test_d1_tenantpaths_accessors(tmp_path):
    """TenantPaths(root, T) exposes .dir == root/T, .row == root/T/tenant.json, .runs ==
    root/T/runs, .episodes == root/T/episodes and .learning == root/T/learning."""
    root = tmp_path / "data"
    paths = H.TenantPaths(root, "playground")
    expected = {
        "dir": root / "playground",
        "row": root / "playground" / "tenant.json",
        "runs": root / "playground" / "runs",
        "episodes": root / "playground" / "episodes",
        "learning": root / "playground" / "learning",
    }
    got = {name: getattr(paths, name) for name in expected}
    assert got == expected
    assert not root.exists(), "constructing TenantPaths created something: it is a path owner"


def test_s7_j03_tenantpaths_relative_root_refused(tmp_path, monkeypatch):
    """TenantPaths(data_root, T) refuses a relative data_root at the constructor, naming it,
    and creates nothing; an absolute root is accepted (the control)."""
    monkeypatch.chdir(tmp_path)
    before = H.census(tmp_path)
    refusal = H.owner_refusal(H.TenantPaths, Path("rel/root"), "playground")
    assert "rel/root" in str(refusal), f"the refusal does not name the relative root: {refusal}"
    H.owner_refusal(H.TenantPaths, "rel/root", "playground")
    assert H.census(tmp_path) == before, "the refused relative root created something"
    assert H.TenantPaths(tmp_path / "abs", "playground").dir == tmp_path / "abs" / "playground"


def test_o11a_root_inside_defender_refused(tmp_path):
    """TenantPaths(<checkout>/defender/x, 'playground') is refused, also when the root is
    reached through a symlink."""
    checkout_defender = H.mod("_paths").PATHS.defender_dir
    assert checkout_defender == H.DEFENDER, "the suite is importing another checkout's package"
    refusal = H.owner_refusal(H.TenantPaths, checkout_defender / "x", "playground")
    assert "playground" in str(refusal) or str(checkout_defender) in str(refusal)
    link = tmp_path / "innocent-looking-root"
    link.symlink_to(checkout_defender / "x", target_is_directory=True)
    H.owner_refusal(H.TenantPaths, link, "playground")
    assert not (checkout_defender / "x").exists(), "a refused root was created inside defender/"


def test_o11a_checkout_root_tenant_defender_refused():
    """TenantPaths(<checkout>, 'defender') is refused because its folder is the mounted
    defender/ tree."""
    checkout = H.mod("_paths").PATHS.defender_dir.parent
    H.owner_refusal(H.TenantPaths, checkout, "defender")


def test_o11a_positive_control():
    """TenantPaths(<checkout>/.defender-data, 'playground') is accepted."""
    checkout = H.mod("_paths").PATHS.defender_dir.parent
    paths = H.TenantPaths(checkout / ".defender-data", "playground")
    assert paths.dir == checkout / ".defender-data" / "playground"


def test_checkout_path_itself_reached_through_a_symlink(tmp_path):
    """O11a's refusal holds when the checkout path is reached through a symlink: the
    comparison is between resolved paths."""
    checkout = H.mod("_paths").PATHS.defender_dir.parent
    link = tmp_path / "checkout-link"
    link.symlink_to(checkout, target_is_directory=True)
    H.owner_refusal(H.TenantPaths, link, "defender")
    H.owner_refusal(H.TenantPaths, link / "defender" / "x", "playground")
    # the control: the same symlinked checkout, at an allowed location, is accepted
    assert H.TenantPaths(link / ".defender-data", "playground").dir.name == "playground"


def test_data_root_inside_another_checkouts_mounted_tree(tmp_path):
    """O11a does not refuse a data root inside ANOTHER checkout's defender/ (N13's stated
    non-obligation). Whether this non-check is pinned as a test rides demand fork F6 — kept
    as a test (§7 F6, auto)."""
    other = tmp_path / "other-checkout"
    (other / ".git").mkdir(parents=True)
    (other / "defender").mkdir()
    paths = H.TenantPaths(other / "defender" / "data", "playground")
    assert paths.dir == other / "defender" / "data" / "playground"
    # and the running checkout's own tree is still refused beside it (the pair is not vacuous)
    H.owner_refusal(H.TenantPaths, H.mod("_paths").PATHS.defender_dir / "data", "playground")


# ======================================================================================
# The row: create_tenant / require_tenant (D1, O2, O10)
# ======================================================================================

def test_d1_row_shape(tmp_path):
    """The row is a JSON object holding tenant_id (equal to the id) and created_at."""
    root = tmp_path / "data"
    H.create_tenant(root, "playground")
    doc = json.loads(H.row_path(root, "playground").read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    assert set(doc) == {"tenant_id", "created_at"}, f"the row carries {sorted(doc)}"
    assert doc["tenant_id"] == "playground"
    assert isinstance(doc["created_at"], str)
    datetime.fromisoformat(doc["created_at"])  # an ISO timestamp, not free text


@pytest.mark.parametrize("fault", [
    "absent", "invalid-json", "list-top-level", "non-utf8", "missing-tenant_id",
    "missing-created_at", "non-string-tenant_id", "non-string-created_at",
    "off-grammar-tenant_id", "disagreeing-tenant_id", "directory-at-row", "dangling-link",
])
def test_d1_require_tenant_refusals(tmp_path, fault):
    """require_tenant refuses an absent row, a corrupt row (invalid JSON, a non-object top
    level, a decode error, or a missing or non-string tenant_id or created_at), a row whose
    tenant_id is off-grammar, and a row whose tenant_id disagrees with its folder (refused as
    corrupt); every refusal names the path.

    The directory squatting the row's name and the dangling link are §7 J22's fold (a
    directory reads as corrupt, a dangling link as absent): refused either way."""
    root = tmp_path / "data"
    row = H.row_path(root, "playground")
    row.parent.mkdir(parents=True)
    plant = {
        "absent": lambda: None,
        "invalid-json": lambda: H.plant_row(root, "playground", "{not json"),
        "list-top-level": lambda: H.plant_row(root, "playground", '["playground"]'),
        "non-utf8": lambda: H.plant_row(root, "playground", b'{"tenant_id": "\xff\xfe"}'),
        "missing-tenant_id": lambda: H.plant_row(root, "playground", drop="tenant_id"),
        "missing-created_at": lambda: H.plant_row(root, "playground", drop="created_at"),
        "non-string-tenant_id": lambda: H.plant_row(
            root, "playground", '{"tenant_id": 7, "created_at": "2026-09-26T00:00:00+00:00"}'),
        "non-string-created_at": lambda: H.plant_row(root, "playground", created_at=17),
        "off-grammar-tenant_id": lambda: H.plant_row(root, "playground",
                                                     row_tenant_id="../../x"),
        "disagreeing-tenant_id": lambda: H.plant_row(root, "playground", row_tenant_id="other"),
        "directory-at-row": lambda: row.mkdir(),
        "dangling-link": lambda: row.symlink_to(tmp_path / "nowhere.json"),
    }[fault]
    plant()
    refusal = H.owner_refusal(H.require_tenant, root, "playground")
    assert str(row) in str(refusal), f"the {fault} refusal does not name the row: {refusal}"
    # the control: a well-formed row for the same folder is accepted
    good = tmp_path / "good"
    H.plant_row(good, "playground")
    assert H.require_tenant(good, "playground").tenant_id == "playground"


def test_n13_require_tenant_ignores_other_rows(tmp_path):
    """require_tenant(root, T) succeeds when the data root also holds a second, hand-made
    tenant row."""
    root = tmp_path / "data"
    H.create_tenant(root, "playground")
    H.plant_row(root, "other")
    row = H.require_tenant(root, "playground")
    assert row.tenant_id == "playground"


def test_d1_create_exclusive(tmp_path):
    """Two create_tenant calls for the same id cannot both succeed; the loser refuses and the
    row is the winner's.

    Sequential (the second call meets the first's row) and concurrent (N callers released
    together onto one empty root): exactly one returns, every other one REFUSES — the owner's
    ValueError, not an escaping FileExistsError (§7 J12: the loser refuses naming that the
    row exists) — and the row on disk is the winner's."""
    root = tmp_path / "seq"
    first = H.create_tenant(root, "playground")
    bytes_after_first = H.row_path(root, "playground").read_bytes()
    H.owner_refusal(H.create_tenant, root, "playground")
    assert H.row_path(root, "playground").read_bytes() == bytes_after_first
    assert json.loads(bytes_after_first)["created_at"] == first.created_at

    for trial in range(20):
        root = tmp_path / f"race-{trial}"
        n = 6
        gate = threading.Barrier(n)
        won: list = []
        lost: list = []

        def attempt(gate=gate, root=root, won=won, lost=lost) -> None:
            gate.wait(timeout=30)
            try:
                won.append(H.create_tenant(root, "playground"))
            except BaseException as refused:  # noqa: BLE001 — classified below
                lost.append(refused)

        threads = [threading.Thread(target=attempt) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert len(won) == 1, f"trial {trial}: {len(won)} creates of one id succeeded"
        assert all(isinstance(e, ValueError) for e in lost), (
            f"trial {trial}: a loser escaped with {[type(e).__name__ for e in lost]} rather "
            "than the owner's refusal")
        on_disk = json.loads(H.row_path(root, "playground").read_text(encoding="utf-8"))
        assert on_disk["created_at"] == won[0].created_at, "the row is not the winner's"


# ======================================================================================
# The data root (D2) and runs_base_for
# ======================================================================================

def test_d2_resolve_data_root(tmp_path, monkeypatch):
    """resolve_data_root refuses a relative DEFENDER_DATA_ROOT and returns an absolute value
    .resolve()d, so a symlinked root resolves to its target."""
    monkeypatch.chdir(tmp_path)
    H.set_data_root(monkeypatch, "relative/data")
    refusal = H.owner_refusal(H.resolve_data_root)
    assert "relative/data" in str(refusal) or H.DATA_ROOT_ENV in str(refusal)
    assert not (tmp_path / "relative").exists()

    target = tmp_path / "real-data"
    target.mkdir()
    link = tmp_path / "data-link"
    link.symlink_to(target, target_is_directory=True)
    H.set_data_root(monkeypatch, link)
    assert H.resolve_data_root() == target.resolve()

    H.set_data_root(monkeypatch, tmp_path / "plain" / ".." / "plain")
    got = H.resolve_data_root()
    assert got.is_absolute()
    assert got == (tmp_path / "plain").resolve()


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_d2_data_root_default(tmp_path, monkeypatch, value):
    """With DEFENDER_DATA_ROOT unset, resolve_data_root refuses, naming the variable; an empty
    value is refused the same way (parametrized); a set absolute value resolves (the
    control). There is no code default."""
    if value is None:
        H.set_data_root(monkeypatch, None)
    else:
        monkeypatch.setenv(H.DATA_ROOT_ENV, value)
    refusal = H.owner_refusal(H.resolve_data_root)
    assert H.DATA_ROOT_ENV in str(refusal), f"the refusal does not name the variable: {refusal}"
    H.set_data_root(monkeypatch, tmp_path / "set")
    assert H.resolve_data_root() == (tmp_path / "set").resolve()


def test_d2_runs_base_for(tmp_path, monkeypatch):
    """runs_base_for(T) equals TenantPaths(resolve_data_root(), T).runs, that is
    <root>/T/runs."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    assert H.runs_base_for("playground") == root.resolve() / "playground" / "runs"
    assert H.runs_base_for("playground") == H.TenantPaths(H.resolve_data_root(),
                                                          "playground").runs
    H.owner_refusal(H.runs_base_for, "../x")


def test_data_root_itself_is_a_symlink(tmp_path, monkeypatch):
    """A symlinked data root: resolve_data_root returns the resolved target, so O10's scan
    lists the target's entries and any refusal names resolved paths."""
    target = tmp_path / "target-root"
    target.mkdir()
    (target / "stray").write_text("x", encoding="utf-8")
    link = tmp_path / "root-link"
    link.symlink_to(target, target_is_directory=True)
    H.set_data_root(monkeypatch, link)
    resolved = H.resolve_data_root()
    assert resolved == target.resolve()
    refusal = H.owner_refusal(H.create_tenant, resolved, "playground")
    assert "stray" in str(refusal), f"O10's scan did not list the target's entry: {refusal}"
    assert str(link) not in str(refusal), "the refusal names the unresolved link"
    assert H.entries(target) == ["stray"], "the refused create wrote into the target"


@pytest.mark.parametrize("shape", ["equal", "learning-inside-data-root",
                                   "learning-contains-data-root", "equal-through-a-symlink"])
def test_o13_widened_refusal(tmp_path, monkeypatch, shape):
    """The learning-state refusal, which lives in resolve_data_root, refuses a learning state
    root equal to, nested inside, or containing the data root, comparing resolved paths, and
    a disjoint pair passes."""
    data = tmp_path / "data"
    data.mkdir()
    learning = {
        "equal": data,
        "learning-inside-data-root": data / "playground" / "learning",
        "learning-contains-data-root": tmp_path,
        "equal-through-a-symlink": tmp_path / "learning-link",
    }[shape]
    if shape == "equal-through-a-symlink":
        learning.symlink_to(data, target_is_directory=True)
    H.set_data_root(monkeypatch, data)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(learning))
    H.owner_refusal(H.resolve_data_root)
    # the control: a disjoint pair passes
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "elsewhere" / "learning"))
    assert H.resolve_data_root() == data.resolve()


def test_widened_refusal_meets_the_pass_c_layout_early(tmp_path, monkeypatch):
    """DEFENDER_LEARNING_STATE_DIR=<root>/T/learning set during (A) is refused by the widened
    refusal, because it lies inside the data root. This holds under demand fork F3's
    provisional reading (§7 F3, auto: the data root is the compared side)."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.create_tenant(root, "playground")
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root / "playground" / "learning"))
    H.owner_refusal(H.resolve_data_root)
    H.owner_refusal(H.runs_base_for, "playground")


# ======================================================================================
# Demand #0 — the return contract and the ONE refusal shape
# ======================================================================================

def _common_refusal_class(refusals: dict[str, BaseException]) -> type:
    """The most specific class every refusal is an instance of, below `ValueError`."""
    first = next(iter(refusals.values()))
    for cls in type(first).__mro__:
        if cls in (ValueError, Exception, BaseException, object):
            break
        if all(isinstance(e, cls) for e in refusals.values()):
            return cls
    raise AssertionError(
        "the owner functions do not refuse through ONE ValueError subclass: "
        + ", ".join(f"{k} raised {type(v).__mro__[:3]}" for k, v in refusals.items()))


def test_d0_return_contract(tmp_path, monkeypatch):
    """require_tenant returns a TenantRow whose tenant_id equals the requested id and whose
    created_at is the row's; tenant_of_run_dir returns the tenant id as a str; create_tenant
    returns the TenantRow it wrote; TenantPaths accessors return absolute Paths under .dir.
    The owner functions (TenantPaths, create_tenant, require_tenant, tenant_of_run_dir,
    ensure_runs_base_record, resolve_data_root, refuse_bad_tenant_id) refuse by raising one
    ValueError subclass whose message names the refused value; run.py main surfaces a tenant
    refusal as SystemExit carrying a '[run.py] ...' message before the preflight, exactly as
    _resume_target does today; the branch launcher surfaces it as LauncherRefused; tenant.py
    setup returns 0 when every kind of its pass adopted, was already in place, or had nothing
    to adopt, and 1 when any kind was refused or a racing entry was re-listed; a selector tool
    given no --tenant exits non-zero before touching any state. Every entry passes the owner's
    refusal message through verbatim, never rephrased."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    _d0_return_values(root)
    refusals = _d0_owner_refusals(tmp_path, root, monkeypatch)
    _d0_entry_surfaces(tmp_path, root, refusals)


def _d0_return_values(root: Path) -> None:
    """#0's return half: the row types, the absolute accessors, the derived str."""
    written = H.create_tenant(root, "playground")
    on_disk = json.loads(H.row_path(root, "playground").read_text(encoding="utf-8"))
    assert (written.tenant_id, written.created_at) == (on_disk["tenant_id"],
                                                        on_disk["created_at"])
    got = H.require_tenant(root, "playground")
    assert type(got) is type(written), "require_tenant and create_tenant return different types"
    assert (got.tenant_id, got.created_at) == ("playground", on_disk["created_at"])
    paths = H.TenantPaths(root, "playground")
    for name in ("row", "runs", "episodes", "learning"):
        value = getattr(paths, name)
        assert isinstance(value, Path)
        assert value.is_absolute()
        assert paths.dir in value.parents, f"TenantPaths.{name} is not under .dir"
    base = H.runs_dir(root, "playground")
    H.plant_record(base, "playground")
    (base / "r1").mkdir()
    derived = H.tenant_of_run_dir(base / "r1")
    assert derived == "playground"
    assert type(derived) is str


def _d0_owner_refusals(tmp_path: Path, root: Path, monkeypatch) -> dict:
    """#0's refusal half: every owner function refuses through ONE ValueError subclass, and
    each refusal names the value it refused. Returns `{owner: (refusal, named value)}`."""
    old_base = tmp_path / "old-runs"
    H.plant_record(old_base, "playground")
    (old_base / "r0").mkdir()
    other_base = tmp_path / "other-base"
    H.plant_record(other_base, "someone-else")
    refusals = {
        "refuse_bad_tenant_id": (H.owner_refusal(H.tenant().refuse_bad_tenant_id, "../x"),
                                 "../x"),
        "TenantPaths": (H.owner_refusal(H.TenantPaths, root, "Acme-Corp"), "Acme-Corp"),
        "create_tenant": (H.owner_refusal(H.create_tenant, tmp_path / "x", "a/b"), "a/b"),
        "require_tenant": (H.owner_refusal(H.require_tenant, root, "acme"), "acme"),
        "tenant_of_run_dir": (H.owner_refusal(H.tenant_of_run_dir, old_base / "r0"),
                              str(old_base)),
        "ensure_runs_base_record": (
            H.owner_refusal(H.ensure_runs_base_record, other_base, "playground"),
            "someone-else"),
    }
    monkeypatch.delenv(H.DATA_ROOT_ENV)
    refusals["resolve_data_root"] = (H.owner_refusal(H.resolve_data_root), H.DATA_ROOT_ENV)
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
    _common_refusal_class({k: v[0] for k, v in refusals.items()})
    for owner, (exc, names) in refusals.items():
        assert names in str(exc), f"{owner}'s refusal does not name the refused value: {exc}"
    refusals["old_run_dir"] = (None, old_base / "r0")
    return refusals


def _d0_entry_surfaces(tmp_path: Path, root: Path, refusals: dict) -> None:
    """#0's entry half: each entry surfaces the owner's refusal in its own convention and
    passes the owner's message through verbatim; setup's exit status; a selector tool."""
    rec = H.Recorder(tmp_path / "never")
    rc, refused = H.drive_main([str(H.plant_alert(tmp_path / "a")), "--tenant", "acme"], rec)
    assert rc is None, "run.py accepted an unknown tenant"
    assert refused is not None
    text = H.refusal_text(refused)
    assert text.startswith("[run.py] "), f"run.py's refusal is not a '[run.py] ...' exit: {text}"
    H.assert_verbatim(text, refusals["require_tenant"][0], entry="run.py main")
    assert not rec.spent, f"run.py spent before refusing: {rec.order}"

    launched = H.drive_launch(refusals["old_run_dir"][1])
    assert isinstance(launched, H.branch_cli().LauncherRefused), (
        f"the launcher did not surface the tenant refusal as LauncherRefused: {launched!r}")
    H.assert_verbatim(H.refusal_text(launched), refusals["tenant_of_run_dir"][0],
                      entry="the branch launcher")

    fresh = tmp_path / "fresh-root"
    ok = H.run_setup(fresh, "playground")
    H.assert_setup_ran(ok)
    assert ok.returncode == 0, H.setup_output(ok)
    again = H.run_setup(fresh, "playground")
    assert again.returncode == 0, "a same-id re-run (nothing to adopt in pass A) is not 0"
    crowded = tmp_path / "crowded"
    H.plant_row(crowded, "other")
    no = H.run_setup(crowded, "playground")
    assert no.returncode == 1, f"a refused setup exits {no.returncode}, not 1"
    H.assert_verbatim(H.setup_output(no),
                      H.owner_refusal(H.create_tenant, crowded, "playground"),
                      entry="tenant.py setup")

    held_out = H.mod("evals.held_out")
    before = H.census(root)
    try:
        status = held_out.main([])
    except SystemExit as refused_selector:
        status = refused_selector.code
    assert status not in (0, None), "held_out with neither --tenant nor a runs dir ran"
    assert H.census(root) == before, "the refused selector tool touched the data root"
