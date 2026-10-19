"""The tenant owner (tenancy/_tenant.py): id grammar, checkout/data-root placement refusals, row create/require, data-root and learning-state resolution."""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

GRAMMAR = re.compile(H.GRAMMAR)


@pytest.mark.parametrize("candidate", [
    "a", "playground", "defender", "default", "a-b-c", "a0", "z" * 63, "a" * 64, "", "A",
    "../x", "a/b", "1abc", "acme\n", "-a", "a_b", "a.b", " a", "a ", "\nacme", "acme\r",
    "ａ",  # a fullwidth letter: not [a-z]
])
def test_o3_grammar_seam(candidate):
    """is_valid_tenant_id returns True exactly when re.fullmatch('^[a-z][a-z0-9-]{0,62}$', id)
    matches, and constructing a TenantId raises on exactly the ids it returns False for."""
    tenant = H.tenant()
    expected = GRAMMAR.fullmatch(candidate) is not None
    assert tenant.is_valid_tenant_id(candidate) is expected, (
        f"is_valid_tenant_id({candidate!r}) disagrees with re.fullmatch of the grammar")
    if expected:
        tenant.TenantId(candidate)  # accepted: returns without raising
    else:
        refusal = H.owner_refusal(tenant.TenantId, candidate)
        assert str(refusal), "the grammar refusal carries no message"


def test_o3_trailing_newline_refused(tmp_path, monkeypatch):
    assert re.match(H.GRAMMAR, "acme\n"), "the premise moved: re.match no longer accepts it"
    tenant = H.tenant()
    root = tmp_path / "root"
    assert tenant.is_valid_tenant_id("acme\n") is False
    H.owner_refusal(tenant.TenantId, "acme\n")
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
    assert _opened_tenant(root, tenant_id, "r1") == tenant_id


def _opened_tenant(root: Path, tenant_id: str, run_id: str) -> str:
    """The tenant the run `run_id` is addressed to, opened through `tenant_id`'s runs repository
    under `root` once its operator-placed knowledge is there (#1120 DC2) — the replacement for
    `tenant_of_run_dir` (#1105 PR 2, F-13)."""
    from defender.run_repository import RunId

    H.place_knowledge_for_rows()
    return H.accept(root, tenant_id).runs_repository().open(RunId.parse(run_id)).tenant_id


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
    other = tmp_path / "other-checkout"
    (other / ".git").mkdir(parents=True)
    (other / "defender").mkdir()
    paths = H.TenantPaths(other / "defender" / "data", "playground")
    assert paths.dir == other / "defender" / "data" / "playground"
    # and the running checkout's own tree is still refused beside it (the pair is not vacuous)
    H.owner_refusal(H.TenantPaths, H.mod("_paths").PATHS.defender_dir / "data", "playground")


@pytest.mark.parametrize("fault", [
    "absent", "invalid-json", "list-top-level", "non-utf8", "missing-tenant_id",
    "missing-created_at", "non-string-tenant_id", "non-string-created_at",
    "off-grammar-tenant_id", "disagreeing-tenant_id", "directory-at-row", "dangling-link",
])
def test_d1_require_tenant_refusals(tmp_path, fault):
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


def test_d1_create_exclusive(tmp_path):
    """Two create_tenant calls for the same id cannot both succeed; the loser refuses and the
    row is the winner's."""
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
        assert all(isinstance(e, H.tenant().TenantRefused) for e in lost), (
            f"trial {trial}: a loser escaped with {[type(e).__name__ for e in lost]} rather "
            "than the owner's refusal")
        on_disk = json.loads(H.row_path(root, "playground").read_text(encoding="utf-8"))
        assert on_disk["created_at"] == won[0].created_at, "the row is not the winner's"


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
    if value is None:
        H.set_data_root(monkeypatch, None)
    else:
        monkeypatch.setenv(H.DATA_ROOT_ENV, value)
    refusal = H.owner_refusal(H.resolve_data_root)
    assert H.DATA_ROOT_ENV in str(refusal), f"the refusal does not name the variable: {refusal}"
    H.set_data_root(monkeypatch, tmp_path / "set")
    assert H.resolve_data_root() == (tmp_path / "set").resolve()


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
