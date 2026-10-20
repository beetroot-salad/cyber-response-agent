"""The tenant owner (tenancy/_tenant.py): id grammar, checkout/data-root placement refusals, row create/require, data-root and learning-state resolution."""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import pytest

from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

RUN_ID = fixture_uuid("r1")

GRAMMAR = re.compile(H.GRAMMAR)


@pytest.mark.parametrize(("candidate", "expected"), [
    (fixture_uuid("tenant:acme"), True),
    ("00000000-0000-0000-0000-000000000000", True),
    ("ffffffff-ffff-ffff-ffff-ffffffffffff", True),
    *[(text, False) for text in (
        "acme", "playground", "defender", "default", "a", "a-b-c", "a0", "z" * 63,
        "a" * 64, "", "A", "../x", "a/b", "1abc", "acme\n", "-a", "a_b", "a.b",
        " a", "a ", "\nacme", "acme\r", "ａ",
        fixture_uuid("tenant:acme").upper(), fixture_uuid("tenant:acme").replace("-", ""),
        "{" + fixture_uuid("tenant:acme") + "}", "urn:uuid:" + fixture_uuid("tenant:acme"),
        " " + fixture_uuid("tenant:acme"), fixture_uuid("tenant:acme") + "\n",
    )],
])
def test_o3_grammar_seam(candidate, expected):
    tenant = H.tenant()
    assert (GRAMMAR.fullmatch(candidate) is not None) is expected
    assert tenant.is_valid_tenant_id(candidate) is expected
    if expected:
        assert str(tenant.TenantId(candidate)) == candidate
    else:
        assert str(H.owner_refusal(tenant.TenantId, candidate))


def test_o3_trailing_newline_refused(tmp_path):
    raw = fixture_uuid("tenant:acme") + "\n"
    assert re.match(H.GRAMMAR, raw), "control: a prefix match would admit the newline"
    tenant = H.tenant()
    root = tmp_path / "root"
    assert tenant.is_valid_tenant_id(raw) is False
    H.owner_refusal(tenant.TenantId, raw)
    H.owner_refusal(H.TenantPaths, root, raw)
    H.owner_refusal(H.create_tenant, root, raw)
    H.owner_refusal(H.require_tenant, root, raw)
    assert H.entries(tmp_path) == [], "a refused id created a path"


def test_o3_only_canonical_uuid_spelling_reaches_tenant_paths_and_rows(tmp_path):
    root = tmp_path / "root"
    ok = fixture_uuid("tenant:acme")
    assert len(ok) == 36
    assert H.tenant().is_valid_tenant_id(ok) is True
    assert H.TenantPaths(root, ok).dir == root / ok
    H.make_tenant(root, ok)
    assert H.require_tenant(root, ok).tenant_id == ok
    for malformed in (ok.replace("-", ""), ok.upper(), "{" + ok + "}", ok + "x"):
        assert H.tenant().is_valid_tenant_id(malformed) is False
        H.owner_refusal(H.TenantPaths, tmp_path / "other", malformed)
        H.owner_refusal(H.create_tenant, tmp_path / "other", malformed)
    assert not (tmp_path / "other").exists(), "a noncanonical id created a path"


def test_minted_tenant_ids_are_distinct_canonical_uuid4():
    import uuid

    ids = [H.tenant().TenantId.mint() for _ in range(8)]
    assert len(set(ids)) == len(ids)
    for tenant_id in ids:
        assert isinstance(tenant_id, H.tenant().TenantId)
        parsed = uuid.UUID(tenant_id)
        assert parsed.version == 4
        assert parsed.variant == uuid.RFC_4122
        assert str(parsed) == tenant_id


@pytest.mark.parametrize("existing", [False, True], ids=["no-folder", "legacy-folder"])
@pytest.mark.parametrize("legacy", ["acme", "playground", "blue", "tenant-a"])
@pytest.mark.parametrize("door", ["TenantId", "requested_tenant_id", "paths", "create", "require", "accept"])
def test_legacy_tenant_names_are_refused_by_every_admission_door(tmp_path, legacy, door, existing):
    owner = H.tenant()
    root = tmp_path / "data"
    if existing:
        H.place_knowledge(root, legacy)
        H.plant_row(root, legacy)
    before = H.census(tmp_path)
    calls = {
        "TenantId": lambda: owner.TenantId(legacy),
        "requested_tenant_id": lambda: owner.requested_tenant_id(legacy),
        "paths": lambda: H.TenantPaths(root, legacy),
        "create": lambda: H.create_tenant(root, legacy),
        "require": lambda: H.require_tenant(root, legacy),
        "accept": lambda: H.accept(root, legacy),
    }
    error = H.owner_refusal(calls[door])
    assert legacy in str(error), error
    assert H.census(tmp_path) == before, "a legacy-name request changed the data root"
    if not existing:
        assert not root.exists(), "a legacy-name request created the data root"


@pytest.mark.parametrize("tenant_id", [fixture_uuid("tenant:playground"), fixture_uuid("tenant:defender")])
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
    # #1187 R1 (review-4 F42): no container record — the run's tenant is where it sits.
    run_dir = base / RUN_ID
    run_dir.mkdir(parents=True)
    assert _opened_tenant(root, tenant_id, RUN_ID) == tenant_id



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
    refusal = H.owner_refusal(H.TenantPaths, Path("rel/root"), fixture_uuid("tenant:playground"))
    assert "rel/root" in str(refusal), f"the refusal does not name the relative root: {refusal}"
    H.owner_refusal(H.TenantPaths, "rel/root", fixture_uuid("tenant:playground"))
    assert H.census(tmp_path) == before, "the refused relative root created something"
    assert H.TenantPaths(tmp_path / "abs", fixture_uuid("tenant:playground")).dir == tmp_path / "abs" / fixture_uuid("tenant:playground")


def test_o11a_root_inside_defender_refused(tmp_path):
    """TenantPaths(<checkout>/defender/x, 'playground') is refused, also when the root is
    reached through a symlink."""
    checkout_defender = H.mod("_paths").PATHS.defender_dir
    assert checkout_defender == H.DEFENDER, "the suite is importing another checkout's package"
    refusal = H.owner_refusal(H.TenantPaths, checkout_defender / "x", fixture_uuid("tenant:playground"))
    assert fixture_uuid("tenant:playground") in str(refusal) or str(checkout_defender) in str(refusal)
    link = tmp_path / "innocent-looking-root"
    link.symlink_to(checkout_defender / "x", target_is_directory=True)
    H.owner_refusal(H.TenantPaths, link, fixture_uuid("tenant:playground"))
    assert not (checkout_defender / "x").exists(), "a refused root was created inside defender/"


def test_o11a_uuid_tenant_linked_into_the_checkout_is_refused(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    tenant_id = fixture_uuid("tenant:mounted-checkout")
    (root / tenant_id).symlink_to(H.DEFENDER, target_is_directory=True)
    before = H.census(root)
    refused = H.owner_refusal(H.TenantPaths, root, tenant_id)
    assert "inside the checkout" in str(refused), refused
    assert str(H.DEFENDER) in str(refused), refused
    assert H.census(root) == before, "a refused mounted tenant changed its root"
    assert H.TenantPaths(tmp_path / "outside", tenant_id).dir == tmp_path / "outside" / tenant_id


def test_checkout_path_itself_reached_through_a_symlink(tmp_path):
    """O11a's refusal holds when the checkout path is reached through a symlink: the
    comparison is between resolved paths."""
    checkout = H.mod("_paths").PATHS.defender_dir.parent
    link = tmp_path / "checkout-link"
    link.symlink_to(checkout, target_is_directory=True)
    H.owner_refusal(H.TenantPaths, link / "defender", fixture_uuid("tenant:playground"))
    H.owner_refusal(H.TenantPaths, link / "defender" / "x", fixture_uuid("tenant:playground"))
    # the control: the same symlinked checkout, at an allowed location, is accepted
    assert H.TenantPaths(link / ".defender-data", fixture_uuid("tenant:playground")).dir.name == fixture_uuid("tenant:playground")


def test_data_root_inside_another_checkouts_mounted_tree(tmp_path):
    other = tmp_path / "other-checkout"
    (other / ".git").mkdir(parents=True)
    (other / "defender").mkdir()
    paths = H.TenantPaths(other / "defender" / "data", fixture_uuid("tenant:playground"))
    assert paths.dir == other / "defender" / "data" / fixture_uuid("tenant:playground")
    # and the running checkout's own tree is still refused beside it (the pair is not vacuous)
    H.owner_refusal(H.TenantPaths, H.mod("_paths").PATHS.defender_dir / "data", fixture_uuid("tenant:playground"))


@pytest.mark.parametrize("fault", [
    "absent", "invalid-json", "list-top-level", "non-utf8", "missing-tenant_id",
    "missing-created_at", "non-string-tenant_id", "non-string-created_at",
    "off-grammar-tenant_id", "disagreeing-tenant_id", "directory-at-row", "dangling-link",
])
def test_d1_require_tenant_refusals(tmp_path, fault):
    root = tmp_path / "data"
    row = H.row_path(root, fixture_uuid("tenant:playground"))
    row.parent.mkdir(parents=True)
    plant = {
        "absent": lambda: None,
        "invalid-json": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), "{not json"),
        "list-top-level": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), '["playground"]'),
        "non-utf8": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), b'{"tenant_id": "\xff\xfe"}'),
        "missing-tenant_id": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), drop="tenant_id"),
        "missing-created_at": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), drop="created_at"),
        "non-string-tenant_id": lambda: H.plant_row(
            root, fixture_uuid("tenant:playground"), '{"tenant_id": 7, "created_at": "2026-09-26T00:00:00+00:00"}'),
        "non-string-created_at": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), created_at=17),
        "off-grammar-tenant_id": lambda: H.plant_row(root, fixture_uuid("tenant:playground"),
                                                     row_tenant_id="../../x"),
        "disagreeing-tenant_id": lambda: H.plant_row(root, fixture_uuid("tenant:playground"), row_tenant_id=fixture_uuid("tenant:other")),
        "directory-at-row": lambda: row.mkdir(),
        "dangling-link": lambda: row.symlink_to(tmp_path / "nowhere.json"),
    }[fault]
    plant()
    refusal = H.owner_refusal(H.require_tenant, root, fixture_uuid("tenant:playground"))
    assert str(row) in str(refusal), f"the {fault} refusal does not name the row: {refusal}"
    # the control: a well-formed row for the same folder is accepted
    good = tmp_path / "good"
    H.plant_row(good, fixture_uuid("tenant:playground"))
    assert H.require_tenant(good, fixture_uuid("tenant:playground")).tenant_id == fixture_uuid("tenant:playground")


def test_d1_create_exclusive(tmp_path):
    """Two create_tenant calls for the same id cannot both succeed; the loser refuses and the
    row is the winner's."""
    root = tmp_path / "seq"
    first = H.create_tenant(root, fixture_uuid("tenant:playground"))
    bytes_after_first = H.row_path(root, fixture_uuid("tenant:playground")).read_bytes()
    H.owner_refusal(H.create_tenant, root, fixture_uuid("tenant:playground"))
    assert H.row_path(root, fixture_uuid("tenant:playground")).read_bytes() == bytes_after_first
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
                won.append(H.create_tenant(root, fixture_uuid("tenant:playground")))
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
        on_disk = json.loads(H.row_path(root, fixture_uuid("tenant:playground")).read_text(encoding="utf-8"))
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
    refusal = H.owner_refusal(H.create_tenant, resolved, fixture_uuid("tenant:playground"))
    assert "stray" in str(refusal), f"O10's scan did not list the target's entry: {refusal}"
    assert str(link) not in str(refusal), "the refusal names the unresolved link"
    assert H.entries(target) == ["stray"], "the refused create wrote into the target"


@pytest.mark.parametrize("shape", ["equal", "learning-inside-data-root",
                                   "learning-contains-data-root", "equal-through-a-symlink"])
def test_1186_legacy_state_override_cannot_refuse_the_data_root(tmp_path, monkeypatch, shape):
    data = tmp_path / "data"
    data.mkdir()
    learning = {
        "equal": data,
        "learning-inside-data-root": data / fixture_uuid("tenant:playground") / "learning",
        "learning-contains-data-root": tmp_path,
        "equal-through-a-symlink": tmp_path / "learning-link",
    }[shape]
    if shape == "equal-through-a-symlink":
        learning.symlink_to(data, target_is_directory=True)
    H.set_data_root(monkeypatch, data)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(learning))
    assert H.resolve_data_root() == data.resolve(), "O1: the retired state override is inert"
    # Both overlapping and disjoint stale overrides are ignored.
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "elsewhere" / "learning"))
    assert H.resolve_data_root() == data.resolve()
