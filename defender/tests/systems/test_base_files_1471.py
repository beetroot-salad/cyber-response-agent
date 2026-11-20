"""#1471 P-8, P-9, A5: base files are adapter-level content rendered under the system name, named by a content digest, and every
shipped set passes connect's scaffold validator. One literal case pins the framing (surface §7); the other digest cases assert properties."""
from __future__ import annotations

import dataclasses
import importlib
from pathlib import Path

import pytest

from defender._git import REPO_ROOT
from defender.systems.catalog import Catalog
from defender.tests.tenancy.adoption_1471._forge import RENDERING

DEFENDER = Path(__file__).resolve().parents[2]
FIXTURE_AGENT = DEFENDER / "tests" / "fixtures" / "tenant-fixture" / "agent"
TENANT_TEMPLATE_SKILLS = REPO_ROOT / "knowledge" / "tenant-template" / "agent" / "skills"


def _base():
    return importlib.import_module("defender.system_rules.base_files")


def _catalog() -> Catalog:
    return Catalog.of_checkout(DEFENDER)


def _entry_over(folder: Path, adapter: str = "cmdb"):
    """The real catalog entry of `adapter`, naming `folder` as its base files."""
    return dataclasses.replace(_catalog().entry(adapter), base_files=folder)


def _plant(root: Path, files: dict[str, bytes]) -> Path:
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    return root


# --- P-8: placement and what is filled ------------------------------------------------------------------------------------

def test_render_places_the_files_under_the_system_name_and_fills_only_the_system_placeholder(tmp_path):
    """`{system}` in a folder name, a `name:`, a template id fills with the system; `{host}`, `${p}`, `{{system}}`-free text and raw bytes stay. (P-8)"""
    folder = _plant(tmp_path / "base", {
        "skills/{system}/SKILL.md": b"---\nname: defender-{system}\n---\nuses {host} and ${p} and {System} and {systems}\n",
        "skills/{system}/execution.md": b"no placeholder\r\n\xff\xfe",
        "skills/gather/queries/{system}/by-host.md": b"id: {system}.by-host\nverb: get-host\n",
    })
    rendered = _base().render(_entry_over(folder), "acme-cmdb")
    assert rendered == {
        "agent/skills/acme-cmdb/SKILL.md": b"---\nname: defender-acme-cmdb\n---\nuses {host} and ${p} and {System} and {systems}\n",
        "agent/skills/acme-cmdb/execution.md": b"no placeholder\r\n\xff\xfe",
        "agent/skills/gather/queries/acme-cmdb/by-host.md": b"id: acme-cmdb.by-host\nverb: get-host\n",
    }


def test_two_systems_of_one_adapter_get_their_own_folders_and_ids(tmp_path):
    """The same entry rendered for two system names gives two disjoint path sets, each id naming its own system. (P-8, G-A7)"""
    folder = _plant(tmp_path / "base", {"skills/{system}/SKILL.md": b"name: defender-{system}\n"})
    first, second = (_base().render(_entry_over(folder), s) for s in ("one", "two"))
    assert set(first) == {"agent/skills/one/SKILL.md"}
    assert set(second) == {"agent/skills/two/SKILL.md"}
    assert first["agent/skills/one/SKILL.md"] == b"name: defender-one\n"


# --- P-9: the digest and the branch, by property --------------------------------------------------------------------------

def test_the_digest_is_64_lowercase_hex_and_the_branch_is_its_first_16(tmp_path):
    """`digest` is SHA-256 hex; `branch_of(system, d)` is `adopt/<system>/<first 16 hex>`. (P-9)"""
    digest = _base().digest(RENDERING)
    assert len(digest) == 64
    assert digest == digest.lower()
    assert int(digest, 16) >= 0
    assert _base().branch_of("elastic", digest) == f"adopt/elastic/{digest[:16]}"


def test_the_digest_and_branch_of_a_small_rendering_are_these_literals():
    """SHA-256 over 4-byte big-endian length-framed paths (UTF-8, byte order: `B` before `a`, `é` last) and contents; literals computed once by hand. (P-9, surface §7)"""
    rendering = {
        "agent/skills/a/z.md": b"z\n",
        "agent/\u00e9.md": b"caf\xc3\xa9\xff",
        "agent/a.md": b"",
        "agent/B.md": b"upper\r\n",
    }
    digest = _base().digest(rendering)
    assert digest == "07a52cc8f756a4e762fe3209c7b590aa16366ba03a628363ae181668c1cebeae"
    assert _base().branch_of("acme", digest) == "adopt/acme/07a52cc8f756a4e7"


def test_the_digest_ignores_the_order_the_files_were_listed_in():
    """Same files, reversed insertion order: one digest. (P-9: paths in byte order)"""
    assert _base().digest(RENDERING) == _base().digest(dict(reversed(list(RENDERING.items()))))


@pytest.mark.parametrize("change", ["byte", "append", "path", "extra-file", "empty-file", "move-file"])
def test_the_digest_changes_with_any_change_of_the_rendering(change):
    """One changed byte, appended byte, renamed path, extra or emptied file each give another digest. (P-9, A4)"""
    first = sorted(RENDERING)[0]
    changed = dict(RENDERING)
    if change == "byte":
        changed[first] = bytes([changed[first][0] ^ 1]) + changed[first][1:]
    elif change == "append":
        changed[first] += b"\n"
    elif change == "path":
        changed[first.replace("SKILL", "SKILL2")] = changed.pop(first)
    elif change == "extra-file":
        changed["agent/skills/elastic/extra.md"] = b""
    elif change == "empty-file":
        changed[first] = b""
    else:
        changed["agent/skills/elastic/z.md"] = changed.pop(first)
    assert _base().digest(changed) != _base().digest(RENDERING)


@pytest.mark.parametrize(("left", "right"), [
    ({"agent/a": b"bc"}, {"agent/ab": b"c"}),
    ({"agent/a": b"", "agent/b": b"c"}, {"agent/a": b"b", "agent/c": b""}),
    ({"x": b"yz"}, {"xy": b"z"}),
    ({"a": b"\x00b"}, {"a\x00": b"b"}),
], ids=["byte-moves-from-content-to-path", "split-across-two-files", "short-paths", "nul-at-the-boundary"])
def test_a_byte_moved_across_the_path_content_boundary_changes_the_digest(left, right):
    """Length-framed: concatenation-equal renderings differ. (P-9 length-prefixed path then bytes)"""
    assert _base().digest(left) != _base().digest(right)


# --- A5: shipped base files pass connect's scaffold validator -------------------------------------------------------------

def scaffold_failures(tmp_path: Path, rendering: dict[str, bytes], system: str) -> list[str]:
    """The FAIL rows of connect's skill check and template check over `rendering`, judged against the adapter's declared verbs."""
    scaffold = importlib.import_module("defender.skills.connect.validate_scaffold")
    staged = tmp_path / "staged-agent"
    for path, data in rendering.items():
        assert path.startswith("agent/"), path
        target = staged / path.removeprefix("agent/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    report = scaffold.Report()
    verbs = scaffold.check_registry(report, DEFENDER, system)
    scaffold.check_skill(report, staged, system)
    scaffold.check_templates(report, staged, system, verbs)
    return [message for status, message in report.rows if status == scaffold.FAIL]


def _fixture_cmdb() -> dict[str, bytes]:
    return {f"agent/{p.relative_to(FIXTURE_AGENT)}": p.read_bytes() for p in (
        FIXTURE_AGENT / "skills" / "cmdb" / "SKILL.md", FIXTURE_AGENT / "skills" / "cmdb" / "execution.md",
        FIXTURE_AGENT / "skills" / "gather" / "queries" / "cmdb" / "host-owner.md")}


def test_the_scaffold_check_passes_a_good_set_and_rejects_each_bad_one(tmp_path):
    """The A5 gate can fail: a well-formed cmdb set passes; a wrong skill name, an undeclared verb, an undeclared placeholder and a missing skill each fail. (A5)"""
    good = _fixture_cmdb()
    assert scaffold_failures(tmp_path / "good", good, "cmdb") == []
    skill, template = "agent/skills/cmdb/SKILL.md", "agent/skills/gather/queries/cmdb/host-owner.md"
    bad = {
        "wrong-name": {**good, skill: good[skill].replace(b"defender-cmdb", b"defender-other")},
        "undeclared-verb": {**good, template: good[template].replace(b"get-host", b"no-such-verb")},
        "undeclared-placeholder": {**good, template: good[template].replace(b"${host}", b"${nowhere}")},
        "no-skill": {p: d for p, d in good.items() if p != skill},
    }
    for name, rendering in bad.items():
        assert scaffold_failures(tmp_path / name, rendering, "cmdb"), f"{name}: the scaffold check passed a bad set"


def _shipping():
    return [e.adapter_id for e in _catalog().entries() if getattr(e, "base_files", None) is not None]


@pytest.mark.parametrize("adapter", _shipping() or [pytest.param(None, marks=pytest.mark.skip("no catalog entry ships base files yet"))])
def test_every_shipped_base_file_set_renders_and_passes_the_scaffold_check(tmp_path, adapter):
    """Each catalog entry that ships base files renders for its own id and passes skill and template checks against its declared verbs. (A5, P-8)"""
    entry = _catalog().entry(adapter)
    assert entry.base_files.is_dir()
    assert DEFENDER / "integrations" in entry.base_files.parents
    rendering = _base().render(entry, adapter)
    assert rendering
    assert all(p.startswith("agent/") and "{" not in p for p in rendering), sorted(rendering)
    assert f"agent/skills/{adapter}/SKILL.md" in rendering
    assert scaffold_failures(tmp_path, rendering, adapter) == []
    assert not [p for p, d in rendering.items() if b"{system}" in d], "an unfilled system placeholder was shipped"


def test_every_catalog_entry_declares_its_base_files():
    """Every entry has the `base_files` field (a folder or None), so no adapter is read as shipping by accident. (A1, A5)"""
    entries = _catalog().entries()
    assert entries
    assert all(hasattr(e, "base_files") for e in entries)


def test_no_carried_adapter_id_is_a_tenant_template_skill_folder():
    """An adapter id equal to `gather` or `tacit-knowledge` would let a rendering overwrite the tenant's own skill. (A5)"""
    folders = {p.name for p in TENANT_TEMPLATE_SKILLS.iterdir() if p.is_dir()}
    assert {"gather", "tacit-knowledge"} <= folders, "premise: the tenant template's skill folders"
    assert folders.isdisjoint(_catalog().adapter_ids)
