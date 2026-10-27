"""The lessons frontend's api layer (`serialize.build_view`): the posture page reads a tenant's
knowledge from an export's agent root (`build_view(agent_root=...)`), never the product tree.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from defender.learning.frontend import serialize  # noqa: E402
from defender.tests.support.shared.contracts._frontend_outputs import frontend_outputs_lock  # noqa: E402,F401 — shared pytest fixture
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

DEFENDER = Path(__file__).resolve().parents[3]

#: The groups the posture page shows: the defender's corpus and the questioner's.
LIVE_GROUPS = {"defender", "questioner"}

#: The committed fixture tenant's lessons (`knowledge/tenant-fixture/agent/`), by group.
FIXTURE_TITLES = {
    "defender": {"fixture-change-window-is-not-approval", "fixture-owner-before-close"},
    "questioner": {"fixture-questioner-seed"},
}


@pytest.fixture
def export_agent(tmp_path: Path, data_root: Path) -> Path:
    """The fixture tenant's `agent/` inside a real export: the root the frontend reads."""
    with published_tenant(tmp_path / "forge", root=data_root) as tenant:
        yield tenant.export.path / "agent"


def test_o_u5_the_posture_page_has_only_the_live_groups(export_agent: Path):
    """Exactly the live groups, each with a label, blurb and declared metadata fields."""
    groups = serialize.build_view(agent_root=export_agent)["groups"]
    assert set(groups) == LIVE_GROUPS
    for g in groups.values():
        assert g["label"]
        assert g["blurb"]
        assert isinstance(g["fields"], list)
        assert g["fields"], "each group must declare metadata fields for the view"


def test_o1_the_page_shows_the_exports_lessons_not_the_product_trees(export_agent: Path):
    """Built from an export, the page shows exactly that export's lessons, in the record shape it
    renders."""
    groups = serialize.build_view(agent_root=export_agent)["groups"]
    assert {name: {rec["title"] for rec in g["lessons"]} for name, g in groups.items()} \
        == FIXTURE_TITLES
    for g in groups.values():
        for lesson in g["lessons"]:
            assert set(lesson) >= {
                "group", "title", "description", "status", "source_path", "metadata", "body",
            }
            assert lesson["title"]
            assert lesson["status"] in {"live", "stale", "malformed"}
            assert isinstance(lesson["metadata"], dict)


def test_skipped_lesson_gets_a_degraded_record(tmp_path):
    import json

    agent = tmp_path / "agent"
    for spec in serialize.GROUPS.values():
        (agent / spec["dir"]).mkdir(parents=True)
    (agent / "lessons" / "good.md").write_text("---\nname: good\ndescription: d\n---\nbody\n")
    (agent / "lessons" / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    (agent / "lessons" / "_draft.md").write_text("not a lesson\n")

    lessons = serialize.build_view(agent_root=agent)["groups"]["defender"]["lessons"]

    assert [rec["title"] for rec in lessons] == ["broken", "good"]
    broken = lessons[0]
    assert broken["status"] == "malformed"
    assert "frontmatter unavailable" in broken["description"]
    assert broken["metadata"] == {}
    assert broken["body"] == ""
    # Relative to the tenant repo, never `defender/...`; the exact prefix is left open.
    assert broken["source_path"].endswith("lessons/broken.md")
    assert not broken["source_path"].startswith(("defender/", "/"))
    json.dumps(lessons)


def test_metadata_is_json_safe(export_agent: Path):
    """YAML-parsed dates etc. must serialize (lessons carry created_at)."""
    import json

    json.dumps(serialize.build_view(agent_root=export_agent))


def test_json_safe_coerces_exotic_types():
    """_json_safe must neutralize non-JSON YAML scalars so a build can't crash
    on an exotic frontmatter value (a !!set, a bare time, ...)."""
    import datetime
    import json

    out = serialize._json_safe({
        "s": {"b", "a"},
        "t": datetime.time(9, 30),
        "d": datetime.date(2026, 6, 2),
    })
    assert out["s"] == ["a", "b"]
    assert out["d"] == "2026-06-02"
    assert isinstance(out["t"], str)
    json.dumps(out)


def _serialize_cli(*args: str) -> subprocess.CompletedProcess:
    import os

    env = {**os.environ, "PYTHONPATH": f"{DEFENDER.parent}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}
    return subprocess.run(  # noqa: S603 — this interpreter, the serializer script
        [sys.executable, str(Path(serialize.__file__).resolve()), *args],
        capture_output=True, text=True, encoding="utf-8", check=False, env=env, timeout=180)


@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_serialize_keeps_only_stdout_and_never_writes_into_the_tree(export_agent: Path):
    """The contract goes to stdout with or without `--stdout`; no `lessons.json` is written into
    the tree (#1279)."""
    in_tree = Path(serialize.__file__).resolve().parent / "lessons.json"
    before = in_tree.read_bytes() if in_tree.is_file() else None
    try:
        for extra in (("--stdout",), ()):
            shown = _serialize_cli("--agent-root", str(export_agent), *extra)
            assert shown.returncode == 0, shown.stderr
            assert set(json.loads(shown.stdout)["groups"]) == LIVE_GROUPS, extra
        after = in_tree.read_bytes() if in_tree.is_file() else None
        assert after == before, "serialize.py still writes lessons.json into the tree"
    finally:
        if before is None:
            in_tree.unlink(missing_ok=True)
        else:
            in_tree.write_bytes(before)
