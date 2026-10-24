"""Lessons-frontend api layer (serialize.build_view) contract guarantees."""
from __future__ import annotations

from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[3]

import json  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

import pytest  # noqa: E402

from defender.learning.frontend import serialize  # noqa: E402
from defender.tests.support.shared.contracts._frontend_outputs import frontend_outputs_lock  # noqa: E402,F401 — shared pytest fixture


def test_three_groups_present():
    groups = serialize.build_view()["groups"]
    assert set(groups) == {"defender", "actor", "environment", "questioner"}
    for g in groups.values():
        assert g["label"]
        assert g["blurb"]
        assert isinstance(g["fields"], list)
        assert g["fields"], "each group must declare metadata fields for the view"


def test_lesson_record_shape():
    groups = serialize.build_view()["groups"]
    for g in groups.values():
        for lesson in g["lessons"]:
            assert set(lesson) >= {
                "group", "title", "description", "status", "source_path", "metadata", "body",
            }
            assert lesson["title"]
            assert lesson["status"] in {"live", "stale", "malformed"}
            assert isinstance(lesson["metadata"], dict)


def test_environment_seed_field_mapping():
    env = serialize.build_view()["groups"]["environment"]["lessons"]
    assert env, "environment corpus is empty — env-seed retrieval would surface nothing"
    for seed in env:
        assert seed["title"], seed["source_path"]
        assert seed["description"], seed["source_path"]
        assert seed["body"], seed["source_path"]
        assert isinstance(seed["metadata"], dict), seed["source_path"]


def test_environment_field_mapping_unit():
    spec = serialize.GROUPS["environment"]
    path = DEFENDER / spec["dir"] / "corp-vpn-egress.md"
    fm = {
        "subject": "corp-vpn-egress",
        "relevance_criteria": "egress from the corp VPN range is expected",
        "alert_rule_ids": [5712],
    }
    rec = serialize._normalize(
        path, fm, "body text", group="environment",
        title_keys=spec["title_keys"], desc_key=spec["desc_key"],
    )
    assert rec["title"] == "corp-vpn-egress"
    assert rec["description"] == "egress from the corp VPN range is expected"
    assert rec["metadata"]["alert_rule_ids"] == [5712]
    assert rec["body"] == "body text"


def test_skipped_lesson_gets_a_degraded_record(tmp_path):
    import json

    fixture = tmp_path / "defender"
    for spec in serialize.GROUPS.values():
        (fixture / spec["dir"]).mkdir(parents=True)
    (fixture / "lessons" / "good.md").write_text("---\nname: good\ndescription: d\n---\nbody\n")
    (fixture / "lessons" / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    (fixture / "lessons" / "_draft.md").write_text("not a lesson\n")

    lessons = serialize.build_view(defender_dir=fixture)["groups"]["defender"]["lessons"]

    assert [rec["title"] for rec in lessons] == ["broken", "good"]
    broken = lessons[0]
    assert broken["status"] == "malformed"
    assert "frontmatter unavailable" in broken["description"]
    assert broken["metadata"] == {}
    assert broken["body"] == ""
    assert broken["source_path"] == "defender/lessons/broken.md"
    json.dumps(lessons)


def test_metadata_is_json_safe():
    """YAML-parsed dates etc. must serialize (defender lessons carry created_at)."""
    import json

    json.dumps(serialize.build_view())


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
def test_1279_serialize_keeps_only_stdout_and_never_writes_into_the_tree():
    """#1279 migration: `--stdout` prints the contract; the file mode is gone — no `lessons.json` appears in the tree."""
    in_tree = Path(serialize.__file__).resolve().parent / "lessons.json"
    before = in_tree.read_bytes() if in_tree.is_file() else None
    try:
        shown = _serialize_cli("--stdout")
        assert shown.returncode == 0, shown.stderr
        assert set(json.loads(shown.stdout)["groups"]) == {"defender", "actor", "environment", "questioner"}

        _serialize_cli()
        after = in_tree.read_bytes() if in_tree.is_file() else None
        assert after == before, "serialize.py without --stdout still writes lessons.json into the tree"
    finally:
        if before is None:
            in_tree.unlink(missing_ok=True)
        else:
            in_tree.write_bytes(before)
