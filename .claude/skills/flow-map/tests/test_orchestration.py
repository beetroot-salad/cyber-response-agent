"""orchestration.py — deterministic hook wiring + dispatch-candidate minting.

No LLM here: the seed only finds candidates; classification is haiku's job
(see test_haiku.py). Golden assertions double as drift detectors against
defender/SKILL.md + run-settings.json.
"""
from __future__ import annotations

from flowmap.orchestration import seed_orchestration


def test_hook_wiring_is_deterministic(defender_root):
    g, _ = seed_orchestration(defender_root, defender_root / "defender")
    fired = {(e.label, e.dst) for e in g.edges if e.kind == "fires_hook"}
    assert ("Task|Agent", "hook:extract_lead_metadata") in fired
    assert ("Task|Agent", "hook:inject_system_skill_description") in fired
    # all hook edges are deterministic + sourced
    for e in g.edges:
        if e.kind == "fires_hook":
            assert e.via == "settings-hook"
            assert e.confidence == "deterministic"


def test_hook_nodes_resolve_to_real_files(defender_root):
    g, _ = seed_orchestration(defender_root, defender_root / "defender")
    for nid, n in g.nodes.items():
        if n.kind == "hook":
            path, _, line = n.ref.rpartition(":")
            assert (defender_root / path).is_file(), f"{nid} ref {n.ref} missing"


def test_candidates_found_at_expected_sites(defender_root):
    _, cands = seed_orchestration(defender_root, defender_root / "defender")
    lines = sorted(int(c.ref.split(":")[-1]) for c in cands)
    # 8 skills/X/SKILL.md mentions in defender/SKILL.md
    assert lines == [111, 152, 282, 347, 400, 402, 418, 461]


def test_candidate_targets_are_script_minted(defender_root):
    _, cands = seed_orchestration(defender_root, defender_root / "defender")
    # gather + invlang mentions resolve to real skill node ids
    by_skill = {c.target_skill for c in cands}
    assert {"gather", "invlang"} <= by_skill
    for c in cands:
        assert c.target_id.startswith("skill:")
        assert c.target_skill in c.target_id


def test_candidate_carries_context(defender_root):
    _, cands = seed_orchestration(defender_root, defender_root / "defender")
    for c in cands:
        assert c.context  # haiku needs surrounding lines to classify
        assert c.line_text
