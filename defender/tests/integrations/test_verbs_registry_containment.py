"""The model-supplied `system` name is joined into an imported path, so it must not escape the adapters dir; a broken adapter must not kill the catalog."""
from __future__ import annotations

import os

import pytest

from defender.systems.verb_grant import DENY_ALL, VerbGrant
from defender.systems.verbs import ModuleVerbRegistry
from defender.tests.e2e._replay_harness import DEFENDER
from defender.systems.verbs import read_roster

ADAPTERS = DEFENDER / "integrations"


def test_a_real_system_is_admitted():
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), DENY_ALL)
    assert "health-check" in reg.verbs("elastic")


@pytest.mark.parametrize("bad", [
    "../../../../etc/passwd",
    "elastic/../elastic",
    "elastic.x",
    "Elastic",
    "elastic ",
    "",
])
def test_a_malformed_system_is_rejected_not_imported(bad):
    with pytest.raises(KeyError):
        ModuleVerbRegistry(read_roster(ADAPTERS), DENY_ALL).verbs(bad)


def test_a_traversal_system_cannot_execute_an_out_of_tree_module(tmp_path):
    outside = tmp_path / "evil"
    outside.mkdir()
    marker = tmp_path / "EXECUTED"
    (outside / "pwned_adapter.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nVERBS = {{}}\n",
        encoding="utf-8",
    )
    reg = ModuleVerbRegistry(read_roster(ADAPTERS), DENY_ALL)
    rel = os.path.relpath(outside / "pwned_adapter.py", ADAPTERS)[: -len("_adapter.py")]
    assert ".." in rel

    with pytest.raises(KeyError):
        reg.verbs(rel)
    assert not marker.exists(), "a traversal system name imported (and executed) an out-of-tree module"


def test_a_broken_adapter_module_does_not_kill_the_catalog(tmp_path):
    from defender.tests.support.shared.contracts import _system_index_1256 as SI

    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "good_adapter.py").write_text("VERBS = {'health-check': lambda ctx: {}}\n", encoding="utf-8")
    (adapters / "broken_adapter.py").write_text("this is not python(\n", encoding="utf-8")

    skills = tmp_path / "skills"
    for name in ("good", "broken"):
        (skills / name).mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: the {name} system\n---\n", encoding="utf-8",
        )

    grant = VerbGrant(
        role="gather",
        entries=(("good", "health-check", "r"), ("broken", "health-check", "r")),
    )
    catalog = SI.index_text(SI.index_module(), skills, read_roster(adapters), grant)
    assert SI.listing(catalog), "one broken adapter emptied the whole catalog"
    assert "`good`" in catalog


def test_a_broken_adapter_module_raises_from_the_registry(tmp_path):
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "broken_adapter.py").write_text("this is not python(\n", encoding="utf-8")

    with pytest.raises(SyntaxError):
        ModuleVerbRegistry(read_roster(adapters), DENY_ALL).verbs("broken")
