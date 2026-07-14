"""Impl-time hardening for the #611 verb registry: the model-supplied `system` name is joined
into a filesystem path that gets IMPORTED, so it must not escape the adapters dir.

This is the input-partition the spec-coverage graph structurally could not see: `check_binds`
reasons over the DECLARED domain (`verbs_registry.domain.distinguished[empty]` — the empty-VERBS
case), not over the invalid domain a path join opens up. The invariant is
`resolve(adapters_dir/<system>_cli.py)` stays under `resolve(adapters_dir)`, and it is defined by
the traversal danger, not by the registry's own existing branches — so this is written against
the invariant, not as "same as the old lookup".
"""
from __future__ import annotations

import os

import pytest

from defender.runtime.verbs import ModuleVerbRegistry
from defender.tests.e2e._replay_harness import DEFENDER

ADAPTERS = DEFENDER / "scripts" / "adapters"


def test_a_real_system_is_admitted():
    # The positive control: the guard is selective, not a blanket deny.
    reg = ModuleVerbRegistry(ADAPTERS)
    assert "health-check" in reg.verbs("elastic")


@pytest.mark.parametrize("bad", [
    "../../../../etc/passwd",     # classic traversal
    "elastic/../elastic",         # a `/` even where it re-lands in the dir
    "elastic.x",                  # a `.` — would be a different filename token
    "Elastic",                    # uppercase — not the lowercase-kebab shape
    "elastic ",                   # trailing space
    "",                           # empty
])
def test_a_malformed_system_is_rejected_not_imported(bad):
    # A malformed `system` raises KeyError (which the query tool turns into "unknown system"),
    # never a module import.
    with pytest.raises(KeyError):
        ModuleVerbRegistry(ADAPTERS).verbs(bad)


def test_a_traversal_system_cannot_execute_an_out_of_tree_module(tmp_path):
    # The teeth: plant a hostile `*_cli.py` OUTSIDE the adapters dir, reachable by `..`, and
    # confirm the registry never imports it. A module that ran would flip this flag.
    outside = tmp_path / "evil"
    outside.mkdir()
    marker = tmp_path / "EXECUTED"
    (outside / "pwned_cli.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nVERBS = {{}}\n",
        encoding="utf-8",
    )
    reg = ModuleVerbRegistry(ADAPTERS)
    rel = os.path.relpath(outside / "pwned_cli.py", ADAPTERS)[: -len("_cli.py")]
    assert ".." in rel  # the probe really does traverse out of the adapters dir

    with pytest.raises(KeyError):
        reg.verbs(rel)
    assert not marker.exists(), "a traversal system name imported (and executed) an out-of-tree module"


def test_a_broken_adapter_module_does_not_kill_the_catalog(tmp_path):
    """A `*_cli.py` that will not import costs its OWN system, not the run.

    Reading the roster IMPORTS each adapter (the filename glob never did), so an adapter with a
    syntax error — a newly onboarded system, say — would otherwise raise straight out of
    `descriptor_catalog`, killing prompt construction for EVERY system and with it the whole run.
    The healthy systems must still be advertised."""
    from defender.hooks.inject_system_skill_description import descriptor_catalog

    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "good_cli.py").write_text("VERBS = {'health-check': lambda ctx: {}}\n", encoding="utf-8")
    (adapters / "broken_cli.py").write_text("this is not python(\n", encoding="utf-8")

    skills = tmp_path / "skills"
    for name in ("good", "broken"):
        (skills / name).mkdir(parents=True)
        (skills / name / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: the {name} system\n---\n", encoding="utf-8",
        )

    catalog = descriptor_catalog(skills, adapters)
    assert catalog is not None, "one broken adapter emptied the whole catalog"
    assert "`good`" in catalog
    assert "`broken`" not in catalog, "a system that cannot be imported was still advertised"


def test_a_broken_adapter_module_raises_from_the_registry(tmp_path):
    """The registry itself stays honest — it does not swallow the failure into a KeyError, which
    would file a code bug as 'unknown system'. The CALLERS decide what to do with it (the catalog
    skips the system; the query tool files it as infra against that system)."""
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    (adapters / "broken_cli.py").write_text("this is not python(\n", encoding="utf-8")

    with pytest.raises(SyntaxError):
        ModuleVerbRegistry(adapters).verbs("broken")
