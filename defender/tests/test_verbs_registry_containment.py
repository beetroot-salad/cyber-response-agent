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
