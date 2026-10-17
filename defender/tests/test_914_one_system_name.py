"""#914 — one system-name predicate, and every channel answers from it."""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

import pytest

from defender.runtime import verbs
from defender.runtime.verbs import SYSTEM_MAX_LEN, is_system_name

#: The names every real source in this repo carries, and the shapes #869/#868 pinned as
#: refused. `gather` and `fakesys` are deliberately in the ADMITTED column: they are
#: well-formed names that no source declares, and keeping shape apart from membership is what
#: lets a drop be attributed to the right one.
ADMITTED = ("elastic", "cmdb", "change-mgmt", "host-state", "threat-intel", "ticket",
            "identity", "gather", "fakesys", "a", "s3", "a-b-c")
REFUSED = ("", "..", ".", ".hidden", "a/b", "a\\b", "a\x00b", "my sys", "wazuh-café",
           "Elastic", "HOST-STATE", "host_state", "-lead", "a" * (SYSTEM_MAX_LEN + 1),
           " elastic", "elastic ", "elastic\n", "\n", "élastic")


@pytest.mark.parametrize("name", ADMITTED)
def test_the_predicate_admits_every_well_formed_name(name):
    assert is_system_name(name) is True, name


@pytest.mark.parametrize("name", REFUSED)
def test_the_predicate_refuses_every_malformed_name(name):
    assert is_system_name(name) is False, name


def test_the_resolver_and_the_dispatch_seam_cannot_disagree(tmp_path):
    """THE defect this issue closes, driven end to end rather than asserted about.

    For every refused shape, `_adapter_path_under` returns None — so if the resolver admitted
    one, it would declare a system that cannot dispatch. Driven over a real adapters directory
    holding a real file for each name, so a None here is the PREDICATE's answer and not a
    missing file's.
    """
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    root = adapters.resolve()
    for name in ADMITTED:
        (adapters / (name.replace("-", "_") + verbs.ADAPTER_SUFFIX)).write_text("VERBS = {}\n")
        assert verbs._adapter_path_under(root, name) is not None, name

    for name in REFUSED:
        # A name the resolver must not declare is a name dispatch must not resolve. The file
        # is planted for every shape that can BE one — INCLUDING the separator-bearing `a/b`,
        # whose parent directory is created first. Without the mkdir that one assertion is
        # vacuous: `_adapter_path_under` returns None for the missing file, so it passes just as
        # well against a predicate that admits everything, and the traversal shape is the one
        # FK-5 is most about. `a\x00b` is the single shape no filesystem can hold.
        planted = adapters / (name.replace("-", "_") + verbs.ADAPTER_SUFFIX)
        with contextlib.suppress(OSError, ValueError):
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text("VERBS = {}\n")
        assert verbs._adapter_path_under(root, name) is None, name


