"""#914 — one system-name predicate, and every channel answers from it."""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

import pytest

from defender.systems import verbs
from defender.systems.verbs import SYSTEM_MAX_LEN, is_system_name

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
    adapters = tmp_path / "adapters"
    adapters.mkdir()
    root = adapters.resolve()
    for name in ADMITTED:
        (adapters / (name.replace("-", "_") + verbs.ADAPTER_SUFFIX)).write_text("VERBS = {}\n")
        assert verbs._adapter_path_under(root, name) is not None, name

    for name in REFUSED:
        planted = adapters / (name.replace("-", "_") + verbs.ADAPTER_SUFFIX)
        with contextlib.suppress(OSError, ValueError):
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text("VERBS = {}\n")
        assert verbs._adapter_path_under(root, name) is None, name
