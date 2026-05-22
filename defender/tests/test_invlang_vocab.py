"""Tests for the controlled-vocab module and the `enum` CLI subcommand.

`vocab.py` is the single source of truth for invlang closed catalogs;
these tests pin the slot names so other-side consumers (validator,
SKILL.md prose, CLI help) don't silently drift if a slot is renamed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from defender.skills.invlang import vocab


def test_list_slots_returns_sorted_strings():
    slots = vocab.list_slots()
    assert slots == sorted(slots)
    assert all(isinstance(s, str) for s in slots)
    # Pin the small, stable set so a renamed slot trips this test.
    expected = {
        "types", "relations", "anchor-kinds", "auth-kinds",
        "compute.role", "compute.zone", "compute.provenance", "compute.kind",
        "identity.kind", "identity.provenance",
        "application.vendor", "application.trust",
        "session.class", "storage.kind", "database.kind",
        "network-device.kind", "socket.protocol", "configuration.kind",
        "app-object.kind", "credential.kind",
    }
    assert set(slots) == expected


def test_get_enum_returns_tuple_for_known_slot():
    values = vocab.get_enum("types")
    assert isinstance(values, tuple)
    assert "compute" in values
    assert "process" in values


def test_get_enum_raises_on_unknown_slot():
    with pytest.raises(ValueError, match="unknown slot"):
        vocab.get_enum("nope.kind")


def test_relations_includes_added_verbs():
    rels = vocab.get_enum("relations")
    # New verbs from the closed-vocab rewrite — pin so they don't get
    # silently dropped.
    for r in ("authenticated_via", "assumed_role", "granted_consent",
              "issued", "contained_in", "created", "deleted"):
        assert r in rels, f"missing relation {r!r}"


def test_anchor_kinds_includes_iam_and_gpo():
    kinds = vocab.get_enum("anchor-kinds")
    assert "iam-policy" in kinds
    assert "gpo" in kinds
    assert "other" in kinds


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "defender.skills.invlang.cli",
         "/tmp/nonexistent", *args],
        capture_output=True, text=True, check=False,
        cwd=str(Path(__file__).resolve().parents[2]),
    )


def test_cli_enum_no_arg_lists_slots():
    r = _run_cli("enum")
    assert r.returncode == 0, r.stderr
    listed = r.stdout.strip().splitlines()
    assert "types" in listed
    assert "relations" in listed
    assert listed == sorted(listed)


def test_cli_enum_slot_lists_values():
    r = _run_cli("enum", "compute.role")
    assert r.returncode == 0, r.stderr
    values = r.stdout.strip().splitlines()
    assert "bastion" in values
    assert "ip-only" in values


def test_cli_enum_unknown_slot_nonzero():
    r = _run_cli("enum", "no-such-slot")
    assert r.returncode != 0
    assert "unknown slot" in r.stderr


def test_cli_enum_json_mode():
    r = _run_cli("enum", "anchor-kinds", "--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload["slot"] == "anchor-kinds"
    assert "iam-policy" in payload["values"]


def test_cli_hypothesis_shape_requires_filter():
    r = _run_cli("hypothesis-shape")
    assert r.returncode != 0
    assert "at least one of" in r.stderr
