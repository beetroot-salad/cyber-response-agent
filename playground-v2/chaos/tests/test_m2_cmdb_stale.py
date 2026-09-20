"""M2 — the cmdb-stale mode's three variants, and what they send to the stub.

Every variant must read as ordinary CMDB decay (O6): a phantom host is named in
the inventory's own pattern, a flipped value comes from the inventory's own value
set, and a missing host is expressed with M4's tombstone rather than a
harness-shaped marker. The transport is the stub's existing admin routes —
POST/DELETE /admin/overlay/<name> — reached only through the exec seam (M1).
"""
from __future__ import annotations

import re

from _fakes import FakeExecSeam, write_profile

from chaos import ctl
from chaos.mutations import resolve_mutations
from chaos.profiles import load_profile

# The overlay sentinel M4 teaches the stub to read as "this host is gone".
TOMBSTONE = {"__absent__": True}
HARNESS_MARKERS = ("chaos", "fault", "inject", "harness", "defender", "eval", "fake")
SEEDS = (1, 2, 3, 7, 13, 42, 99, 4242)


def _inventory_name_patterns(inventory_host_names: list[str]) -> str:
    """web-1/web-2/db-1/office-ws-1/... -> the prefixes actually in use."""
    prefixes = sorted({re.sub(r"-\d+$", "", name) for name in inventory_host_names})
    assert "web" in prefixes and "office-ws" in prefixes, prefixes
    return r"(?:%s)-\d+" % "|".join(re.escape(p) for p in prefixes)


def test_phantom_host_is_named_in_the_inventorys_own_pattern(
    profiles_dir, inventory, inventory_host_names
):
    write_profile(profiles_dir, "stale-phantom", "cmdb-stale", {"variant": "phantom-host", "hosts": 1})
    profile = load_profile("stale-phantom", profiles_dir=profiles_dir)
    pattern = _inventory_name_patterns(inventory_host_names)

    for seed in SEEDS:
        mutations = resolve_mutations(profile, seed=seed, inventory=inventory)
        assert len(mutations) == 1
        name = mutations[0]["host"]
        assert re.fullmatch(pattern, name), f"seed {seed}: {name!r} is not an inventory-shaped name"
        assert name not in inventory_host_names, f"seed {seed}: {name} already exists — not a phantom"
        lowered = name.lower()
        for marker in HARNESS_MARKERS:
            assert marker not in lowered, f"seed {seed}: harness-shaped host name {name!r}"


def test_phantom_host_record_is_built_from_real_inventory_vocabulary(profiles_dir, inventory):
    write_profile(profiles_dir, "stale-phantom2", "cmdb-stale", {"variant": "phantom-host", "hosts": 1})
    profile = load_profile("stale-phantom2", profiles_dir=profiles_dir)
    record = resolve_mutations(profile, seed=42, inventory=inventory)[0]["new_value"]

    roles = {h["role"] for h in inventory["hosts"]}
    owners = {h["owner"] for h in inventory["hosts"]}
    criticalities = {h["criticality"] for h in inventory["hosts"]}
    assert record["role"] in roles
    assert record["owner"] in owners
    assert record["criticality"] in criticalities
    assert repr(record).lower().count("chaos") == 0


def test_missing_host_uses_the_tombstone_not_a_harness_marker(
    profiles_dir, inventory, inventory_host_names
):
    write_profile(profiles_dir, "stale-missing", "cmdb-stale", {"variant": "missing-host", "hosts": 1})
    profile = load_profile("stale-missing", profiles_dir=profiles_dir)

    mutation = resolve_mutations(profile, seed=42, inventory=inventory)[0]
    assert mutation["host"] in inventory_host_names, "missing-host must hide a real host"
    assert mutation["new_value"] == TOMBSTONE


def test_field_flip_activation_posts_the_overlay_patch_through_the_seam(
    profiles_dir, rules_dir, ledger_dir, inventory_host_names
):
    write_profile(
        profiles_dir,
        "stale-owner",
        "cmdb-stale",
        {"variant": "field-flip", "field": "owner", "hosts": 2},
    )
    execer = FakeExecSeam()
    record = ctl.activate(
        "stale-owner",
        seed=42,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )

    posts = execer.calls_for(target="cmdb", method="POST", path_contains="/admin/overlay/")
    assert len(posts) == 2
    for mutation in record["resolved_mutations"]:
        match = [p for p in posts if p["path"] == f"/admin/overlay/{mutation['host']}"]
        assert len(match) == 1, f"no overlay POST for {mutation['host']}: {posts}"
        assert match[0]["body"] == {"owner": mutation["new_value"]}
        assert mutation["host"] in inventory_host_names
    # Nothing in the stack's pipelines is touched by a CMDB-only profile.
    assert execer.calls_for(target="es") == []


def test_phantom_host_activation_posts_the_full_record_through_the_seam(
    profiles_dir, rules_dir, ledger_dir
):
    """`resolve_mutations` producing a phantom-host mutation is not the same
    claim as `ctl.activate` actually pushing it — a controller that only
    wires up field-flip would still write an "active" ledger record here
    while touching the stack not at all."""
    write_profile(profiles_dir, "stale-phantom-activate", "cmdb-stale", {"variant": "phantom-host", "hosts": 1})
    execer = FakeExecSeam()
    record = ctl.activate(
        "stale-phantom-activate",
        seed=42,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )
    mutation = record["resolved_mutations"][0]

    posts = execer.calls_for(target="cmdb", method="POST", path_contains="/admin/overlay/")
    assert len(posts) == 1, f"phantom-host activation pushed nothing: {execer.calls}"
    assert posts[0]["path"] == f"/admin/overlay/{mutation['host']}"
    assert posts[0]["body"] == mutation["new_value"]


def test_missing_host_activation_posts_the_tombstone_through_the_seam(
    profiles_dir, rules_dir, ledger_dir
):
    write_profile(profiles_dir, "stale-missing-activate", "cmdb-stale", {"variant": "missing-host", "hosts": 1})
    execer = FakeExecSeam()
    record = ctl.activate(
        "stale-missing-activate",
        seed=42,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )
    mutation = record["resolved_mutations"][0]

    posts = execer.calls_for(target="cmdb", method="POST", path_contains="/admin/overlay/")
    assert len(posts) == 1, f"missing-host activation pushed nothing: {execer.calls}"
    assert posts[0]["path"] == f"/admin/overlay/{mutation['host']}"
    assert posts[0]["body"] == TOMBSTONE


def test_revert_deletes_exactly_the_overlays_activation_created(
    profiles_dir, rules_dir, ledger_dir
):
    write_profile(
        profiles_dir,
        "stale-owner2",
        "cmdb-stale",
        {"variant": "field-flip", "field": "owner", "hosts": 2},
    )
    execer = FakeExecSeam()
    record = ctl.activate(
        "stale-owner2",
        seed=42,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )
    hosts = sorted(m["host"] for m in record["resolved_mutations"])

    reverter = FakeExecSeam()
    ctl.revert(
        record["ledger_ref"],
        execer=reverter,
        profiles_dir=profiles_dir,
        ledger_dir=ledger_dir,
    )
    deletes = reverter.calls_for(target="cmdb", method="DELETE", path_contains="/admin/overlay/")
    assert sorted(c["path"] for c in deletes) == [f"/admin/overlay/{h}" for h in hosts]
    assert reverter.mutating_calls() == deletes, "revert did more than undo the activation"


def test_a_field_flip_with_no_other_value_to_flip_to_is_refused(profiles_dir):
    """Two hosts, both owned by the same team: there is no real value to
    flip to. Falling back to the same value would push an overlay that
    changes nothing and record a stale-owner fault the stack never had."""
    import pytest

    from chaos.mutations import UnresolvableProfile

    write_profile(profiles_dir, "flip-single", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    profile = load_profile("flip-single", profiles_dir=profiles_dir)
    single_valued = {"hosts": [{"name": "web-1", "owner": "t"}, {"name": "web-2", "owner": "t"}]}
    with pytest.raises(UnresolvableProfile):
        resolve_mutations(profile, seed=42, inventory=single_valued)
