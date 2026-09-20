"""O3 — same profile + seed → same shape; a different seed → a different shape.

`resolve_mutations` is pure: it takes the parsed inventory as an argument and
does no I/O, so the whole obligation is checkable without the stack. Two halves:

  * cmdb-stale — replay-stability per seed over a fixed seed table, plus the
    seed genuinely selecting among the inventory's real hosts and values.
  * data-drop  — the seed is folded into the drop hash as its salt, so a
    different seed drops a different subset and the same seed replays it. The
    design's live check pinned this exactly: salt 7 dropped 1 of 4 lines,
    salt 42 dropped 2 of 4.
"""
from __future__ import annotations

from _fakes import write_profile

from chaos.mutations import resolve_mutations
from chaos.profiles import load_profile

# A fixed table, not a sampled one: every assertion below is deterministic.
SEEDS = (1, 2, 3, 7, 13, 42, 99, 4242)
FLIPPABLE_FIELDS = ("owner", "criticality", "role")


def _values_in_inventory(inventory: dict, field: str) -> set:
    return {h[field] for h in inventory["hosts"] if field in h}


def _cmdb_stale_profile(profiles_dir, field: str = "owner"):
    write_profile(
        profiles_dir,
        f"cmdb-stale-{field}",
        "cmdb-stale",
        {"variant": "field-flip", "field": field, "hosts": 1},
    )
    return load_profile(f"cmdb-stale-{field}", profiles_dir=profiles_dir)


def test_cmdb_stale_replays_identically_for_each_seed(profiles_dir, inventory):
    profile = _cmdb_stale_profile(profiles_dir)
    for seed in SEEDS:
        first = resolve_mutations(profile, seed=seed, inventory=inventory)
        second = resolve_mutations(profile, seed=seed, inventory=inventory)
        assert first == second, f"seed {seed} did not replay"


def test_cmdb_stale_seed_selects_among_real_hosts_and_real_values(
    profiles_dir, inventory, inventory_host_names
):
    profile = _cmdb_stale_profile(profiles_dir)
    owners = _values_in_inventory(inventory, "owner")

    hosts_chosen, values_chosen = [], []
    for seed in SEEDS:
        mutations = resolve_mutations(profile, seed=seed, inventory=inventory)
        assert len(mutations) == 1, f"hosts:1 must resolve one mutation (seed {seed})"
        mutation = mutations[0]
        assert mutation["host"] in inventory_host_names
        assert mutation["field"] == "owner"
        # The replacement is drawn from the inventory's own value set, never coined.
        assert mutation["new_value"] in owners
        assert mutation["new_value"] != mutation["old_value"]
        base = next(h for h in inventory["hosts"] if h["name"] == mutation["host"])
        assert mutation["old_value"] == base["owner"]
        hosts_chosen.append(mutation["host"])
        values_chosen.append(mutation["new_value"])

    # The seed is a real selector, not decoration: over this fixed table it must
    # land on more than one host and more than one replacement value.
    assert len(set(hosts_chosen)) >= 2, f"seed does not move the host: {hosts_chosen}"
    assert len(set(values_chosen)) >= 2, f"seed does not move the value: {values_chosen}"


def test_cmdb_stale_multi_host_selection_is_a_stable_set(profiles_dir, inventory, inventory_host_names):
    write_profile(
        profiles_dir,
        "cmdb-stale-three",
        "cmdb-stale",
        {"variant": "field-flip", "field": "criticality", "hosts": 3},
    )
    profile = load_profile("cmdb-stale-three", profiles_dir=profiles_dir)
    criticalities = _values_in_inventory(inventory, "criticality")
    for seed in SEEDS:
        mutations = resolve_mutations(profile, seed=seed, inventory=inventory)
        hosts = [m["host"] for m in mutations]
        assert len(hosts) == 3
        assert len(set(hosts)) == 3, f"seed {seed} resolved a duplicate host: {hosts}"
        assert set(hosts) <= set(inventory_host_names)
        assert all(m["new_value"] in criticalities for m in mutations)
        assert resolve_mutations(profile, seed=seed, inventory=inventory) == mutations


def _drop_condition(mutations: list) -> str:
    """Pull the Painless `drop.if` out of whatever shape the resolved mutation
    has — the test pins the condition, not the wrapper's key names."""
    found: list[str] = []

    def walk(node):
        if isinstance(node, str):
            if "ctx.message" in node:
                found.append(node)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value)

    walk(mutations)
    assert len(found) == 1, f"expected exactly one drop condition, got {found}"
    return found[0]


def test_data_drop_salt_is_the_seed_and_every_seed_gives_a_distinct_hash(profiles_dir, inventory):
    write_profile(
        profiles_dir,
        "drop-syslog",
        "data-drop",
        {"target_stream": "logs-system.syslog-*", "rate": 25},
    )
    profile = load_profile("drop-syslog", profiles_dir=profiles_dir)

    conditions = {}
    for seed in SEEDS:
        mutations = resolve_mutations(profile, seed=seed, inventory=inventory)
        assert resolve_mutations(profile, seed=seed, inventory=inventory) == mutations
        condition = _drop_condition(mutations)
        # The seed is the salt inside the drop hash (design's live check: salt 7
        # dropped 1 of 4 lines, salt 42 dropped 2 of 4 — the seed selects the subset).
        # Pinned exactly, not just "contains the salt" — an unrelated appended
        # clause would still satisfy a substring check.
        assert condition == (
            f"ctx.message != null && ((ctx.message + '{seed}').hashCode() "
            "& 0x7fffffff) % 100 < 25"
        ), f"seed {seed}: {condition}"
        conditions[seed] = condition

    assert len(set(conditions.values())) == len(SEEDS), "different seeds produced the same drop hash"


def test_the_emitted_condition_really_selects_a_seed_dependent_subset(profiles_dir, inventory):
    """Evaluate the controller's own Painless expression as arithmetic: the same
    seed must drop the same lines, a different seed a different set, and neither
    all nor none of them."""
    write_profile(
        profiles_dir,
        "drop-syslog-rate",
        "data-drop",
        {"target_stream": "logs-system.syslog-*", "rate": 50},
    )
    profile = load_profile("drop-syslog-rate", profiles_dir=profiles_dir)
    messages = [
        f"Sep 20 0{i}:11:22 web-1 CRON[{1000 + i}]: (root) CMD (run-parts /etc/cron.hourly)"
        for i in range(24)
    ]

    def java_hash_code(text: str) -> int:
        code = 0
        for char in text:
            code = (31 * code + ord(char)) & 0xFFFFFFFF
        return code

    def dropped(seed: int) -> set[str]:
        condition = _drop_condition(resolve_mutations(profile, seed=seed, inventory=inventory))
        # Pinned to the whole formula, not fragments of it — a trailing extra
        # conjunct (e.g. one that never evaluates true) would still contain
        # every substring a looser check might assert, while silently
        # dropping nothing.
        assert condition == (
            f"ctx.message != null && ((ctx.message + '{seed}').hashCode() "
            "& 0x7fffffff) % 100 < 50"
        )
        salt = str(seed)
        return {m for m in messages if (java_hash_code(m + salt) & 0x7FFFFFFF) % 100 < 50}

    assert dropped(7) == dropped(7)
    assert dropped(7) != dropped(42)
    assert 0 < len(dropped(7)) < len(messages)
