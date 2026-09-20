"""M2 — resolve a chaos profile + seed into concrete mutations.

Pure: takes the parsed inventory as an argument, does no I/O, and is
deterministic in the seed (O3). `chaos.ctl` is the only caller that pushes
the returned mutations through the exec seam.

Each mutation is a dict with a `kind` (`field-flip` | `phantom-host` |
`missing-host` | `schema-drift` | `data-drop`) plus the fields `ctl.py`
needs to push it and `status()` needs to reconcile it later:

  cmdb-stale:    host, field, old_value, new_value
  schema-drift:  pipeline, processor
  data-drop:     target_stream, pipeline, processor
"""
from __future__ import annotations

import random
import re
from typing import Any

# The overlay sentinel M4 teaches the CMDB stub to read as "this host is
# gone" — the common real-world silent gap, expressed with no harness marker.
TOMBSTONE: dict[str, Any] = {"__absent__": True}

# schema-drift always targets the auth pipeline; the guard (M3) restricts
# *which* field on it, never the pipeline itself.
AUTH_PIPELINE = "logs-system.auth@custom"


class UnresolvableProfile(ValueError):
    """The profile cannot produce a real fault against this inventory — e.g.
    a field-flip on a field every host shares. A no-op must never be pushed
    and recorded as an injected fault."""


def pipeline_for_stream(target_stream: str) -> str:
    """The `@custom` pipeline Fleet calls for a data-stream glob."""
    base = target_stream[:-2] if target_stream.endswith("-*") else target_stream
    return f"{base}@custom"


def resolve_mutations(profile: Any, *, seed: int, inventory: dict[str, Any]) -> list[dict[str, Any]]:
    if profile.mode == "cmdb-stale":
        return _resolve_cmdb_stale(profile, seed, inventory)
    if profile.mode == "schema-drift":
        return _resolve_schema_drift(profile)
    if profile.mode == "data-drop":
        return _resolve_data_drop(profile, seed)
    raise ValueError(f"unknown chaos mode {profile.mode!r}")


def _resolve_cmdb_stale(profile: Any, seed: int, inventory: dict[str, Any]) -> list[dict[str, Any]]:
    variant = profile.params["variant"]
    hosts = inventory.get("hosts") or []
    count = int(profile.params.get("hosts", 1))
    rng = random.Random(seed)

    if variant == "field-flip":
        field = profile.params["field"]
        pool = sorted({h[field] for h in hosts if field in h})
        chosen = rng.sample(hosts, k=min(count, len(hosts)))
        mutations = []
        for host in chosen:
            old = host.get(field)
            candidates = [v for v in pool if v != old]
            if not candidates:
                raise UnresolvableProfile(
                    f"field-flip on {field!r}: every host in the inventory has {old!r}, "
                    "so there is no other real value to flip to"
                )
            new = rng.choice(candidates)
            mutations.append(
                {
                    "kind": "field-flip",
                    "host": host["name"],
                    "field": field,
                    "old_value": old,
                    "new_value": new,
                }
            )
        return mutations

    if variant == "phantom-host":
        # web-1/web-2/db-1/office-ws-1/... -> the prefixes actually in use.
        # Never a coined "chaos"-shaped prefix: the name must read as
        # ordinary fleet growth.
        prefixes = sorted({re.sub(r"-\d+$", "", h["name"]) for h in hosts})
        roles = sorted({h["role"] for h in hosts if "role" in h})
        owners = sorted({h["owner"] for h in hosts if "owner" in h})
        criticalities = sorted({h["criticality"] for h in hosts if "criticality" in h})
        existing = {h["name"] for h in hosts}
        generated: set[str] = set()
        mutations = []
        for _ in range(count):
            prefix = rng.choice(prefixes)
            idx = 1
            while f"{prefix}-{idx}" in existing or f"{prefix}-{idx}" in generated:
                idx += 1
            name = f"{prefix}-{idx}"
            generated.add(name)
            record = {
                "name": name,
                "role": rng.choice(roles),
                "owner": rng.choice(owners),
                "criticality": rng.choice(criticalities),
            }
            mutations.append(
                {
                    "kind": "phantom-host",
                    "host": name,
                    "field": None,
                    "old_value": None,
                    "new_value": record,
                }
            )
        return mutations

    if variant == "missing-host":
        chosen = rng.sample(hosts, k=min(count, len(hosts)))
        return [
            {
                "kind": "missing-host",
                "host": host["name"],
                "field": None,
                "old_value": dict(host),
                "new_value": dict(TOMBSTONE),
            }
            for host in chosen
        ]

    raise ValueError(f"unknown cmdb-stale variant {variant!r}")


def _resolve_schema_drift(profile: Any) -> list[dict[str, Any]]:
    params = profile.params
    # ignore_missing + ignore_failure are mandatory, always: proven on the
    # live pipeline that a bare rename/remove stamps event.kind:pipeline_error
    # + error.message onto the field-less majority of auth lines, and those
    # error fields land in the agent-visible index (O6). No tag/description
    # either — a harness-named string sitting in cluster state is a tell.
    if "rename" in params:
        rename = params["rename"]
        processor = {
            "rename": {
                "field": rename["from"],
                "target_field": rename["to"],
                "ignore_missing": True,
                "ignore_failure": True,
            }
        }
    elif "remove" in params:
        processor = {
            "remove": {
                "field": params["remove"],
                "ignore_missing": True,
                "ignore_failure": True,
            }
        }
    else:
        raise ValueError("schema-drift profile needs a 'rename' or 'remove' param")
    return [{"kind": "schema-drift", "pipeline": AUTH_PIPELINE, "processor": processor}]


def _resolve_data_drop(profile: Any, seed: int) -> list[dict[str, Any]]:
    params = profile.params
    target_stream = params["target_stream"]
    rate = int(params["rate"])
    # Null-guarded (a field-less line survives untouched rather than
    # throwing into pipeline_error) and salted by the seed, so a different
    # seed drops a different subset and the same seed replays it (O3).
    condition = (
        f"ctx.message != null && ((ctx.message + '{seed}').hashCode() "
        f"& 0x7fffffff) % 100 < {rate}"
    )
    return [
        {
            "kind": "data-drop",
            "target_stream": target_stream,
            "pipeline": pipeline_for_stream(target_stream),
            "processor": {"drop": {"if": condition}},
        }
    ]
