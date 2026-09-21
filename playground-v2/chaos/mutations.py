"""M2 — resolve a chaos profile + seed into concrete mutations.

Pure: takes the parsed inventory as an argument, does no I/O, and is
deterministic in the seed (O3). `chaos.ctl` is the only caller that pushes
the returned mutations through the exec seam.

Mutations speak the stack's vocabulary, not the operator's: a data-drop
names a *dataset* (`system.syslog`), which fixes exactly one ingest pipeline
(`logs-system.syslog@custom`) and one stream (`logs-system.syslog-*`); an
ingest-processor mutation carries the full set of `fields` it touches. The
guard (M3) reasons about those, with no glob translation in between.

Each mutation is a dict with a `kind` (`field-flip` | `phantom-host` |
`missing-host` | `schema-drift` | `data-drop`) plus the fields `ctl.py`
needs to push it and `status()` needs to reconcile it later:

  cmdb-stale:    host, field, old_value, new_value
  schema-drift:  dataset, stream, pipeline, processor, fields
  data-drop:     dataset, stream, pipeline, processor, fields (empty)
"""
from __future__ import annotations

import random
import re
from typing import Any

# The overlay sentinel M4 teaches the CMDB stub to read as "this host is
# gone" — the common real-world silent gap, expressed with no harness marker.
TOMBSTONE: dict[str, Any] = {"__absent__": True}

# schema-drift always targets the auth dataset; the guard (M3) restricts
# *which* field on it, never the pipeline itself.
AUTH_DATASET = "system.auth"

# A Fleet dataset name: dotted lowercase segments, no wildcards. Anything
# else cannot name exactly one pipeline, so it is not a valid target.
_DATASET_RE = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)*$")


class UnresolvableProfile(ValueError):
    """The profile cannot produce a real, well-formed fault — e.g. a
    field-flip on a field every host shares, or a dataset that is not a
    dataset. A no-op or a nonsense target must never be pushed and recorded
    as an injected fault."""


def pipeline_for_dataset(dataset: str) -> str:
    """The `@custom` pipeline Fleet calls for every document of a dataset."""
    return f"logs-{dataset}@custom"


def stream_for_dataset(dataset: str) -> str:
    """The data-stream glob every document of a dataset lands in."""
    return f"logs-{dataset}-*"


def dataset_of_stream(index: str) -> str | None:
    """`logs-system.auth-*` / `logs-system.auth-default` -> `system.auth`;
    None when the pattern does not pin down one dataset (`logs-*`)."""
    m = re.fullmatch(r"logs-([a-z0-9_]+(?:\.[a-z0-9_]+)*)-(?:\*|[a-z0-9_]+)", index)
    return m.group(1) if m else None


def _require_dataset(value: Any) -> str:
    if not isinstance(value, str) or not _DATASET_RE.fullmatch(value):
        raise UnresolvableProfile(
            f"{value!r} is not a dataset name (expected e.g. 'system.syslog'; no wildcards, "
            "no 'logs-' prefix, no '-*' suffix) — it cannot name exactly one ingest pipeline"
        )
    return value


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
        # A phantom is a clone of a real host with the next free index —
        # web-3 looks exactly like web-1 and web-2 — so it reads as ordinary
        # fleet growth. Drawing role/owner/criticality independently of the
        # name produced `db-2` with `role: web`: a record that contradicts
        # the fleet's own naming convention is a harness tell (O6), and so
        # is any coined "chaos"-shaped prefix.
        existing = {h["name"] for h in hosts}
        generated: set[str] = set()
        mutations = []
        for _ in range(count):
            sibling = rng.choice(hosts)
            prefix = re.sub(r"-\d+$", "", sibling["name"])
            idx = 1
            while f"{prefix}-{idx}" in existing or f"{prefix}-{idx}" in generated:
                idx += 1
            name = f"{prefix}-{idx}"
            generated.add(name)
            record = {"name": name}
            for key in ("role", "owner", "criticality", "change_window", "os"):
                if key in sibling:
                    record[key] = sibling[key]
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
        fields = [rename["from"], rename["to"]]
    elif "remove" in params:
        processor = {
            "remove": {
                "field": params["remove"],
                "ignore_missing": True,
                "ignore_failure": True,
            }
        }
        fields = [params["remove"]]
    else:
        raise ValueError("schema-drift profile needs a 'rename' or 'remove' param")
    dataset = AUTH_DATASET
    return [
        {
            "kind": "schema-drift",
            "dataset": dataset,
            "stream": stream_for_dataset(dataset),
            "pipeline": pipeline_for_dataset(dataset),
            "processor": processor,
            "fields": fields,
        }
    ]


def _resolve_data_drop(profile: Any, seed: int) -> list[dict[str, Any]]:
    params = profile.params
    dataset = _require_dataset(params.get("dataset"))
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
            "dataset": dataset,
            "stream": stream_for_dataset(dataset),
            "pipeline": pipeline_for_dataset(dataset),
            "processor": {"drop": {"if": condition}},
            "fields": [],
        }
    ]
