"""The tacit-knowledge registry: the estate's authored record of sanctioned patterns.

The one system with no service behind it: the file
(`defender/skills/tacit-knowledge/registry.yaml`) is the system of record. Its safety rests on
provenance — every entry traces to a human commit, since nothing a run can reach writes it, so
the commit is the sign-off.

Read-only end to end: this module exports no write-capable function and
`permission.decide_write` refuses the path for every run role. A registry populated from the
agent's own closes would be the system vouching for itself.

  * `load_entries` — the file, validated entry by entry. A malformed row is dropped and the
    rest loads (as in `defender._corpus.iter_query_templates`), rather than one bad row sinking
    every sanction.
  * `find_entry` — the pure lookup, with `now` passed as a value so expiry is testable.

`lookup` is the gather verb over the pair, taking the tree and the as-of moment from its
`VerbContext`.
"""
from __future__ import annotations

import datetime as dt
import re
from fnmatch import fnmatchcase
from typing import Any, NamedTuple

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from pathlib import Path

import yaml

from defender import _yaml
from defender._io import TEXT_READ_ERRORS, read_text_utf8
from defender.runtime.verbs import VerbContext

SYSTEM = "tacit-knowledge"

#: The fields one entry carries, including the `id` a `:R authz` row cites as its `anchor_id`
#: (without it a citation would name a `pattern` string, and editing that string would silently
#: re-identify the sanction). Closed: missing or extra keys drop the entry.
#:
#: There is no field for citing a past case: precedent-by-similarity cannot be
#: recorded as a sanction at all.
ENTRY_FIELDS: tuple[str, ...] = (
    "id", "pattern", "actor_scope", "host_scope",
    "added_by", "added_at", "review_by", "justification",
)

#: Date fields: a `dt.date` PyYAML resolved from an unquoted scalar is normalized back to ISO.
_DATE_FIELDS: tuple[str, ...] = ("added_at", "review_by")

#: The maximum span from `added_at` to `review_by`, enforced at load. A file entry is not
#: re-verified on read the way a live IAM or change-management query is, so this bound stands
#: in for that; a sanction that could name its own expiry is a rubber stamp.
TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS = 180

#: The fewest literal (non-glob) characters an `actor_scope` or `host_scope` may carry.
#:
#: A denylist of blanket spellings misses scopes like `*-0`, which matches every actor ending
#: in `-0`; counting literal characters separates that from `build-runner-*.prod`.
#:
#: This is a shape rule, not a breadth proof: `prod-*` is mostly literal and still covers a
#: fleet. It only guarantees that scopes covering everything cannot be written.
TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS = 4

#: The glob metacharacters `fnmatchcase` reads, which is what makes a character not literal.
_WILDCARD_CHARS = "*?[]"

#: One `fnmatch` bracket expression — `[seq]` or `[!seq]`, with a leading `]` literal, as
#: `fnmatch.translate` reads it. Its contents are a character set, not literal text:
#: `[!QQQQ]*` would otherwise clear the literal minimum while matching every actor.
_BRACKET_EXPR_RE = re.compile(r"\[!?\]?[^\]]*\]")

#: Scope spellings that cover everything by name; complements the literal-character minimum.
_BLANKET_SCOPES = frozenset({"*", "all", "any"})


def registry_path(defender_dir: Path) -> Path:
    """Where the registry lives inside a defender tree.

    Under `skills/` as a system's data (so `runtime.verb_roster.model_read_surfaces` sees it),
    not a tenant's `settings/systems/{system}/`, which holds endpoints and credentials for live
    services.
    """
    return Path(defender_dir) / "skills" / SYSTEM / "registry.yaml"


def _literal_chars(value: str) -> int:
    """How many characters of `value` a name must match exactly (bracket expressions excluded)."""
    return sum(1 for ch in _BRACKET_EXPR_RE.sub("", value) if ch not in _WILDCARD_CHARS)


def _blanket_scope_reason(field: str, value: str) -> str | None:
    """Why this scope covers (very nearly) everything — or `None`."""
    scoped = value.strip()
    if not scoped:
        return f"`{field}` is blank, which scopes the sanction to nothing and to everything"
    if scoped.lower() in _BLANKET_SCOPES:
        return f"`{field}` is {value!r}, a blanket scope"
    if _literal_chars(scoped) < TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS:
        return (
            f"`{field}` is {value!r}, which carries fewer than "
            f"{TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS} literal characters — a scope that is "
            f"mostly wildcard covers a class nobody enumerated"
        )
    return None


def _parse_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value.strip())
    except ValueError:
        return None


def _normalized(raw: Any) -> dict[str, str] | None:
    """One raw YAML mapping as an entry of string fields, or `None` when it is not one.

    Dates PyYAML resolved from unquoted scalars are folded back to ISO: the file is
    hand-edited, and quoting should not drop a sanction. `dt.datetime` (from an unquoted
    timestamp) goes through `.date()` first, since `fromisoformat` would not read its
    `isoformat()`; it is a `dt.date` subclass, so one `isinstance` covers both. Anything else
    must be a non-empty string, or it would raise inside `fnmatchcase` in a verb body.
    """
    if not isinstance(raw, dict) or set(raw) != set(ENTRY_FIELDS):
        return None
    out: dict[str, str] = {}
    for field in ENTRY_FIELDS:
        value = raw[field]
        if field in _DATE_FIELDS and isinstance(value, dt.date):
            value = (value.date() if isinstance(value, dt.datetime) else value).isoformat()
        if not isinstance(value, str) or not value.strip():
            return None
        out[field] = value.strip()
    return out


def _read_entry(raw: Any) -> tuple[dict[str, str] | None, str]:
    """One raw YAML row as a loadable entry, or `(None, why not)`.

    One call answers both, so the two cannot disagree. The refusal text is for the human
    editing the file, so it names the field and the rule.
    """
    entry = _normalized(raw)
    if entry is None:
        known = set(raw) if isinstance(raw, dict) else set()
        missing = sorted(set(ENTRY_FIELDS) - known)
        unknown = sorted(known - set(ENTRY_FIELDS))
        return None, (
            f"an entry carries {sorted(known) or 'no fields'} — every one of "
            f"{list(ENTRY_FIELDS)} is required as non-empty text and nothing else is read"
            + (f"; missing {missing}" if missing else "")
            + (f"; unrecognised {unknown}" if unknown else "")
        )
    for field in ("actor_scope", "host_scope"):
        reason = _blanket_scope_reason(field, entry[field])
        if reason is not None:
            return None, f"entry {entry['id']!r}: {reason}"
    added_at, review_by = _parse_date(entry["added_at"]), _parse_date(entry["review_by"])
    if added_at is None or review_by is None:
        return None, (
            f"entry {entry['id']!r}: `added_at` and `review_by` are ISO dates "
            f"(YYYY-MM-DD); got {entry['added_at']!r} and {entry['review_by']!r}"
        )
    span = (review_by - added_at).days
    if not 0 <= span <= TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS:
        return None, (
            f"entry {entry['id']!r}: `review_by` is {span} days past `added_at`, outside the "
            f"0..{TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS}-day policy bound — a sanction may not "
            f"name its own expiry, because nothing re-verifies a file entry on read"
        )
    return entry, ""


class RegistryRead(NamedTuple):
    """One reading of the registry file: the entries that answer, in file order, and every
    reason something does not.

    The verb and the validating CLI share this reading, so a drop the human is told about is
    exactly the drop a run makes. `fatal` is a whole-file refusal (unreadable, or no `entries:`
    list), meaning nothing answers.

    A `NamedTuple`, not a `@dataclass`: adapter modules are loaded by path and are not in
    `sys.modules`, and `@dataclass` resolves string annotations through it, so it would raise
    at import and take every verb down.
    """

    entries: tuple[dict[str, str], ...]
    refusals: tuple[str, ...]
    fatal: str | None = None


def read_registry(path: Path) -> RegistryRead:
    """The registry at `path`, entry by entry, with the reason for each drop.

    Returns the refusals rather than printing them so a human can see them:
    `defender.scripts.tacit_cli` reports them and CI runs it. Printed during a run, a dropped
    entry is indistinguishable from an absent one and the run escalates a sanctioned case.
    """
    try:
        loaded = _yaml.safe_load(read_text_utf8(Path(path)))
    except (*TEXT_READ_ERRORS, yaml.YAMLError) as e:
        return RegistryRead((), (), f"registry at {path} could not be read ({e})")
    rows = loaded.get("entries") if isinstance(loaded, dict) else None
    if not isinstance(rows, list):
        return RegistryRead((), (), (
            f"registry at {path} declares no `entries:` list (top level is "
            f"{type(loaded).__name__}, `entries` is {type(rows).__name__}) — no sanction in it "
            f"will answer any lookup"
        ))
    entries: list[dict[str, str]] = []
    refusals: list[str] = []
    claimed: set[str] = set()
    for raw in rows:
        entry, refusal = _read_entry(raw)
        if entry is None:
            refusals.append(refusal)
            continue
        if entry["id"] in claimed:
            refusals.append(
                f"entry {entry['id']!r}: an EARLIER entry already claims this `id` — an id "
                f"names ONE sanction, and a citation cannot say which of two it means; give "
                f"this entry its own id"
            )
            continue
        claimed.add(entry["id"])
        entries.append(entry)
    return RegistryRead(tuple(entries), tuple(refusals))


def load_entries(path: Path) -> list[dict[str, str]]:
    """Every well-formed entry in the registry at `path`, in file order — the verb-side
    surface over `read_registry`.

    One bad entry is dropped, never the file. A repeated `id` is dropped too (the first keeps
    answering), since a citation must identify one sanction. A malformed file shape (no
    `entries:` list) is announced as well; otherwise it would look exactly like an empty
    registry, with every lookup an ordinary miss. Drops go to stderr, the only channel a run
    has.
    """
    read = read_registry(path)
    if read.fatal is not None:
        print(f"warn: tacit-knowledge {read.fatal}", file=_sys.stderr)
    for refusal in read.refusals:
        print(f"warn: skipping tacit-knowledge entry ({refusal})", file=_sys.stderr)
    return list(read.entries)


def find_entry(
    entries: list[dict[str, str]], *,
    actor: str, host: str, pattern: str, now: dt.date,
) -> dict[str, str] | None:
    """The first unexpired entry whose scope covers this actor, host and action — or `None`.

    Containment, never similarity. `pattern` is compared exactly (a glob would let one entry
    sanction every action); the scopes are globs held to a literal minimum at load. A near miss
    (`uid-00` vs `uid-0`) is a miss.

    Valid only while `added_at <= now <= review_by`. The lower bound matters because the span
    limit alone could be dodged by dating both ends into the future. Outside the window it is
    simply no hit — never a refusal or a stale authorization.
    """
    for entry in entries:
        if entry["pattern"] != pattern:
            continue
        if not fnmatchcase(actor, entry["actor_scope"]):
            continue
        if not fnmatchcase(host, entry["host_scope"]):
            continue
        added_at, review_by = _parse_date(entry["added_at"]), _parse_date(entry["review_by"])
        if added_at is None or review_by is None:
            continue
        if not added_at <= now <= review_by:
            continue
        return entry
    return None


def _as_of_date(ctx: VerbContext) -> dt.date:
    """The day this call is served as of: `ctx.as_of` on a branched run, else today.

    `getattr` because duck-typed contexts reach this adapter, and an `AttributeError` in a verb
    body is filed as an infra fault.
    """
    at = getattr(ctx, "as_of", None)
    return (dt.datetime.now(dt.UTC) if at is None else at).date()


def health_check(ctx: VerbContext) -> dict:
    """Liveness for a system with no service: does the registry exist, and how many entries
    does it hold. Returns data rather than printing, so the queries table records a payload."""
    path = registry_path(ctx.defender_dir)
    present = path.is_file()
    return {
        "system": SYSTEM,
        "connected": present,
        "registry": str(path),
        "entries": len(load_entries(path)) if present else 0,
    }


def lookup(  # lint-dup: ok — a verb name addressed as `<system>.lookup`; `threat_intel_adapter.lookup` is a different system's verb
    ctx: VerbContext, *, actor: str, host: str, pattern: str,
) -> dict:
    """Does an authored, unexpired registry entry sanction `actor` doing `pattern` on `host`?

    One key: `matched` is the entry (what a `:R consultations` row cites) or `None`. A miss
    names nothing — not a near match, not an expired entry — since an almost-hit's id would be a
    citation waiting to be written.
    """
    entries = load_entries(registry_path(ctx.defender_dir))
    return {
        "matched": find_entry(
            entries, actor=actor, host=host, pattern=pattern, now=_as_of_date(ctx),
        ),
    }


VERBS = {
    "health-check": health_check,
    "lookup": lookup,
}
