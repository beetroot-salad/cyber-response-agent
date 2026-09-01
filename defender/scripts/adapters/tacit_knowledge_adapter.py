"""The tacit-knowledge registry: the estate's authored record of sanctioned patterns.

The one system in this tree with no service behind it — the FILE is the system of record
(`defender/skills/tacit-knowledge/registry.yaml`), and its entire safety argument is
provenance: every entry traces to a human commit, because nothing an agent run can reach
writes it. The commit/PR IS the sign-off, which is the role the missing human-review step in
this pipeline would otherwise have played (#983 mechanism B).

READ-ONLY END TO END, and deliberately so. This module exports no write-capable function, and
`permission.decide_write` refuses the path for every role a run can reach. A registry populated
from the agent's own automated closes would be the system vouching for itself.

Two halves, split so the rules are testable without a `VerbContext`:

  * `load_entries` — the file, validated ENTRY BY ENTRY. One malformed row is DROPPED and the
    rest of the file loads, mirroring `defender._corpus.iter_query_templates`: a registry is a
    curated list, and one bad row sinking every sanctioned pattern in the estate is the worse
    failure.
  * `find_entry` — the pure lookup, with `now` entering as a VALUE so expiry is checkable
    without a clock to patch.

`lookup` is the gather verb over the pair, resolving both the tree it reads and the moment it
judges expiry against off the `VerbContext` it is handed.
"""
from __future__ import annotations

import datetime as dt
import re
from fnmatch import fnmatchcase
from typing import Any

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

#: The eight fields ONE entry carries — the seven the design names plus the `id` a `:R authz`
#: row cites as its `anchor_id`. Closed: an entry missing any of them, or carrying a key this
#: loader does not read, is dropped. Without `id` a citation would name a `pattern` STRING, and
#: every edit to that string would be a silent re-identification of the sanction.
#:
#: Nothing here can cite a past case (`cites_past_case`, `similar_to`, `precedent`), and that
#: omission is the mechanical half of a rejected non-obligation: "this resembles a case we
#: resolved" cannot be recorded as a sanction at all, so precedent-by-similarity has no home
#: even with a human's signature on it.
ENTRY_FIELDS: tuple[str, ...] = (
    "id", "pattern", "actor_scope", "host_scope",
    "added_by", "added_at", "review_by", "justification",
)

#: The two fields that carry a DATE, so a `dt.date` PyYAML resolved from an unquoted scalar is
#: normalized back to the ISO string the rest of this module compares.
_DATE_FIELDS: tuple[str, ...] = ("added_at", "review_by")

#: How far past its own `added_at` an entry may set its `review_by`. THE freshness bound, and
#: it is enforced at load rather than trusted: a file entry does not re-verify itself on every
#: read the way a live IAM or change-management query does, so the bound is what stands in for
#: that re-verification. A sanction that could name its own expiry is a rubber stamp.
#:
#: One module-level constant so the policy knob is tunable in one place.
TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS = 180

#: The fewest LITERAL characters — anything that is not a glob metacharacter — an `actor_scope`
#: or `host_scope` may carry.
#:
#: The three spellings a denylist catches (empty, `*`, `all`/`any`) are not enough, because a
#: denylist cannot tell a blanket wildcard from a legitimate scoped glob: `actor_scope: "*-0"`
#: matches `uid-0`, `svc-0`, `root-0` and every other actor whose name ends that way, and it is
#: none of those three spellings. Counting literal characters is the property that actually
#: separates them — `build-runner-*.prod` is eighteen literal characters around one star, and
#: `*-0` is nearly all star.
#:
#: THE LIMIT, recorded rather than papered over: this is a shape rule, not a breadth proof.
#: `host_scope: "prod-*"` is mostly literal and still covers a fleet, and no character count
#: can tell a fleet-wide sanction a human MEANT from one they wrote carelessly. What the rule
#: buys is that the spellings covering EVERYTHING cannot be written at all; who may author a
#: broad-but-legal entry is a process risk on the registry itself.
TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS = 4

#: The glob metacharacters `fnmatchcase` reads, which is what makes a character NOT literal.
_WILDCARD_CHARS = "*?[]"

#: One `fnmatch` BRACKET EXPRESSION — `[seq]` or the negated `[!seq]`, with a `]` in first
#: position taken literally, exactly as `fnmatch.translate` reads it.
#:
#: Its contents are a CHARACTER SET, never literal text, and counting them as literal was the
#: hole in the rule below: `[!QQQQ]` is five characters that match every character except `Q`,
#: so `actor_scope: "[!QQQQ]*"` cleared the four-literal minimum and matched every actor in the
#: estate — a blanket scope in a spelling the rule claims cannot be written at all. The whole
#: expression counts as wildcard, which is what it is.
_BRACKET_EXPR_RE = re.compile(r"\[!?\]?[^\]]*\]")

#: Scope spellings that cover everything by NAME rather than by wildcard. Held beside the
#: literal-character minimum, not instead of it: each catches what the other cannot.
_BLANKET_SCOPES = frozenset({"*", "all", "any"})


def registry_path(defender_dir: Path) -> Path:
    """Where the registry lives inside a defender tree.

    The per-system directory convention, so the file is a SYSTEM's data queried through a
    gather verb rather than a vocabulary of the invlang module — and so
    `runtime.verb_roster.model_read_surfaces`, which already enumerates `skills/*/`, sees the
    skill beside it. Deliberately NOT `knowledge/environment/systems/{system}/`: that lane
    holds endpoints and credentials for a live service, and this system has no service.
    """
    return Path(defender_dir) / "skills" / SYSTEM / "registry.yaml"


def _literal_chars(value: str) -> int:
    """How many characters of `value` a host or actor name has to MATCH exactly.

    Bracket expressions are struck out whole before the count — see `_BRACKET_EXPR_RE` for the
    blanket scope that reached `find_entry` while they were being counted as literal text.
    """
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
    """One raw YAML mapping as an entry of eight string fields, or `None` when it is not one.

    A `dt.date` PyYAML resolved out of an unquoted `added_at: 2026-03-01` is folded back to its
    ISO spelling: the file is HUMAN-EDITED, and refusing an entry for the quoting of a date
    would drop a legitimate sanction over a formatting detail. Everything else must already be
    a non-empty string — a list or a mapping in a field this module compares as text would
    otherwise reach `fnmatchcase` and raise inside a verb body.

    The fold goes through `.date()` FIRST, which is the whole of what makes it work. PyYAML also
    resolves an unquoted `2026-03-01 00:00:00` — a legal timestamp a human plausibly commits —
    to a `dt.datetime`, whose `isoformat()` is `'2026-03-01T00:00:00'`, and
    `dt.date.fromisoformat` does not read that. So the branch that exists to SAVE these entries
    dropped exactly the ones it was reached for, and the sanction silently stopped answering.
    One `isinstance(value, dt.date)` covers both: `dt.datetime` is a `dt.date` subclass, which
    is also why naming it beside `dt.date` in a tuple never selected anything on its own.
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

    Both halves from ONE call so the loader cannot answer "does this load" and "what is it"
    with two normalizations that could disagree. The refusal text is what a human editing the
    file reads on stderr, so it names the field and the rule.
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


def load_entries(path: Path) -> list[dict[str, str]]:
    """Every well-formed entry in the registry at `path`, in file order.

    ONE entry is dropped, never the file — the argument `_corpus.iter_query_templates` makes
    for the query catalog. Each drop is announced on stderr, because the only person who can
    repair the row is the human who committed it.

    A REPEATED `id` is one of those drops. The file's own header says an id may never be
    re-used, and until this check nothing enforced it: two entries could share one, `find_entry`
    would answer with whichever came first in file order, and a `:R authz` row citing that id
    named neither of them in particular. A citation has to identify ONE sanction — that is the
    entire reason the id exists rather than a `pattern` string — so the later row is refused
    while the first, which every existing citation already means, keeps answering.

    THE FILE'S OWN SHAPE is announced too, and it is the drop that was silent. A top-level that
    is not a mapping, or a mapping with no `entries:` list under it — a `entires:` typo, a list
    at the root, a file emptied to `null` — reached the same `return []` a genuinely empty
    registry does, with nothing on stderr and `health_check` reporting `connected: true,
    entries: 0`. Every sanction in the estate stops answering and every lookup is an ordinary
    MISS, which is the one failure mode this system cannot distinguish from working.
    """
    try:
        loaded = _yaml.safe_load(read_text_utf8(Path(path)))
    except (*TEXT_READ_ERRORS, yaml.YAMLError) as e:
        print(f"warn: tacit-knowledge registry at {path} could not be read ({e})",
              file=_sys.stderr)
        return []
    rows = loaded.get("entries") if isinstance(loaded, dict) else None
    if not isinstance(rows, list):
        print(
            f"warn: tacit-knowledge registry at {path} declares no `entries:` list "
            f"(top level is {type(loaded).__name__}, `entries` is {type(rows).__name__}) — "
            f"no sanction in it will answer any lookup",
            file=_sys.stderr,
        )
        return []
    entries: list[dict[str, str]] = []
    claimed: set[str] = set()
    for raw in rows:
        entry, refusal = _read_entry(raw)
        if entry is None:
            print(f"warn: skipping tacit-knowledge entry ({refusal})", file=_sys.stderr)
            continue
        if entry["id"] in claimed:
            print(
                f"warn: skipping tacit-knowledge entry (entry {entry['id']!r}: an EARLIER entry "
                f"already claims this `id` — an id names ONE sanction, and a citation cannot "
                f"say which of two it means; give this entry its own id)",
                file=_sys.stderr,
            )
            continue
        claimed.add(entry["id"])
        entries.append(entry)
    return entries


def find_entry(
    entries: list[dict[str, str]], *,
    actor: str, host: str, pattern: str, now: dt.date,
) -> dict[str, str] | None:
    """The first unexpired entry whose scope COVERS this actor, host and action — or `None`.

    CONTAINMENT, never similarity. `pattern` is compared for exact equality (a glob there would
    let one entry sanction every action, which is the hole the no-wildcard rule closes on the
    two scopes); `actor_scope` and `host_scope` are ordinary globs, already held to a literal
    minimum at load. A near miss is a miss — `uid-00` is not `uid-0` and
    `build-runner-07.prod.example` is not a `build-runner-*.prod` host — so resemblance to a
    past case cannot become a hit at read time either.

    Validity is a property of the READ, not of the load, and it has BOTH ends. An entry that is
    well formed and inside the review span still stops answering once its own review date
    passes, which is what makes the freshness bound stand in for a live system's
    re-verification — and it does not START answering before the day it says it was added.

    The second half is what makes the first mean anything. `_read_entry` bounds the SPAN between
    the two dates, so an entry cannot name its own expiry; checking only `review_by` on the way
    out left that bound satisfiable by moving both dates forward together, which buys effectively
    unlimited validity from today with a legal 151-day span. A sanction dated into the future has
    not been authored yet as far as this read is concerned.

    Either way it is simply NO HIT — never a refusal, and never a stale authorization.
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
    """The day this call is being served AS OF.

    `ctx.as_of` is the branch point's moment on a branched run and `None` on an ordinary one,
    where the call really is executing now. THE ONE ANCHOR for that optionality, resolved here
    and handed to `find_entry` as a concrete value — `getattr` for the reason
    `host_state_adapter._captured_at` uses it: this adapter is reachable with duck-typed
    contexts, and an `AttributeError` inside a verb body is filed as an INFRA fault rather than
    as the shape mismatch it is.
    """
    at = getattr(ctx, "as_of", None)
    return (dt.datetime.now(dt.UTC) if at is None else at).date()


def health_check(ctx: VerbContext) -> dict:
    """Liveness for a system with no service: does the registry file exist, and how many
    entries does it hold. Returns data rather than printing, like every other health check —
    prose on stdout would leave the queries table recording an empty payload."""
    path = registry_path(ctx.defender_dir)
    present = path.is_file()
    return {
        "system": SYSTEM,
        "connected": present,
        "registry": str(path),
        "entries": len(load_entries(path)) if present else 0,
    }


def lookup(  # lint-dup: ok — a VERB name, not a helper: `threat_intel_adapter.lookup` is a different system's verb with a different contract, and the roster/query seam addresses both as `<system>.lookup`, so the module attribute must be spelled exactly this. Same NAME-ONLY collision the baselined `health_check() x4` across these adapters already is.
    ctx: VerbContext, *, actor: str, host: str, pattern: str,
) -> dict:
    """Does an authored, unexpired registry entry sanction `actor` doing `pattern` on `host`?

    ONE key on the return. A `hit` boolean beside the entry would be two spellings of one fact;
    `matched is None` already says "miss" to a reader and to a gather model looking at the
    payload, and the whole entry is what a `:R consultations` row cites and a human reviews.

    A MISS names nothing — not the entry it nearly matched, not the one that expired. An
    almost-hit that reported its own id would be a citation waiting to be written.
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
