"""The naming rules a world label is held to, as pure text checks with no dependencies.

Two owners judge a world label: the family model (a label must not claim a reserved name) and
the world-view adapter (a label must name a search-index view). Each raises its own error type,
but the rule and its words live here once, so a reader that holds no model stack and no adapter
(the runs repository's episode-record writer, #1105) judges a label exactly as they do. Each
`*_fault` function returns the refusal's sentence, or `None` when the label passes; a label is
shown `quoted`, so a model-authored megabyte cannot flood the refusal.
"""
from __future__ import annotations

import re

from defender._shown import quoted

#: Labels no world may claim. `base` names the family's shared capture (a world using it would
#: append live rows into the recording its siblings replay); `family` would give a per-world judge
#: draw the family-level call's agent id `judge:family:<n>`, interleaving two streams in one
#: wire log.
RESERVED_WORLD_LABELS: frozenset[str] = frozenset({"base", "family"})

#: `family_<digits>` too, defensively: the colon fold that names a wire-log file is not obviously
#: injective across `judge:<world>:<n>` and `judge:family:<n>`, so the whole near-miss shape is
#: refused.
_RESERVED_FAMILY_DRAW_LABEL = re.compile(r"\Afamily_\d+\Z", re.IGNORECASE)

#: Punctuation an index or alias name cannot carry (whitespace is checked separately). `:` is
#: absent: legal in the cross-cluster expression `remote:logs-*`.
_ILLEGAL_IN_NAME = frozenset('\\/*?"<>|,')


def is_reserved_world_label(label: str) -> bool:
    """The membership test for the reserved namespace (the set, case-folded, and the
    `family_<digits>` shape). Other gates, such as the judge's, ask this rather than re-deriving
    the fold."""
    return (label.casefold() in RESERVED_WORLD_LABELS
            or _RESERVED_FAMILY_DRAW_LABEL.match(label) is not None)


def reserved_label_fault(label: str, *, at: str = "") -> str | None:
    """Why `label` is reserved, or `None`. The shape arm runs first so `family_1` is refused for
    the rule that actually matched it; `at` prefixes where the label was found."""
    where = f"{at} " if at else ""
    if _RESERVED_FAMILY_DRAW_LABEL.match(label):
        return (f"{where}world label {quoted(label)} matches family_<n> — the colon fold that names a "
                "wire log file is not injective, and this label's own agent id would fold to "
                "the same stem as one of the family call's draws")
    if is_reserved_world_label(label):
        return (f"{where}world label {quoted(label)} is the reserved name of the family's own base "
                "capture or the family-level judge call — a world claiming it would append its "
                "live rows into the recording its siblings replay, or collide with the family "
                "call's own agent id")
    return None


#: The world-token rule's alphabet: lower-case ASCII letters, digits and `_`, starting with a
#: letter or digit. No `-`: a sibling's run id is `<episode id>-<label>` and the launcher reads
#: the label back after the last `-`. No `.`: the world token is `<episode token>.<label>`. Lower
#: case only: a label names a run dir, a ledger file and an oracle-side store, and two labels one
#: case fold apart would be one file wherever the filesystem folds case.
_WORLD_LABEL = re.compile(r"\A[a-z0-9][a-z0-9_]*\Z")


def world_label_fault(label: object, *, at: str = "") -> str | None:
    """Why `label` cannot be a world label, or `None`: a string in the world-token alphabet
    that does not claim a reserved name. `at` prefixes where the label was found.

    The one statement of the shape rule; the manifest loader asks it of every world, so every
    reader of a manifest (the launcher, the sibling, the judge, the page) holds labels to it."""
    where = f"{at} " if at else ""
    if not isinstance(label, str) or not _WORLD_LABEL.match(label):
        return (f"{where}world label {quoted(label)} is outside the world-token alphabet (lower-"
                "case ASCII letters, digits and '_', starting with a letter or digit) — a label "
                "names a run dir, a ledger file and an oracle-side store, and is read back out "
                "of `<episode id>-<label>` after the last '-'")
    return reserved_label_fault(label, at=at)


def view_name_fault(part: str, origin: str) -> str | None:
    """Why `part` cannot name an index or alias, or `None`; `origin` says what it came from."""
    if not part:
        return (f"{origin} reduces to nothing an alias can be named by — a world view is built "
                "from the corpus it stages, and a bare wildcard leaves no corpus to name")
    illegal = sorted({c for c in part if c in _ILLEGAL_IN_NAME or c.isspace()})
    if illegal:
        return (f"{origin} carries {illegal}, which an index or alias name cannot hold — the "
                "view is written back unquoted, so the retargeted query would not parse as the "
                "one command it replaced")
    # Lower case only. The search backend does not refuse an upper-case alias here: `_search` uses
    # `ignore_unavailable=true`, so it silently returns zero hits.
    if part != part.lower():
        return (f"{origin} carries upper case, which an index or alias name cannot hold — a "
                "view named above the case rule is not refused by the cluster, it is answered "
                "with an empty result, so the world would read as one that changed nothing")
    return None


def world_view_fault(world_id: str) -> str | None:
    """Why `world_id` cannot name a world view, or `None`: the alias name rule plus no `-`.

    `-` delimits `wv-{id}-{stem}`, so an id containing it makes one world's view name parse as
    another's (`a-logs-nginx`'s view of `logs-*` reads as world `a`'s view of
    `logs-nginx-logs-*`)."""
    if (why := view_name_fault(world_id, f"world id {quoted(world_id)}")) is not None:
        return why
    if "-" in world_id:
        return (f"world id {quoted(world_id)} carries '-', which a view name uses to separate the id "
                "from the corpus it stages — an id holding the delimiter makes one view name "
                "readable as another world's, so the boundary between siblings stops holding")
    return None
