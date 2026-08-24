"""ES|QL text mechanics — the small set of string facts about the query language.

ONE home, because the alternative is what `split_commands`' own docstring warns about: "Two
copies of 'split on `|`' is how one of them learns about quoting and the other does not." The
two callers are `evals/oracle_golden/controls.py`, which places and reads back a window clause,
and the turn-N branch's corpus stager, which retargets a leading `FROM` — both reason about
command boundaries, and a `|` inside a string literal is DATA in both.

Lives beside the adapters because that directory is where per-vendor knowledge is allowed to
be vendor-named by design, and both callers already reach the elastic adapter.
"""

from __future__ import annotations

COMMAND_SEP = "|"


def separator_offsets(query: str) -> list[int]:
    """Offsets of the `|` characters that actually separate commands.

    A `|` inside a string literal is DATA, not a separator — `WHERE message RLIKE "sshd|sudo"`
    carries one — so a naive `split("|")` cuts a predicate in half. Splicing there produces a
    query that will not even parse, and reading command positions off it names the wrong
    command as the one that ran first.
    """
    out: list[int] = []
    in_string = escaped = False
    for i, ch in enumerate(query):
        if escaped:
            escaped = False
        elif ch == "\\" and in_string:
            escaped = True
        elif ch == '"':
            in_string = not in_string
        elif ch == COMMAND_SEP and not in_string:
            out.append(i)
    return out


def split_commands(query: str) -> list[str]:
    """This query's commands, split on the separators ES|QL actually uses."""
    edges = [-1, *separator_offsets(query), len(query)]
    return [query[a + 1:b] for a, b in zip(edges, edges[1:], strict=False)]


def split_first_command(query: str) -> tuple[str, str]:
    """`(first command, the rest INCLUDING its leading separator)`.

    What a caller retargeting the source command needs: `partition("|")` answers the same pair
    for an ordinary query and the wrong one for `FROM "logs|weird"`, where the split lands
    inside the quoted source name.
    """
    offsets = separator_offsets(query)
    if not offsets:
        return query, ""
    return query[: offsets[0]], query[offsets[0]:]
