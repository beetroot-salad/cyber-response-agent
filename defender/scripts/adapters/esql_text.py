"""ES|QL text mechanics — the small set of string facts about the query language.

One home, so every caller treats a `|` inside a string literal as data: two copies of "split on
`|`" is how one learns about quoting and the other does not. Callers are
`evals/oracle_golden/controls.py` (placing a window clause) and the turn-N branch's corpus
stager (retargeting a leading `FROM`). Lives beside the adapters, where vendor-named knowledge
is allowed.
"""

from __future__ import annotations

import re

COMMAND_SEP = "|"

#: The source command every time-bearing ES|QL query opens with. `ROW` and `SHOW` have no
#: `@timestamp` to bound. A predicate only; `stagers/elastic._FROM` captures the clause's parts
#: because it rewrites them.
_OPENS_FROM = re.compile(r"\A\s*FROM\s", re.IGNORECASE)


def opens_with_from(query: str) -> bool:
    """Does this query open with the `FROM` source command?

    Asked before adding a `@timestamp` stage: on any other source it would turn a working query
    into an `Unknown column [@timestamp]` error.
    """
    return bool(_OPENS_FROM.match(split_first_command(query)[0]))


def separator_offsets(query: str) -> list[int]:
    """Offsets of the `|` characters that actually separate commands.

    A `|` inside a string literal (`RLIKE "sshd|sudo"`) is data, not a separator.
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
    """`(first command, the rest including its leading separator)`.

    Unlike `partition("|")`, correct for `FROM "logs|weird"`.
    """
    offsets = separator_offsets(query)
    if not offsets:
        return query, ""
    return query[: offsets[0]], query[offsets[0]:]
