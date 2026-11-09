"""ES|QL text mechanics — the small set of string facts about the query language.

One home, so every caller treats a `|` inside a string literal as data: two copies of "split on
`|`" is how one learns about quoting and the other does not. Callers are
`evaluations/oracle_golden/controls.py` (placing a window clause), the Elastic adapter's ES|QL
confinement and the chaos guard (`sources`: what a query reads, #1347 A5). Lives beside the
adapters, where vendor-named knowledge is allowed.
"""

from __future__ import annotations

import re

COMMAND_SEP = "|"

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


# the sources a query reads (#1347 A5/A6)

_TOKEN = re.compile(r'''
    (?P<ws>\s+)
  | (?P<line>//[^\r\n]*)
  | (?P<triple>""".*?""")
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<tick>`(?:[^`]|``)*`)
  | (?P<sep>\|)
  | (?P<comma>,)
  | (?P<paren>[()])
  | (?P<word>(?:(?!/\*|//)[^\s|,"()`])+)
''', re.VERBOSE | re.DOTALL)

#: Commands that read an index they do not name, or hold a pipeline of their own.
_UNREADABLE_COMMANDS = frozenset({"ENRICH", "FORK", "FROM", "TS", "ROW", "SHOW"})

_Token = tuple[str, str]


def _block_comment_end(query: str, start: int) -> int:
    """Offset past the (nesting) block comment opening at `start`, or -1 if it never closes."""
    depth, i = 0, start
    while i < len(query):
        if query.startswith("/*", i):
            depth, i = depth + 1, i + 2
        elif query.startswith("*/", i):
            depth, i = depth - 1, i + 2
            if depth == 0:
                return i
        else:
            i += 1
    return -1


def _tokens(query: str) -> list[_Token] | None:
    """The query's tokens without whitespace or comments, or `None` where the text does not
    tokenize (an unterminated string or comment)."""
    out: list[_Token] = []
    i = 0
    while i < len(query):
        if query.startswith("/*", i):
            i = _block_comment_end(query, i)
            if i < 0:
                return None
            continue
        m = _TOKEN.match(query, i)
        if m is None:
            return None
        i = m.end()
        if m.lastgroup not in ("ws", "line"):
            out.append((str(m.lastgroup), m.group()))
    return out


def _commands(tokens: list[_Token]) -> list[list[_Token]] | None:
    """The tokens split at command separators; `None` if a command is empty."""
    commands: list[list[_Token]] = [[]]
    for token in tokens:
        if token[0] == "sep":
            commands.append([])
        else:
            commands[-1].append(token)
    return None if any(not c for c in commands) else commands


def _index_name(token: _Token) -> str | None:
    """The index expression a source token names, or `None` if it is not a plain local one
    (a subquery, a remote `cluster:index`, an escaped or triple-quoted name)."""
    kind, text = token
    if kind == "string":
        text = text[1:-1]
    elif kind != "word":
        return None
    return None if not text or ":" in text or "\\" in text else text


def _from_sources(rest: list[_Token]) -> list[str] | None:
    """The comma list after `FROM` / `TS`, up to an optional `METADATA` clause."""
    found: list[str] = []
    i = 0
    while True:
        name = _index_name(rest[i]) if i < len(rest) else None
        if name is None:
            return None
        found.append(name)
        i += 1
        if i == len(rest) or (rest[i][0] == "word" and rest[i][1].upper() == "METADATA"):
            return found
        if rest[i][0] != "comma":
            return None
        i += 1


def _later_command_sources(command: list[_Token]) -> list[str] | None:
    """What a command after the first reads: its `LOOKUP JOIN` index, nothing for most."""
    head, rest = command[0], command[1:]
    if head[0] != "word":
        return None
    keyword = head[1].upper()
    if keyword == "LOOKUP":
        joined = bool(rest) and rest[0][0] == "word" and rest[0][1].upper() == "JOIN"
        name = _index_name(rest[1]) if joined and len(rest) > 1 else None
        return None if name is None else [name]
    return None if keyword in _UNREADABLE_COMMANDS else []


def _first_command_sources(command: list[_Token]) -> list[str] | None:
    head, rest = command[0], command[1:]
    keyword = head[1].upper() if head[0] == "word" else ""
    if keyword in ("ROW", "SHOW"):
        return []
    return _from_sources(rest) if keyword in ("FROM", "TS") else None


def sources(query: str) -> list[str] | None:
    """The index expressions this ES|QL query reads, in order: the `FROM` / `TS` list and every
    `LOOKUP JOIN` index, quotes removed, comments and string literals ignored. `[]` means it
    reads no index (`ROW`, `SHOW`); `None` means it cannot be read with confidence (ENRICH, FORK,
    a subquery, a remote cluster, unparsable text), and the caller must fail closed."""
    tokens = _tokens(query)
    commands = _commands(tokens) if tokens else None
    if commands is None:
        return None
    found = _first_command_sources(commands[0])
    for command in commands[1:]:
        later = _later_command_sources(command)
        if found is None or later is None:
            return None
        found += later
    return found
