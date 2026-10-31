"""ES|QL text mechanics — the small set of string facts about the query language.

One home, so every caller treats a `|` inside a string literal as data: two copies of "split on
`|`" is how one learns about quoting and the other does not. Callers are
`evals/oracle_golden/controls.py` (placing a window clause) and the Elastic adapter's ES|QL
confinement (`esql_sources`: every index a query reads, #1347 O2a). Lives beside the adapters,
where vendor-named knowledge is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass

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


# the sources a query reads (#1347 O2a)


class EsqlUnclassifiable(ValueError):
    """A query whose sources `esql_sources` cannot name: a source command it does not know, a
    malformed source list, an unterminated string or comment, or a command that reads an index
    it cannot see (`ENRICH` reads its policy's)."""


#: Source commands that read the indexes they name.
_READING_SOURCES = frozenset({"FROM", "TS"})
#: Source commands that read no index.
_INDEXLESS_SOURCES = frozenset({"ROW", "SHOW"})
#: Processing commands that read no index beyond their input rows. A command outside this set
#: (and not `LOOKUP JOIN`) may read one the parser cannot see, so it is unclassifiable.
_ROW_COMMANDS = frozenset({
    "WHERE", "EVAL", "STATS", "INLINESTATS", "KEEP", "DROP", "RENAME", "SORT", "LIMIT",
    "DISSECT", "GROK", "MV_EXPAND", "CHANGE_POINT", "SAMPLE", "FORK", "COMPLETION", "RERANK",
})


@dataclass(frozen=True)
class _Token:
    #: `word` (an unquoted run), `string` (a quoted value, unquoted), or the punctuation itself.
    kind: str
    text: str


def _string_end(query: str, i: int) -> tuple[int, str]:
    """`(offset past the string literal opening at i, its value)`; triple quotes take no escapes."""
    if query.startswith('"""', i):
        end = query.find('"""', i + 3)
        if end < 0:
            raise EsqlUnclassifiable("an unterminated triple-quoted string")
        return end + 3, query[i + 3:end]
    j, escaped = i + 1, False
    while j < len(query):
        ch = query[j]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            return j + 1, query[i + 1:j]
        j += 1
    raise EsqlUnclassifiable("an unterminated string")


def _tokens(query: str) -> list[_Token]:
    """The query's tokens with comments dropped: a comment is not a source (O2a)."""
    out: list[_Token] = []
    i = 0
    while i < len(query):
        ch = query[i]
        if ch.isspace():
            i += 1
        elif query.startswith("//", i):
            end = next((k for k in range(i, len(query)) if query[k] in "\r\n"), -1)
            i = len(query) if end < 0 else end + 1
        elif query.startswith("/*", i):
            end = query.find("*/", i + 2)
            if end < 0:
                raise EsqlUnclassifiable("an unterminated block comment")
            i = end + 2
        elif ch == '"':
            i, value = _string_end(query, i)
            out.append(_Token("string", value))
        elif ch == "`":
            # A quoted identifier: `"`, `//` and `/*` inside it open nothing; "``" is a literal backtick.
            j = i + 1
            while True:
                if j >= len(query):
                    raise EsqlUnclassifiable("an unterminated backtick identifier")
                if query[j] == "`":
                    if query.startswith("``", j):
                        j += 2
                        continue
                    break
                j += 1
            out.append(_Token("string", query[i + 1:j].replace("``", "`")))
            i = j + 1
        elif ch in "|,()":
            out.append(_Token(ch, ch))
            i += 1
        else:
            j = i
            while (j < len(query) and not query[j].isspace() and query[j] not in '|,()"`'
                   and not query.startswith("//", j) and not query.startswith("/*", j)):
                j += 1
            out.append(_Token("word", query[i:j]))
            i = j
    return out


def _split_top(tokens: list[_Token], sep: str) -> list[list[_Token]]:
    """`tokens` split on `sep` outside parentheses; an unbalanced parenthesis is unclassifiable."""
    parts: list[list[_Token]] = [[]]
    depth = 0
    for tok in tokens:
        if tok.kind == "(":
            depth += 1
        elif tok.kind == ")":
            depth -= 1
            if depth < 0:
                raise EsqlUnclassifiable("an unbalanced ')'")
        if tok.kind == sep and depth == 0:
            parts.append([])
        else:
            parts[-1].append(tok)
    if depth:
        raise EsqlUnclassifiable("an unbalanced '('")
    return parts


def _keyword(command: list[_Token]) -> str:
    if not command or command[0].kind != "word":
        raise EsqlUnclassifiable("an empty command, or one that opens with no keyword")
    return command[0].text.upper()


def _source_list(tokens: list[_Token]) -> list[str]:
    """The indexes a `FROM` / `TS` list names, a subquery's included; `METADATA` ends the list."""
    for at, tok in enumerate(tokens):
        if tok.kind == "word" and tok.text.upper() == "METADATA":
            tokens = tokens[:at]
            break
    found: list[str] = []
    for item in _split_top(tokens, ","):
        if len(item) == 1 and item[0].kind in ("word", "string"):
            found.append(item[0].text)
        elif len(item) > 2 and item[0].kind == "(" and item[-1].kind == ")":
            found.extend(_query_sources(item[1:-1]))
        else:
            raise EsqlUnclassifiable(
                "a source list entry that is neither one index name nor one subquery")
    return found


def _query_sources(tokens: list[_Token]) -> list[str]:
    commands = _split_top(tokens, "|")
    head = _keyword(commands[0])
    if head in _READING_SOURCES:
        found = _source_list(commands[0][1:])
    elif head in _INDEXLESS_SOURCES:
        found = []
    else:
        raise EsqlUnclassifiable(f"an unknown source command {commands[0][0].text!r}")
    for command in commands[1:]:
        found.extend(_processing_sources(command))
    return found


def _processing_sources(command: list[_Token]) -> list[str]:
    """The indexes one processing command reads: a `LOOKUP JOIN` target, or those of each
    `FORK` branch (a pipeline of processing commands); none for a row command."""
    keyword = _keyword(command)
    if keyword == "ENRICH":
        raise EsqlUnclassifiable("ENRICH reads its policy's indexes, which the query does not name")
    if keyword in _READING_SOURCES:
        raise EsqlUnclassifiable(f"a source command {command[0].text!r} after the first")
    if keyword == "LOOKUP":
        rest = command[1:]
        if (len(rest) < 2 or rest[0].kind != "word" or rest[0].text.upper() != "JOIN"
                or rest[1].kind not in ("word", "string")):
            raise EsqlUnclassifiable("a LOOKUP that names no JOIN target")
        return [rest[1].text]
    if keyword not in _ROW_COMMANDS:
        raise EsqlUnclassifiable(f"an unknown processing command {command[0].text!r}")
    if keyword != "FORK":
        return []
    found: list[str] = []
    for branch in _groups(command[1:]):
        for inner in _split_top(branch, "|"):
            found.extend(_processing_sources(inner))
    return found


def _groups(tokens: list[_Token]) -> list[list[_Token]]:
    """The contents of each outermost `( … )` group in `tokens`; anything between groups is
    unclassifiable (a `FORK` is its branches alone)."""
    groups: list[list[_Token]] = []
    depth = 0
    for tok in tokens:
        if tok.kind == "(":
            depth += 1
            if depth == 1:
                groups.append([])
                continue
        elif tok.kind == ")":
            depth -= 1
            if depth == 0:
                continue
        if depth == 0:
            raise EsqlUnclassifiable("a FORK holding something other than its branches")
        groups[-1].append(tok)
    if not groups:
        raise EsqlUnclassifiable("a FORK with no branches")
    return groups


def esql_sources(query: str) -> list[str]:
    """Every index this ES|QL query reads, as named: each `FROM` / `TS` list entry (comma lists
    split, quotes removed), each source inside a subquery, each `LOOKUP JOIN` target. `ROW` and
    `SHOW` read none. Comments and string literals are not sources.

    `EsqlUnclassifiable` when the sources cannot be named — the caller refuses such a query
    rather than guess (#1347 O2a). Names are returned as written: judging them (`*`,
    cross-cluster `remote:`) is the caller's."""
    return _query_sources(_tokens(query))
