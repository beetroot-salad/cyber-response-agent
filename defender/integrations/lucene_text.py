"""Lucene query-string and KQL text mechanics: just enough to find the values a query bounds a
range or comparison with (#1347 r6.2), so a frozen run can refuse one on Elasticsearch's own
clock (`now` date math) while every other mention of the word passes as data.

One scanner, not patterns over raw text: an escape (`\\[`), a quoted phrase, or a regex term
(`/[now]+/`) holds no bound, while a range (`[a TO b]`, `{a TO *}`) or a comparison (`:>=x`,
`:(>a AND <b)`) holds bounds whether or not each bound is quoted. Lives beside the adapters,
where vendor-named knowledge is allowed.
"""

from __future__ import annotations

import re

#: Elasticsearch date math anchored on the cluster's clock: `now`, then nothing or an operator
#: (`now-1h`, `now+5m`, `now/d`). Case-insensitive, erring toward refusal.
_DATE_MATH_NOW = re.compile(r"now(?:$|[+\-/|])", re.IGNORECASE)

#: Characters that end an unquoted Lucene term.
_TERM_END = set(" \t\r\n()[]{}\"")


def is_now_date_math(value: str) -> bool:
    """Is `value` (a bound, quotes already removed) date math on the cluster's clock?"""
    return bool(_DATE_MATH_NOW.match(value.strip()))


def _quoted(text: str, i: int) -> tuple[int, str]:
    """`(index after, value)` of the phrase opening at `text[i] == '"'`; `\\` escapes. An
    unterminated phrase runs to the end."""
    j, out = i + 1, []
    while j < len(text):
        ch = text[j]
        if ch == "\\" and j + 1 < len(text):
            out.append(text[j + 1])
            j += 2
            continue
        if ch == '"':
            return j + 1, "".join(out)
        out.append(ch)
        j += 1
    return j, "".join(out)


def _term(text: str, i: int) -> tuple[int, str]:
    """`(index after, value)` of the unquoted term at `i`; `\\` escapes the next character."""
    j, out = i, []
    while j < len(text) and text[j] not in _TERM_END:
        if text[j] == "\\" and j + 1 < len(text):
            out.append(text[j + 1])
            j += 2
            continue
        out.append(text[j])
        j += 1
    return j, "".join(out)


def _value(text: str, i: int) -> tuple[int, str]:
    """The bound at `i` (after whitespace): a quoted phrase or a term."""
    while i < len(text) and text[i].isspace():
        i += 1
    if i < len(text) and text[i] == '"':
        return _quoted(text, i)
    return _term(text, i)


def _regex_end(text: str, i: int) -> int:
    """The index after the regex term opening at `text[i] == '/'`; `\\` escapes."""
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "/":
            return j + 1
        j += 1
    return j


def _at_term_start(text: str, i: int) -> bool:
    return i == 0 or text[i - 1] in " \t\r\n(:"


def lucene_bounds(text: str) -> list[str]:
    """Every value a Lucene query string bounds a range or comparison with, unquoted and
    unescaped: both ends of `[a TO b]` / `{a TO b}` and the operand of `>`, `>=`, `<`, `<=` at a
    term's start (`f:>x`, `f:(>=x AND <y)`). Phrases, escapes and regex terms hold none."""
    bounds: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
        elif ch == '"':
            i, _ = _quoted(text, i)
        elif ch == "/" and _at_term_start(text, i):
            i = _regex_end(text, i)
        elif ch in "[{":
            i, ends = _range(text, i + 1)
            bounds += ends
        elif ch in "<>" and _at_term_start(text, i):
            i += 2 if text.startswith("=", i + 1) else 1
            i, value = _value(text, i)
            bounds.append(value)
        else:
            i += 1
    return bounds


def _range(text: str, i: int) -> tuple[int, list[str]]:
    """`(index after the closing bracket, [low, high])` of the range body starting at `i`."""
    ends: list[str] = []
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        if text[i] in "]}":
            return i + 1, ends
        i, value = _value(text, i)
        if value != "TO":
            ends.append(value)
        if i < len(text) and text[i] not in "]}" and not text[i].isspace() and text[i] != '"':
            i += 1  # a character the term scanner stopped on that closes nothing: step past
    return i, ends


#: A KQL range comparison and its operand (a quoted value takes `\\"` escapes).
_KQL_COMPARISON = re.compile(r'(?:>=|<=|>|<)\s*("(?:[^"\\]|\\.)*"|[^\s()"]+)')


def kql_bounds(text: str) -> list[str]:
    """Every operand of a KQL range comparison (`f >= x`, `f < "x"`), unquoted."""
    out = []
    for match in _KQL_COMPARISON.finditer(text):
        value = match.group(1)
        if value.startswith('"'):
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        out.append(value)
    return out
