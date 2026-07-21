#!/usr/bin/env python3

from __future__ import annotations

import re
import shlex

NON_ADAPTER_SHIMS = frozenset(
    {"defender-invlang", "defender-lessons", "defender-sql"}
)

OPERATOR_TOOLS = frozenset({"defender-policy"})

ADAPTER_RE = re.compile(r"scripts/adapters/\w+_adapter\.py\b")


def _skip_timeout_prefix(tokens: list[str]) -> int:
    i = 0
    if tokens[i] == "timeout":
        i += 1
        while i < len(tokens) and (tokens[i].startswith("-") or tokens[i].replace(".", "").isdigit()):
            i += 1
    return i


def _unwrap_bash_c(tokens: list[str], i: int) -> str | None:
    if i + 1 < len(tokens) and tokens[i + 1] == "-c":
        if i + 2 == len(tokens) - 1:
            return tokens[i + 2]
        return None
    return None


def _strip_prefix_from_raw(cmd: str, prefix_tokens: list[str]) -> str | None:
    rest = cmd.lstrip(" \t")
    for tok in prefix_tokens:
        if not rest.startswith(tok):
            return None
        rest = rest[len(tok):].lstrip(" \t")
    return rest


def unwrap(cmd: str) -> str | None:
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if not tokens:
        return None
    i = _skip_timeout_prefix(tokens)
    if i < len(tokens) and tokens[i] in ("bash", "sh"):
        return _unwrap_bash_c(tokens, i)
    if i > 0:
        return _strip_prefix_from_raw(cmd, tokens[:i])
    return cmd


def tokenize(script: str) -> list[str] | None:
    lex = shlex.shlex(script, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return None
