"""#1366 O11 / DC6: comparing the store's fault line with connect's handoff line.

The two print the SAME sentence and differ only in the locator: the store (a record) says `system <s> settings` /
`system <s> access`; the handoff (a folder) says the FILE (`config.env` / `access.yaml`, with whatever folder prefix).
Each helper replaces its side's locator with one placeholder, so the remaining sentence compares equal and each
side's locator is pinned separately (the record's is not a file, the handoff's is)."""
from __future__ import annotations

import re

LOCATOR = "<locator>"
FILES = {"settings": "config.env", "access": "access.yaml"}
#: A file name anywhere in the sentence (today's settings sentence says "its base is its access.yaml's"): the same text
#: on both sides, so it is normalised on both, whatever else the locator rewrite does.
_ANY_FILE = re.compile(r"\S*(?:config\.env|access\.yaml)\S*")


def _same_words(line: str) -> str:
    return _ANY_FILE.sub(LOCATOR, line)


def store_sentence(line: str, system: str, part: str) -> str:
    """The store's fault `line` with its record locator replaced; fails if the line does not locate the record."""
    locator = f"system {system} {part}"
    assert locator in line, f"the store's fault does not locate the record as {locator!r}: {line!r}"
    return _same_words(line.replace(locator, LOCATOR))


def handoff_lines(output: str, key: str, system: str, part: str) -> list[str]:
    """The handoff report's lines naming `key`, each with its file locator replaced; fails if a line locates the
    fault by the record's words instead of the file."""
    lines = [ln for ln in output.splitlines() if key in ln]
    assert lines, f"the handoff report does not name {key!r}:\n{output}"
    file = FILES[part]
    for ln in lines:
        assert file in ln, f"the handoff's fault does not locate the file {file!r}: {ln!r}"
        assert f"system {system} {part}" not in ln, f"the handoff locates the fault by the record, not the file: {ln!r}"
    return [_same_words(ln) for ln in lines]
