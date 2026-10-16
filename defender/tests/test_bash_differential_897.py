"""#897 — the executor's grammar, differentially against real bash."""
from __future__ import annotations

import itertools
import shutil
import subprocess

import pytest

from defender.runtime import bash_exec

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None,
    reason="the differential oracle IS bash; without it this file asserts nothing",
)

#: One word stands for all words — the grammar is over operators, and every non-operator token
#: takes the same path (`cur_argv.append`). `echo` is inert, and nothing here is ever executed.
_WORD = "echo"

_ALPHABET = (_WORD, "|", ";", "&&", "||", "\n", "2>/dev/null", "2>&1")

_CONNECTORS_ONLY = tuple(t for t in _ALPHABET if not t.startswith("2>"))

_FULL_ALPHABET_MAX_LEN = 3
_CONNECTOR_MAX_LEN = 4

_SEEDED_FAMILIES: tuple[tuple[str, ...], ...] = (
    (_WORD, "&&", ";", "\n", _WORD),      # the connector crosses the line — #897 review
    (_WORD, "||", ";", "\n", _WORD),
    (_WORD, "&&", ";", ";", "\n", _WORD),  # ...and survives more than one bare `;`
    (_WORD, "|", ";", "\n", _WORD),       # the #884 F-28 shape, spelled across a boundary
    (_WORD, "|", "&&", "\n", _WORD),
    (_WORD, ";", ";", "\n", _WORD),       # control: the carve-out, which must stay accepted
)

_SEPARATORS_BEFORE_A_BENIGN_SEMICOLON = frozenset({";", "&&", "||", "\n"})


def _render(combo: tuple[str, ...]) -> str:
    return " ".join(combo).replace(" \n ", "\n")


def _candidates() -> list[tuple[str, ...]]:
    seen: dict[tuple[str, ...], None] = {}
    for alphabet, max_len in (
        (_ALPHABET, _FULL_ALPHABET_MAX_LEN),
        (_CONNECTORS_ONLY, _CONNECTOR_MAX_LEN),
    ):
        for n in range(1, max_len + 1):
            for combo in itertools.product(alphabet, repeat=n):
                seen[combo] = None
    for combo in _SEEDED_FAMILIES:
        seen[combo] = None
    return list(seen)


def _without_benign_semicolons(combo: tuple[str, ...]) -> tuple[str, ...]:
    kept: list[str] = []
    prev: str | None = None
    for tok in combo:
        if tok == ";" and (prev is None or prev in _SEPARATORS_BEFORE_A_BENIGN_SEMICOLON):
            continue
        kept.append(tok)
        prev = tok
    return tuple(kept)


def _bash_accepts(commands: list[str]) -> list[bool]:
    """`bash -n <cmd>` for each command, driven from ONE Python subprocess."""
    script = (
        "while IFS= read -r -d '' cmd; do\n"
        "  if bash -n -c \"$cmd\" 2>/dev/null; then printf 'y\\n'; else printf 'n\\n'; fi\n"
        "done\n"
    )
    proc = subprocess.run(
        ["bash", "-c", script],
        input=b"".join(c.encode() + b"\0" for c in commands),
        capture_output=True,
        timeout=300,
    )
    verdicts = proc.stdout.decode().split()
    assert len(verdicts) == len(commands), (
        f"the bash oracle answered {len(verdicts)} of {len(commands)} candidates — "
        f"a truncated oracle silently shrinks the corpus. stderr: {proc.stderr[:400]!r}"
    )
    return [v == "y" for v in verdicts]


def _parse_accepts(command: str) -> bool:
    try:
        bash_exec.parse(command)
    except bash_exec.BashExecError:
        return False
    return True


@pytest.fixture(scope="module")
def corpus():
    """The corpus and bash's verdict on it, resolved once."""
    combos = _candidates()
    return tuple(zip(combos, _bash_accepts([_render(c) for c in combos]), strict=True))


def test_every_command_bash_rejects_is_refused_by_the_executor(corpus):
    """The class-level guard the two hand-found instances (#854 F-22, #884 F-28) each needed."""
    diverging = [
        combo for combo, ok in corpus
        if not ok and _parse_accepts(_render(combo))
    ]

    probes = [_render(_without_benign_semicolons(c)) or "true" for c in diverging]
    unexplained = [
        _render(combo)
        for combo, ok in zip(diverging, _bash_accepts(probes), strict=True)
        if not ok
    ]

    assert not unexplained, (
        "these commands are bash syntax errors that `bash_exec.parse` accepts, and the "
        "leading-`;` carve-out does not explain them:\n  "
        + "\n  ".join(repr(c) for c in sorted(unexplained)[:40])
    )

    load_bearing = [
        _render(combo) for combo in diverging
        if not _parse_accepts(_render(_without_benign_semicolons(combo)) or "true")
    ]
    assert not load_bearing, (
        "the benign-`;` exemption FLIPS this module's own verdict on these commands — `parse` "
        "accepts them but refuses what they strip to, so the `;` is dropping something:\n  "
        + "\n  ".join(repr(c) for c in sorted(load_bearing)[:40])
    )


def test_the_corpus_actually_exercises_the_grammar(corpus):
    """The control for the test above, which is a "no findings" assertion and so passes just as happily on an..."""
    assert len(corpus) > 1800, "the corpus shrank — the sweep is no longer exhaustive in both tiers"

    accepted = sum(1 for _, ok in corpus if ok)
    assert 0 < accepted < len(corpus), "the bash oracle is answering uniformly"

    refused = sum(1 for combo, _ in corpus if not _parse_accepts(_render(combo)))
    assert refused > 1000, (
        f"only {refused} candidates were refused by parse — the executor's own guards are "
        "not being reached, so a passing differential says nothing"
    )


def test_the_semicolon_exemption_does_not_cover_a_dropped_pipe():
    """The exemption's own guard rail, stated as a test so a future widening of..."""
    assert "|" not in _SEPARATORS_BEFORE_A_BENIGN_SEMICOLON
    assert _without_benign_semicolons((_WORD, "|", ";", _WORD)) == (_WORD, "|", ";", _WORD)
    # and the carve-out it IS meant to cover still strips
    assert _without_benign_semicolons((";", _WORD)) == (_WORD,)
    assert _without_benign_semicolons((_WORD, ";", ";", _WORD)) == (_WORD, ";", _WORD)
