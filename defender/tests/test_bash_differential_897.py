"""#897 — the executor's grammar, differentially against real bash.

`bash_exec.parse` is a deliberately tiny hand-rolled grammar, and that is the design: the
permission gate grant-checks the `Pipeline` list `parse` produces (`permission/bash.py`) and
that same list is what crosses into the box (`box.py`), so there is no shell anywhere and no
second parse (`tests/intent_540.md` O7/M8, which rejects `bash -c` by name).

The standing tax on that design is one recurring defect class: **a command text bash rejects,
which our parser accepts with different semantics.** Twice now it has shipped and been found
by eye, one instance at a time —

  #854 F-22  `A |` / `A` then `| B`, across a line boundary.
  #884 F-28  `A | ; B`, `A | && B`, `A | | B`, `A | 2>/dev/null`, within a line. Three of
             those four went unenumerated by the issue reporting it, and the fix it proposed
             missed the case in its own title.

— because nothing tested the grammar against the only authority on it. This file is that test.

WHAT IS ASSERTED, AND IN WHICH DIRECTION

Only one: **anything `bash -n` rejects, `parse` must refuse.** The converse is false by
construction and must never be asserted here, in either direction:

  * We deliberately ACCEPT some text bash rejects — a `;` in a position where no command
    precedes it drops nothing (`A` then `; B` already means the two commands it runs), so
    refusing it would deny a harmless command under a reason (`UNTOKENIZABLE_REASON`) that
    names `|`/`&&`/`||` and not `;`. This is the ONE exemption below.
  * We deliberately REFUSE some text bash accepts — `A | 2>/dev/null` is a null command
    consuming the pipe, which this executor cannot reproduce, so #884 refuses it rather than
    silently dropping both the pipe and the redirect. Pinned in `test_bash_exec.py`, not here.

THE EXEMPTION IS THE LOAD-BEARING PART

An escape hatch spelled "the command contains a bare `;`" would have exempted #884 F-28's own
repro: `echo | ; echo` contains one, and stripping it yields the perfectly legal `echo | echo`.
An oracle that broad passes the bug it exists to catch. So the exemption is narrow in exactly
one way — a `;` counts as benign only where a command could START (line beginning, or after
`;`/`&&`/`||`/newline), and explicitly NOT after a `|`, because there a stage is already banked
and the `;` is what drops the pipe. `_SEPARATORS_BEFORE_A_BENIGN_SEMICOLON` omitting `|` is
what makes this file able to fail; verified by running the sweep against the pre-#884 parser,
where the whole `| ;` / `| &&` / `| ||` family reports as unexplained.

The sweep found one family neither #854 nor #884 had enumerated: `A && ;`, where the connector
is consumed and then dropped because the line does not END with it. The module refused `A &&`
and accepted `A && ;` — an inconsistency with no rule behind it, closed in `parse` (#897).
"""
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

#: The operator alphabet the executor claims to implement, plus the newline that makes each
#: PHYSICAL line its own lexing unit (there is no shell to join them, which is the seam #854
#: F-22 lived in). Anything outside this set is refused by `feed_token`'s operator arm long
#: before grammar is in question.
_ALPHABET = (_WORD, "|", ";", "&&", "||", "\n", "2>/dev/null", "2>&1")

#: The two redirect tokens are grammatically ONE shape — both are "a redirect group", and they
#: differ only in the `Stage.stderr` value `feed_token` sets. They matter for whether a stage
#: can empty itself (`A | 2>/dev/null`), which length 3 already reaches, so they are dropped
#: from the longer sweep rather than doubling it for no new grammar.
_CONNECTORS_ONLY = tuple(t for t in _ALPHABET if not t.startswith("2>"))

#: Two tiers, exhaustive in both — nothing here is sampled. The alphabet is small enough that
#: exhaustive is affordable, and random would be a coin flip on hitting `| ;` at all.
#: Tier A is the full alphabet to length 3; tier B is the connector alphabet to length 4. Every
#: defect this class has produced lives in tier A (`echo | ;` and `echo && ;` are both length
#: 3); tier B buys the four-token interactions between connectors at a quarter of the cost of
#: taking the full alphabet to length 4, which is ~4.7k bash forks and visibly load-sensitive.
_FULL_ALPHABET_MAX_LEN = 3
_CONNECTOR_MAX_LEN = 4

#: Spellings PAST both tiers, seeded by hand because a defect family actually lived there.
#:
#: Exhaustive length 5 over the connector alphabet is 7776 more candidates — ~13s of bash forks
#: idle and several times that on a loaded machine, against a sweep the tiers hold to ~2.8s. So
#: depth is bought where it has been earned instead of everywhere: `A && ;\n B` is 5 tokens and
#: was accepted with the `&&` reaching ACROSS the line boundary to run B conditionally on A —
#: found in review of #897's own fix, which had put the pending-connector check after the whole
#: parse instead of per line. Neither tier can render it, so neither assertion below could see
#: it; without these seeds this file still could not catch the last bug it was used to find.
#:
#: A new family found at length >= 5 belongs here, next to the one that earned the list.
_SEEDED_FAMILIES: tuple[tuple[str, ...], ...] = (
    (_WORD, "&&", ";", "\n", _WORD),      # the connector crosses the line — #897 review
    (_WORD, "||", ";", "\n", _WORD),
    (_WORD, "&&", ";", ";", "\n", _WORD),  # ...and survives more than one bare `;`
    (_WORD, "|", ";", "\n", _WORD),       # the #884 F-28 shape, spelled across a boundary
    (_WORD, "|", "&&", "\n", _WORD),
    (_WORD, ";", ";", "\n", _WORD),       # control: the carve-out, which must stay accepted
)

#: A `;` preceded by one of these — or by nothing — sits where a command could START, so it
#: drops nothing and the carve-out lets it through. `|` is POINTEDLY absent: see the module
#: docstring. Changing this set widens the exemption, which is the one edit here that can
#: silently disarm the file.
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
    """`bash -n <cmd>` for each command, driven from ONE Python subprocess.

    The `bash -n -c` in the loop body still forks a bash per candidate — that is the oracle,
    and it cannot be avoided without moving the parse check away from bash itself. What the
    loop DOES remove is a `subprocess.run` per candidate: one pipe, one fork/exec from Python,
    and one wait, several thousand times over. `-n` means bash parses without running anything.
    `read -d ''` is why the commands are NUL-separated: every other delimiter is a byte a
    candidate might contain."""
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
    """The corpus and bash's verdict on it, resolved once.

    The oracle is one bash fork per candidate; at module scope the tests below share a single
    sweep instead of paying for it each. Returned as a tuple of (combo, bash_accepts) so no
    test can mutate what another reads."""
    combos = _candidates()
    return tuple(zip(combos, _bash_accepts([_render(c) for c in combos]), strict=True))


def test_every_command_bash_rejects_is_refused_by_the_executor(corpus):
    """The class-level guard the two hand-found instances (#854 F-22, #884 F-28) each needed.

    A divergence listed here is not automatically a bug — it is a spelling where our grammar
    and bash's disagree, and the answer is either a fix or a deliberate, WRITTEN carve-out. It
    is never left silent, because silent is how both prior instances survived a green suite."""
    diverging = [
        combo for combo, ok in corpus
        if not ok and _parse_accepts(_render(combo))
    ]

    # Of the divergences, exempt exactly those whose ONLY quarrel with bash is a benign `;`:
    # strip those and bash is satisfied. Anything still rejected after the strip diverges for
    # some OTHER reason, and that reason is what this test is for.
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

    # The exemption's own honesty, checked against OUR parser rather than bash's. Stripping a
    # benign `;` must not change what `parse` says: if it does, that `;` was load-bearing —
    # accepted with it, refused without — and the exemption is excusing a divergence instead
    # of explaining one. bash cannot see this, because the STRIPPED form is legal bash by
    # construction (that is what "explained" means above). It is how `A && ;\nB` hid: accepted,
    # while the `A &&\nB` it strips to is refused as a connector crossing a line boundary.
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
    """The control for the test above, which is a "no findings" assertion and so passes just as
    happily on an empty or unparsed corpus. Pins that the sweep reaches real disagreement:
    bash rejects a large share of the corpus, and our parser refuses a large share too."""
    assert len(corpus) > 1800, "the corpus shrank — the sweep is no longer exhaustive in both tiers"

    accepted = sum(1 for _, ok in corpus if ok)
    assert 0 < accepted < len(corpus), "the bash oracle is answering uniformly"

    refused = sum(1 for combo, _ in corpus if not _parse_accepts(_render(combo)))
    assert refused > 1000, (
        f"only {refused} candidates were refused by parse — the executor's own guards are "
        "not being reached, so a passing differential says nothing"
    )


def test_the_semicolon_exemption_does_not_cover_a_dropped_pipe():
    """The exemption's own guard rail, stated as a test so a future widening of
    `_SEPARATORS_BEFORE_A_BENIGN_SEMICOLON` fails here rather than silently disarming the
    sweep. Adding `|` to that set — the obvious "simplification" — is what would have let
    #884 F-28 through: `echo | ; echo` strips to the perfectly legal `echo | echo`."""
    assert "|" not in _SEPARATORS_BEFORE_A_BENIGN_SEMICOLON
    assert _without_benign_semicolons((_WORD, "|", ";", _WORD)) == (_WORD, "|", ";", _WORD)
    # and the carve-out it IS meant to cover still strips
    assert _without_benign_semicolons((";", _WORD)) == (_WORD,)
    assert _without_benign_semicolons((_WORD, ";", ";", _WORD)) == (_WORD, ";", _WORD)
