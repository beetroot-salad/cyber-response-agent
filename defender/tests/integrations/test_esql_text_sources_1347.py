"""#1347 A5/A6: `esql_text.sources(query)` is the one reader of what an ES|QL query reads (verb and lab
guard): index expressions, `[]` if none, `None` if unreadable so callers fail closed."""
from __future__ import annotations

import random

import pytest

from defender.integrations import esql_text


@pytest.mark.parametrize(("query", "expected"), [
    pytest.param("FROM logs-* | LIMIT 1", ["logs-*"], id="from"),
    pytest.param("from logs-* | limit 1", ["logs-*"], id="lowercase"),
    pytest.param("FROM logs-*|LIMIT 1", ["logs-*"], id="no-space-before-the-separator"),
    pytest.param("FROM logs-a,logs-b", ["logs-a", "logs-b"], id="list"),
    pytest.param("FROM logs-a ,\t logs-b\n, alerts-*", ["logs-a", "logs-b", "alerts-*"], id="list-spaced"),
    pytest.param('FROM "logs-a", "alerts-*" | LIMIT 1', ["logs-a", "alerts-*"], id="quoted"),
    pytest.param("FROM logs-* METADATA _id, _index | LIMIT 1", ["logs-*"], id="metadata-is-not-a-source"),
    pytest.param("FROM\n  logs-*\n| LIMIT 1", ["logs-*"], id="source-on-the-next-line"),
    pytest.param("TS metrics-* | LIMIT 1", ["metrics-*"], id="ts"),
    pytest.param("FROM logs-* | LOOKUP JOIN hosts ON host.name", ["logs-*", "hosts"], id="lookup-join"),
    pytest.param("from logs-*\n| keep a\n| lookup   join hosts on a | lookup join owners on b",
                 ["logs-*", "hosts", "owners"], id="lookup-joins-lowercase-and-spaced"),
    pytest.param('FROM logs-* | WHERE m RLIKE "a|FROM .security-7" | LIMIT 1', ["logs-*"],
                 id="a-string-literal-is-data"),
    pytest.param('FROM logs-* | WHERE m == "LOOKUP JOIN .security-7"', ["logs-*"],
                 id="a-string-literal-holding-a-join-is-data"),
    pytest.param('FROM logs-* | WHERE m == """a " | LOOKUP JOIN .security-7 FROM .security-7 """ | LIMIT 1', ["logs-*"],
                 id="a-triple-quoted-string-holding-a-bare-quote-is-data"),
    pytest.param('FROM logs-* | WHERE m == """x""" | LOOKUP JOIN hosts ON k', ["logs-*", "hosts"],
                 id="a-triple-quoted-string-then-a-join"),
    pytest.param("ROW a = 1 | EVAL b = a + 1", [], id="row-reads-nothing"),
    pytest.param("SHOW INFO", [], id="show-reads-nothing"),
])
def test_sources_lists_every_index_expression_the_query_reads(query, expected):
    """A5/A6: FROM, TS and LOOKUP JOIN name sources (quotes and METADATA dropped, string literals
    ignored); ROW and SHOW read none."""
    assert esql_text.sources(query) == expected


@pytest.mark.parametrize("query", [
    pytest.param("", id="empty"),
    pytest.param("   ", id="blank"),
    pytest.param("FROM", id="from-without-a-source"),
    pytest.param("FROM | LIMIT 1", id="from-with-an-empty-source"),
    pytest.param("FROM logs-a,, logs-b", id="empty-source-in-a-list"),
    pytest.param("LIMIT 1", id="no-source-command"),
    pytest.param("SELECT * FROM logs-*", id="not-esql"),
    pytest.param("FROM logs-* | LOOKUP JOIN", id="join-without-an-index"),
    pytest.param("FROM logs-* | FORK (WHERE a > 1) (WHERE a < 1)", id="fork"),
    pytest.param("FROM (FROM logs-*) | LIMIT 1", id="subquery"),
    pytest.param("FROM logs-a, (FROM logs-b) | LIMIT 1", id="subquery-beside-a-source"),
    pytest.param("FROM logs-* | ENRICH hosts ON host.name", id="enrich"),
    pytest.param("FROM remote:logs-* | LIMIT 1", id="remote-cluster"),
    pytest.param("FROM *:logs-* | LIMIT 1", id="every-remote-cluster"),
    pytest.param("FROM logs-*, remote:logs-* | LIMIT 1", id="remote-among-sources"),
])
def test_sources_is_none_when_the_query_cannot_be_read_with_confidence(query):
    """A5/A6: unparsable text, a subquery, FORK, ENRICH and a remote `cluster:index` are `None`
    (not an empty list, which means "reads no index"), so every caller fails closed."""
    assert esql_text.sources(query) is None


@pytest.mark.parametrize("query", [
    pytest.param("FROM logs-*, /* x */ .security-7", id="comment-between-sources"),
    pytest.param("FROM logs-* | LOOKUP JOIN /* x */ .security-7 ON a", id="comment-before-a-join-index"),
    pytest.param("FROM logs-*\n// x\n, .security-7", id="line-comment-between-sources"),
    pytest.param("FROM logs-*,\n.security-7", id="source-on-the-next-line"),
    pytest.param("FROM logs-*,\t.security-7", id="tab"),
    pytest.param("FrOm logs-*, .security-7", id="mixed-case"),
    pytest.param("FROM logs-* METADATA _id | LOOKUP JOIN\n .security-7 ON a", id="join-index-on-the-next-line"),
    pytest.param('FROM logs-*, ".security-7"', id="quoted"),
    pytest.param("FROM logs-*|LOOKUP JOIN .security-7 ON a", id="no-space-before-the-separator"),
    pytest.param("ROW a = 1 | LOOKUP JOIN .security-7 ON a", id="join-after-a-row"),
    pytest.param("FROM logs-* | EVAL a = 1 | LOOKUP JOIN .security-7 ON a | LIMIT 1", id="join-after-other-commands"),
])
def test_a_source_is_never_hidden_from_the_reader(query):
    """A5/A6: however the text is spelled, a query that reads `.security-7` is read as naming it
    or as unreadable (`None`), never as reading only what is around it."""
    got = esql_text.sources(query)

    assert got is None or any(".security-7" in s for s in got), got


#: Spellings of a source: bare or double-quoted. `logs|weird` can only be quoted.
BARE = ["logs-a", ".security-7", "alerts-*", "idx_1.x", "hosts", "logs-*"]
QUOTED_ONLY = ["logs|weird"]
#: Remote-cluster spellings: any source holding `:` is unreadable, quoted or not.
COLONED = ["remote:logs-*", "*:logs-*", "c1:idx", "a:b:c"]
#: Text that tempts a reader to see a comment, a source or a separator where there is only data.
HOSTILE = ["/*", "*/", "//", "|", ":", '\\"', "FROM zz", "LOOKUP JOIN zz", " ", "x", "-- ", "\\\\"]


def _words(rng: random.Random, pool: list[str], n: int) -> str:
    return "".join(rng.choice(pool) for _ in range(n))


def _block(rng: random.Random, depth: int = 0) -> str:
    """A balanced (possibly nested) block comment whose body is hostile text."""
    quiet = [h for h in HOSTILE if h not in ("/*", "*/")]
    parts = [_words(rng, quiet, rng.randint(0, 4))
             for _ in range(rng.randint(1, 3))]
    if depth < 2 and rng.random() < 0.4:
        parts.insert(rng.randint(0, len(parts)), _block(rng, depth + 1))
    return "/* " + " ".join(parts) + " */"


def _gap(rng: random.Random) -> str:
    """What sits between two tokens: blanks, block comments (nested too), or a line comment."""
    kind = rng.random()
    if kind < 0.35:
        return rng.choice([" ", "  ", "\t", "\n", ""]) or " "
    if kind < 0.7:
        return f" {_block(rng)} "
    if kind < 0.85:
        between = rng.choice(["", " ", "\n"])
        return f" {_block(rng)}{between}{_block(rng)} "
    return " //" + _words(rng, HOSTILE + ["\""], rng.randint(0, 5)) + "\n"


def _spell(rng: random.Random, name: str) -> str:
    """Quoted or bare, as the writer likes; only a name holding `|` must be quoted (a coloned one may be either)."""
    return f'"{name}"' if "|" in name or rng.random() < 0.4 else name


def _literal(rng: random.Random) -> str:
    """A string literal of hostile text: double-quoted, or triple-quoted (where a bare `"` is allowed)."""
    if rng.random() < 0.5:
        return f'"{_words(rng, HOSTILE, rng.randint(1, 5))}"'
    body = _words(rng, HOSTILE + ['"', '""', "|", "FROM zz", '" | LOOKUP JOIN zz "'], rng.randint(1, 5))
    while '"""' in body:
        body = body.replace('"""', '" "')
    return f'"""{"x" if body.startswith(chr(34)) else ""}{body}{"x" if body.endswith(chr(34)) else ""}"""'


def _commands(rng: random.Random, joins: list[str]) -> list[str]:
    """Piped commands: filters with hostile string literals, and every join in `joins` in order."""
    toks: list[str] = []
    pending = list(joins)
    for _ in range(rng.randint(1, 4)):
        toks.append("|")
        kind = rng.choice(["where", "eval", "limit"] + (["join"] if pending else []))
        if kind == "join":
            toks.append(rng.choice(["LOOKUP JOIN", "lookup  join"]))
            toks.append(_spell(rng, pending.pop(0)))
            toks.append("ON k")
        elif kind == "where":
            toks.append(f"WHERE m == {_literal(rng)}")
        elif kind == "eval":
            toks.append("EVAL a = 1")
        else:
            toks.append("LIMIT 5")
    for name in pending:
        toks += ["|", "LOOKUP JOIN", _spell(rng, name), "ON k"]
    return toks


def _query(rng: random.Random, remote: bool) -> tuple[str, list[str] | None]:
    """A query built around a known source set; the expected reading is that set, or `None`
    when one source holds `:`. Strings and comments carry `/*`, `*/`, `//`, `|`, `:`, `"`, and
    text that looks like another source."""
    names = [rng.choice(BARE + QUOTED_ONLY) for _ in range(rng.randint(1, 3))]
    joins = [rng.choice(BARE) for _ in range(rng.randint(0, 2))]
    if remote:
        slot = rng.randrange(len(names) + len(joins))
        if slot < len(names):
            names[slot] = rng.choice(COLONED)
        else:
            joins[slot - len(names)] = rng.choice(COLONED)
    toks: list[str] = []
    if rng.random() < 0.5:
        toks.append(_block(rng))
    toks.append(rng.choice(["FROM", "from", "FrOm"]))
    for i, name in enumerate(names):
        toks.append(_spell(rng, name) + ("," if i < len(names) - 1 else ""))
    if rng.random() < 0.4:
        toks.append("METADATA _id, _index")
    toks += _commands(rng, joins)
    if rng.random() < 0.3:
        toks.append("//" + _words(rng, HOSTILE + ['"'], rng.randint(0, 5)))
    text = "".join(t + _gap(rng) for t in toks).rstrip(" ")
    return text, (None if remote else names + joins)


def test_sources_reads_every_generated_query_as_its_source_set_or_as_unreadable():
    """A5/A6: queries built around a known source set, with comments (nested too), hostile string
    literals (double- and triple-quoted) everywhere, and sources spelled bare or quoted, read as exactly
    that set (as a set: the design fixes no multiplicity); any source holding `:` reads `None`, bare or quoted."""
    rng = random.Random(1347)
    for case in range(400):
        query, want = _query(rng, remote=case % 4 == 3)
        got = esql_text.sources(query)
        assert (got is None) if want is None else (got is not None and set(got) == set(want)), \
            f"case {case}: {query!r} -> {got!r}"
