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
    pytest.param('FROM logs-* | WHERE m == "a\\" | LOOKUP JOIN .security-7 ON k"', ["logs-*"],
                 id="an-escaped-quote-is-data"),
    pytest.param('FROM logs-* | KEEP `a"""b` | LIMIT 1', ["logs-*"],
                 id="a-quote-run-inside-a-backtick-name-is-a-name"),
    pytest.param("ROW a = 1 | EVAL b = a + 1", [], id="row-reads-nothing"),
    pytest.param("SHOW INFO", [], id="show-reads-nothing"),
])
def test_sources_lists_every_index_expression_the_query_reads(query, expected):
    """A5/A6: FROM, TS and LOOKUP JOIN name sources (quotes and METADATA dropped, string literals
    ignored); ROW and SHOW read none. The two triple-quoted positives that stood here moved to the
    refusals below (A6 revised, r6.4.4: any triple-quoted string is `None`)."""
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
    pytest.param("WHERE a > 1 | LIMIT 1", id="a-later-command-first"),
    pytest.param("FROM logs-a | TS logs-b", id="a-first-command-later"),
])
def test_sources_is_none_when_the_query_cannot_be_read_with_confidence(query):
    """A5/A6: unparsable text, a subquery, FORK, ENRICH and a remote `cluster:index` are `None`
    (not an empty list, which means "reads no index"), so every caller fails closed."""
    assert esql_text.sources(query) is None


#: A6 revised (r6.4.4): the reviewer's bypass. ES|QL's lexer ends a triple-quoted string with up to two
#: extra `"` (`"""a""""` is one literal), so the join is real; a reader that disagrees sees it as data.
BYPASS = 'FROM events-* | EVAL x = """a"""" | LOOKUP JOIN secret ON k | EVAL y = "x\\""'


@pytest.mark.parametrize("query", [
    pytest.param(BYPASS, id="the-reviewers-bypass"),
    pytest.param('FROM logs-* | WHERE m == """a " | LOOKUP JOIN .security-7 FROM .security-7 """ | LIMIT 1',
                 id="a-triple-quoted-string-holding-a-bare-quote"),
    pytest.param('FROM logs-* | WHERE m == """x""" | LOOKUP JOIN hosts ON k', id="a-triple-quoted-string-then-a-join"),
    pytest.param('FROM logs-* | EVAL x = """""" | LIMIT 1', id="an-empty-triple-quoted-string"),
    pytest.param('FROM logs-* | EVAL x = """a""""" | LIMIT 1', id="a-triple-quoted-string-ending-in-five"),
    pytest.param('FROM logs-* | WHERE m == "\\"""', id="a-run-of-three-made-by-an-escape"),
    pytest.param('FROM logs-* | EVAL x = "" | EVAL y = """', id="a-run-of-three-after-an-empty-string"),
    pytest.param('FROM logs-* // """\n| LIMIT 1', id="a-run-of-three-in-a-line-comment"),
    pytest.param('FROM logs-* /* """" */ | LIMIT 1', id="a-run-of-four-in-a-block-comment"),
])
def test_quoting_that_might_be_misread_is_none(query):
    """A6 revised (r6.4.4): any triple-quoted string, and any run of three or more `"` outside a backtick-quoted
    name, is `None`, wherever it stands (string, comment, between tokens), so no lexer disagreement can hide a
    source. Control: the same run inside a backtick name is a name (in the listing above)."""
    assert esql_text.sources(query) is None


#: A6 revised: the allow-list. First commands and what each reads; later commands, each with a sample body.
FIRST = {"FROM": ("FROM logs-a", ["logs-a"]), "TS": ("TS metrics-a", ["metrics-a"]),
         "ROW": ("ROW a = 1", []), "SHOW": ("SHOW INFO", [])}
LATER = {"WHERE": ("WHERE a > 1", []), "EVAL": ("EVAL b = a + 1", []), "STATS": ("STATS c = COUNT(*) BY a", []),
         "KEEP": ("KEEP a, b", []), "DROP": ("DROP b", []), "RENAME": ("RENAME a AS z", []),
         "SORT": ("SORT a DESC", []), "LIMIT": ("LIMIT 5", []), "DISSECT": ('DISSECT m "%{a} %{b}"', []),
         "GROK": ('GROK m "%{WORD:w}"', []), "MV_EXPAND": ("MV_EXPAND a", []),
         "LOOKUP JOIN": ("LOOKUP JOIN hosts ON a", ["hosts"])}
#: Every other command, known to ES|QL or not.
OTHER = {"RERANK": 'RERANK "q" ON message', "COMPLETION": 'COMPLETION c = "q" WITH { "inference_id": "x" }',
         "ENRICH": "ENRICH hosts ON a", "FORK": "FORK (WHERE a > 1) (WHERE a < 1)",
         "INLINESTATS": "INLINESTATS c = COUNT(*) BY a", "CHANGE_POINT": "CHANGE_POINT v ON @timestamp",
         "SAMPLE": "SAMPLE 0.1", "FOOBAR": "FOOBAR a"}


@pytest.mark.parametrize("first", sorted(FIRST))
@pytest.mark.parametrize("later", sorted(LATER))
def test_each_allowed_command_reads_as_expected_after_each_first_command_and_after_another_command(first, later):
    """A6 revised (r6.4.4): every allowed first command, followed by every allowed later command, directly and after
    another allowed command, reads as the sources each one names. Controls for the allow-list's positive side."""
    head, head_reads = FIRST[first]
    body, reads = LATER[later]
    assert esql_text.sources(f"{head} | {body}") == head_reads + reads
    assert esql_text.sources(f"{head} | LIMIT 9 | {body} | KEEP a") == head_reads + reads


@pytest.mark.parametrize("command", sorted(OTHER))
@pytest.mark.parametrize("where", ["second", "later", "first"])
def test_every_command_off_the_allow_list_is_none(command, where):
    """A6 revised (r6.4.4): a command not on the allow-list gives `None` wherever it stands, known to ES|QL
    (RERANK, COMPLETION, ENRICH, FORK, INLINESTATS, CHANGE_POINT, SAMPLE) or not (FOOBAR)."""
    query = {"second": f"FROM logs-a | {OTHER[command]}",
             "later": f"FROM logs-a | WHERE a > 1 | {OTHER[command]} | LIMIT 1",
             "first": f"{OTHER[command]} | LIMIT 1"}[where]
    assert esql_text.sources(query) is None, query


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
    if rng.random() < 0.8:   # A6 revised: a triple-quoted literal makes the query `None`; most stay readable
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
    that set (as a set: the design fixes no multiplicity); any source holding `:` reads `None`, bare or quoted,
    and (A6 revised, r6.4.4) so does any query holding a run of three `"`: a triple-quoted literal included."""
    rng = random.Random(1347)
    for case in range(400):
        query, want = _query(rng, remote=case % 4 == 3)
        if '"""' in query:   # A6 revised: a run of three `"` (no backtick names are generated) is `None`
            want = None
        got = esql_text.sources(query)
        assert (got is None) if want is None else (got is not None and set(got) == set(want)), \
            f"case {case}: {query!r} -> {got!r}"
