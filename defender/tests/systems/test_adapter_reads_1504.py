"""#1504: a catalog adapter declares the non-GET reads it sends and the catalog reads them cold (O1); connect's
validator prints them given only the system (O4). The record judgement's cases are folded into their neighbours."""
from __future__ import annotations

import ast
import itertools
import os
import random
import re
import string
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest


from defender.tests.support.shared.contracts._by_path import import_lint_lib
from defender.tests.systems import _reads1504 as X
from defender.tests.systems._rules1470 import rules

_astlib = import_lint_lib("_astlib")

ELASTIC_SETTINGS = {"ELASTIC_EVENTS_INDEX": "logs-*", "ELASTIC_ALERTS_INDEX": "alerts-*"}
REPO = Path(__file__).resolve().parents[3]
THREAT_INTEL_SETTINGS = {"THREAT_INTEL_TIMEOUT_SEC": "10"}


def test_1504_o1_each_adapter_declares_exactly_the_non_get_reads_it_sends():
    """Elastic declares its two searches, threat-intel its lookup, a GET-only adapter none (C3's census). (O1)"""
    catalog = rules("Catalog").of_checkout()
    got = {a: tuple(getattr(catalog.entry(a), X.ENTRY_FIELD)) for a in ("elastic", "threat-intel", "cmdb")}
    assert got == {"elastic": X.ELASTIC_READS, "threat-intel": X.THREAT_INTEL_READS, "cmdb": ()}


def test_1504_o1_the_catalog_reads_the_declared_reads_without_running_the_module(tmp_path):
    """An adapter whose import fails still has its declared reads in its catalog entry: they are read cold, like the
    other declarations, so the API can show them without loading the module. (O1)"""
    folder = tmp_path / "checkout" / "integrations"
    folder.mkdir(parents=True)
    (folder / "widget_adapter.py").write_text(textwrap.dedent(f'''\
        PREFIX = "WIDGET"
        REQUIRED_CONFIG_KEYS = ("TIMEOUT_SEC",)
        DISPLAY_NAME = "Widget"
        EXAMPLE = False
        {X.READS_CONSTANT} = (("POST", "/widgets/_find"),)
        raise RuntimeError("never run 1504")
        '''))
    catalog = rules("Catalog").of_checkout(tmp_path / "checkout")
    assert tuple(getattr(catalog.entry("widget"), X.ENTRY_FIELD)) == (("POST", "/widgets/_find"),)


# --- O4: connect's validator prints the reads given only the system --------------------------------------------------

def _validate(*args: str) -> str:
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", *args], cwd=REPO,
                          env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True, timeout=120,
                          check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out


def test_1504_o4_the_validator_prints_an_adapters_reads_given_only_the_system():
    """Before `access.yaml` exists: `validate_scaffold <system>` with no folder prints every read that adapter declares, so
    the agent can write them: both of Elastic's, and threat-intel's lookup. (O4)"""
    out = _validate("elastic")
    for route in X.ELASTIC_READS:
        assert X.shown(route) in out, (route, out)
    assert X.shown(X.THREAT_INTEL_READS[0]) in _validate("threat-intel")


# --- #1504 O4 (contract repair r3): exactly each adapter's own reads, in the validator and in the API listing ----------

PLANTED_READS = (("POST", "/widgets/_find"), ("PUT", "/widgets/*/mark"))


def _routes_named(text: str, pool: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """The routes of `pool` that `text` names whole (`METHOD path`, not a prefix of a longer path)."""
    import re

    return {r for r in pool if re.search(rf"(?<![A-Za-z]){re.escape(X.shown(r))}(?=$|[\s,;)`'\"])", text, re.M)}


def _validate_over(checkout: Path | None, system: str) -> str:
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    if checkout is not None:
        env["DEFENDER_DIR"] = str(checkout)
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", system], cwd=REPO,
                          env=env, capture_output=True, text=True, timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out


def _planted(tmp_path: Path) -> tuple[Path, Any]:
    checkout = X.plant_adapter(tmp_path / "planted", "widget", reads=repr(PLANTED_READS))
    (checkout / "integrations" / "widget_adapter.md").write_text(
        "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")  # O5: only the reads vary
    return checkout, rules("Catalog").of_checkout(checkout)


def test_1504_o4_the_validator_prints_exactly_each_adapters_reads(tmp_path):
    """Given only the system, for every catalog adapter and one planted adapter: the routes the output names are exactly
    that adapter's own entry's reads (none of another adapter's), and an adapter declaring `()` passes a reads row saying
    none. (O4)"""
    checkout, planted = _planted(tmp_path)
    catalog = rules("Catalog").of_checkout()
    cases: list[tuple[Path | None, str, tuple[Any, ...]]] = [
        (None, a, tuple(getattr(catalog.entry(a), X.ENTRY_FIELD))) for a in catalog.adapter_ids]
    cases.append((checkout, "widget", tuple(getattr(planted.entry("widget"), X.ENTRY_FIELD))))
    assert cases[-1][2] == PLANTED_READS, "premise: the planted list is read"
    pool = {r for _, _, reads in cases for r in reads}
    assert {*X.ELASTIC_READS, *X.THREAT_INTEL_READS, *PLANTED_READS} <= pool, pool
    assert any(reads == () for _, _, reads in cases), "premise: some adapter declares none"
    for where, system, reads in cases:
        out = _validate_over(where, system)
        assert _routes_named(out, pool) == set(reads), (system, out)
        rows = [line for line in out.splitlines() if "[✓]" in line and X.READS_ROW_WORD in line]
        assert rows, (system, out)
        if reads == ():
            assert [line for line in rows if X.NO_READS_WORD in line], (system, out)


def test_1504_o4_the_adapters_listing_serves_exactly_each_entrys_reads_from_the_catalog_it_was_built_with(tmp_path):
    """`GET /adapters`' item list (`ConfigRecords.list_adapters`, no database: it reads only the catalog it was built with)
    carries each entry's own reads as `{method, path}`: the checkout's adapters and a planted catalog's adapter. (O4)"""
    import asyncio

    from defender.api.config_records import ConfigRecords

    _checkout, planted = _planted(tmp_path)
    for catalog in (rules("Catalog").of_checkout(), planted):
        items = asyncio.run(ConfigRecords(None, None, catalog, None).list_adapters())  # type: ignore[arg-type]
        shown = {i.adapter_id: [(r["method"], r["path"]) for r in i.model_dump(mode="json")[X.API_FIELD]] for i in items}
        assert shown == {a: list(getattr(catalog.entry(a), X.ENTRY_FIELD)) for a in catalog.adapter_ids}, shown
    assert shown == {"widget": list(PLANTED_READS)}, shown


# --- #1504 A6: one route rule, shown honestly ---------------------------------------------------------------------------

def _usable_catalog_and_tree(tmp_path: Path, source: str | None) -> tuple[Path, Any]:
    """A repo-shaped tree (`defender/integrations/widget_adapter.py` with its reference) whose adapter declares `source`
    as its list, and the catalog read over its `defender/` folder."""
    root = tmp_path / "tree"
    checkout = X.plant_adapter(root / "defender", "widget", reads=source)
    (checkout / "integrations" / "widget_adapter.md").write_text(
        "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")
    return root, rules("Catalog").of_checkout(checkout)


def _lint_lines(root: Path) -> list[str]:
    """The catalog declarations lint's output lines over `root`."""
    done = subprocess.run([sys.executable, str(REPO / "tooling/lint/lint_catalog_declarations.py"), "--root", str(root)],
                          cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True,
                          timeout=300, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return out.splitlines()


def _lint_names_reads(root: Path, adapter: str = "widget") -> bool:
    """Whether the lint, run over `root`, reports a finding naming the list constant in `adapter`'s module."""
    return any(X.READS_CONSTANT in line and f"{adapter}_adapter.py" in line for line in _lint_lines(root))


def _parser_takes(route: tuple[str, str], where: str) -> bool:
    """Whether the tenant access parser takes `route` in an access record's `reads` or `writes`."""
    from defender.kit.faults import ConfigFault
    from defender.tenancy import parse_access
    from defender.tests.support.tenancy import _systems1366 as R

    try:
        parse_access(R.declaration("https://widget.example", **{where: (route,)}), system="widget")
    except ConfigFault:
        return False
    return True


def _oracle(method: str, path: str) -> bool:
    """A6.1's route shape, written from the design: the method is upper-case letters, 3 to 10; the path starts with `/` and
    holds no `?` or `#`."""
    import re

    return bool(re.fullmatch(r"[A-Z]{3,10}", method)) and path.startswith("/") and "?" not in path and "#" not in path


#: One seed, so a failure replays: every value below is the same on every run.
SEED = 1504
#: Characters the generators draw from (A6.1's inputs): letters of both cases, digits, `_`, blanks, non-ASCII capitals.
METHOD_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "_ \t\n\u00c9\u03a3\uff30"
PATH_CHARS = "////" + string.ascii_lowercase + string.ascii_uppercase + "**%%?# \u00e9"
FIXED_PATHS = ("/x?", "/x#", "//x", "/x//y", "/Items", "/items", "/", "", "/x\x00")  # NUL: only where YAML can carry it
FIXED_METHODS = ("GET", "HEAD", "get", "Head", "GET ", " GET", "HEAD\n", "PROPFIND", "GETX", "HEADS", "G\u00c9T", "\uff30OST")


def _method(rng: random.Random) -> str:
    """A method: usually upper-case letters with at most one mutation, else any 0-12 characters of `METHOD_CHARS`."""
    if rng.random() < 0.5:
        return "".join(rng.choice(METHOD_CHARS) for _ in range(rng.randint(0, 12)))
    word = list("".join(rng.choice(string.ascii_uppercase) for _ in range(rng.randint(2, 11))))
    if rng.random() < 0.5:
        word.insert(rng.randint(0, len(word)), rng.choice(METHOD_CHARS))
    return "".join(word)


def _path(rng: random.Random) -> str:
    """A path of 0 to about 300 characters over `PATH_CHARS`; `?` and `#` are rare so many are well-formed."""
    chars = PATH_CHARS if rng.random() < 0.3 else PATH_CHARS.replace("?", "").replace("#", "")
    n = rng.choice((rng.randint(0, 12), rng.randint(0, 40), rng.randint(130, 300)))
    body = "".join(rng.choice(chars) for _ in range(n))
    return body if rng.random() < 0.15 else "/" + body.lstrip("/")


def _pair(rng: random.Random) -> tuple[str, str]:
    return rng.choice((_method(rng), *FIXED_METHODS)), rng.choice((_path(rng), _path(rng), *FIXED_PATHS))


def _good_pair(rng: random.Random) -> tuple[str, str]:
    """A well-formed route that is not a read method (the oracle below agrees, asserted by the test)."""
    while True:
        method = "".join(rng.choice(string.ascii_uppercase) for _ in range(rng.randint(3, 10)))
        if method not in ("GET", "HEAD"):
            return method, "/" + _path(rng).replace("?", "").replace("#", "").lstrip("/")


def _near(rng: random.Random, pair: tuple[str, str]) -> tuple[str, str]:
    """An entry that is not `pair` but nearly: its path with the case of a letter flipped, or with a trailing `/` toggled."""
    method, path = pair
    flipped = path.swapcase() if path.swapcase() != path else path + "/"
    return method, rng.choice((flipped, path + "/" if not path.endswith("/") else path[:-1] or path + "x"))


def _non_pair(rng: random.Random) -> object:
    return rng.choice(("POST /x", 7, None, ("POST", "/x", "y"), ["POST", "/x"], {"method": "POST"}, ("POST",), "", ()))


def _value(rng: random.Random) -> object:
    """One READ_ROUTES value: a tuple of 0-40 entries (clean; clean with one offence anywhere; or a mix of everything), or
    a whole value that is not a tuple."""
    profile = rng.choice(("clean", "clean", "one", "one", "mixed", "whole"))
    if profile == "whole":
        return rng.choice((None, 0, "", {}, [], "POST /x", 73519, False, [("POST", "/x")]))
    n = rng.choice((rng.randint(0, 6), rng.randint(0, 40), rng.randint(17, 40)))
    entries: list[object] = []
    while len(entries) < n:
        entries.append(_good_pair(rng) if not entries or rng.random() < 0.75 else _near(rng, rng.choice(entries)))  # type: ignore[arg-type]
    entries = list(dict.fromkeys(entries))  # type: ignore[arg-type]
    if profile == "one" and entries:
        at = rng.randrange(len(entries))
        kind = rng.choice(("repeat", "repeat", "pair", "non_pair", "read"))
        if kind == "repeat":
            entries.insert(rng.randint(at, len(entries)), entries[at])
        elif kind == "pair":
            entries[at] = _pair(rng)
        elif kind == "non_pair":
            entries[at] = _non_pair(rng)
        else:
            entries[at] = (rng.choice(("GET", "HEAD")), "/x/_a")
    elif profile == "mixed":
        for _ in range(rng.randint(1, 12)):
            kind = rng.choice(("pair", "pair", "non_pair", "repeat"))
            entry = _pair(rng) if kind == "pair" or not entries else _non_pair(rng) if kind == "non_pair" else rng.choice(entries)
            entries.insert(rng.randint(0, len(entries)), entry)
    return tuple(entries)


def _cold(value: object) -> object:
    """A value as the cold reader (the catalog's and the lint's) reads it from source: a list literal is read as a tuple,
    at any depth, as for every declaration (that reading is older than A6; the rule below judges what it yields)."""
    return tuple(_cold(part) for part in value) if isinstance(value, (list, tuple)) else value


def _oracle_list(value: object) -> list[object]:
    """A6.1 written from the design, over a value read cold (`_cold`): the entries that make it unusable (each offending entry
    once, in order; the value itself when it is not a tuple), empty when the list is usable. Usable: a tuple, each entry a
    2-tuple of text, the method of 3 to 10 upper-case ASCII letters and neither GET nor HEAD, the path text starting `/`
    with no `?` or `#`, and no two entries exactly equal."""
    value = _cold(value)
    if not isinstance(value, tuple):
        return [value]
    offenders: list[object] = []
    seen: list[object] = []
    for entry in value:
        if not (isinstance(entry, tuple) and len(entry) == 2 and all(isinstance(part, str) for part in entry)
                and _oracle(*entry) and entry[0] not in ("GET", "HEAD")):
            if entry not in offenders:
                offenders.append(entry)
        elif entry in seen and entry not in offenders:
            offenders.append(entry)
        seen.append(entry)
    return offenders


def _generated() -> tuple[list[tuple[str, str]], list[object]]:
    """(the pairs the parser is asked about, the READ_ROUTES values the readers are asked about): the earlier hand-picked
    pools in full, then seeded draws."""
    rng = random.Random(SEED)
    pairs = list(itertools.product(X.SHAPE_METHODS, X.SHAPE_PATHS)) + [_pair(rng) for _ in range(500)]
    values: list[object] = [(pair,) for pair in itertools.product(X.SHAPE_METHODS, X.SHAPE_PATHS)]
    values += [((method, "/x/_a"),) for method in X.METHOD_POOL]
    values += [None, 0, "", {}, [], "POST /x", 73519, False, [("POST", "/x")], (("POST", "/x"), {}), (("POST", "/x"), ["POST", "/x"])]
    values += [_value(rng) for _ in range(260)]
    return pairs, values


def test_1504_a61_the_access_parser_the_lint_and_the_catalog_judge_every_generated_route_and_list_alike(tmp_path):
    """Seeded generators (methods of 0-12 characters, paths of 0-300, lists of 0-40 entries with repeats at any distance,
    near variants and non-pairs, and whole values that are not tuples), judged against the A6.1 oracle written in this
    test: the parser takes a route in a record's reads and in its writes exactly when the shape holds; per value, one
    adapter, the catalog reads exactly the list when the oracle finds it usable and none otherwise, its reason holds
    the repr of every entry the oracle names, and the lint reports the list exactly then. (A6.1, A6.2)"""
    pairs, values = _generated()
    taken = [_oracle(*pair) for pair in pairs]
    assert 100 < sum(taken) < len(pairs) - 100, "premise: the pairs hold many routes the shape takes and many it refuses"
    disagree = [f"{pair!r}: the parser takes it in reads={_parser_takes(pair, 'reads')} writes={_parser_takes(pair, 'writes')}, "
                f"the rule says {want}" for pair, want in zip(pairs, taken, strict=True)
                if {_parser_takes(pair, "reads"), _parser_takes(pair, "writes")} != {want}]
    assert not disagree, "\n".join(disagree[:20])
    usable = [not _oracle_list(value) for value in values]
    clean = [v for v, ok in zip(values, usable, strict=True) if ok and isinstance(v, tuple)]
    tuples = [v for v in values if isinstance(v, tuple)]
    assert sum(usable) > 60, "premise: many usable lists"
    assert not all(usable), "premise: many unusable lists"
    assert any(len(v) > 16 for v in clean), "premise: a usable list longer than 16 entries"
    assert any(not p.isascii() for v in clean for _, p in v), "premise: a usable list with a non-ASCII path"
    assert any(len(p) > 128 for v in clean for _, p in v), "premise: a usable list with a path over 128 characters"
    assert any(len(_oracle_list(v)) >= 4 for v in values), "premise: a list with four or more offending entries"
    assert any(len(repr(_oracle_list(v))) > 450 for v in values), "premise: a reason longer than 400 characters"
    assert any(len(_oracle_list(v)) == 1 and not _oracle_list(v[:16]) for v in tuples), (
        "premise: a list whose one offence is past the 16th entry")
    assert any(v[j] == v[i] and j > i + 1 and _oracle(*v[i]) for v in tuples if all(isinstance(e, tuple) and len(e) == 2 for e in v)
               for i in range(len(v)) for j in range(len(v))), "premise: a repeat of an entry that is not the one before"
    assert any(isinstance(e, dict) for v in tuples for e in v), "premise: an entry that cannot be hashed"
    spelled = {repr(v) for v in values}
    assert {"None", "0", "''", "False", "73519", "{}", "[]", "[('POST', '/x')]"} <= spelled, "premise: the whole non-tuple values"
    checkout = tmp_path / "tree" / "defender"
    for i, value in enumerate(values):
        X.plant_adapter(checkout, f"w{i}", reads=repr(value))
        (checkout / "integrations" / f"w{i}_adapter.md").write_text(
            "## Credential\n\nNone known.\n\n## Pitfalls\n\nNone known.\n", encoding="utf-8")
    catalog = rules("Catalog").of_checkout(checkout)
    lines = _lint_lines(tmp_path / "tree")  # the one lint run
    wrong: list[str] = []
    for i, value in enumerate(values):
        entry = catalog.entry(f"w{i}")
        reads, reason = getattr(entry, X.ENTRY_FIELD), getattr(entry, X.UNUSABLE_FIELD)
        flagged = any(X.READS_CONSTANT in line and f"integrations/w{i}_adapter.py" in line for line in lines)
        offenders = _oracle_list(value)
        if not offenders:
            if reads != _cold(value) or not isinstance(reads, tuple) or reason is not None or flagged:
                wrong.append(f"{value!r}: usable by the oracle; the catalog reads {reads!r} ({reason!r}), lint flags={flagged}")
        elif reads is not None or not isinstance(reason, str) or not flagged:
            wrong.append(f"{value!r}: unusable by the oracle; the catalog reads {reads!r} ({reason!r}), lint flags={flagged}")
        else:
            missed = [repr(entry) for entry in offenders if repr(entry) not in reason]
            if missed:
                wrong.append(f"{value!r}: the reason does not name {missed}: {reason!r}")
    assert not wrong, "\n".join(wrong[:10]) + f"\n({len(wrong)} of {len(values)} lists)"


#: Single-offence lists of different kinds over entries a reason must tell apart without the wording of `repr`s (input-03).
KINDS = {"method": (("get", "/x"),), "path": (("POST", "x"),), "read method": (("GET", "/x"),), "not a pair": ("POST /x",),
         "repeat": (("POST", "/x"), ("POST", "/x")), "not a tuple": "POST /x"}


def test_1504_a61_each_kind_of_offence_has_a_reason_of_its_own_beyond_the_entries_it_shows(tmp_path):
    """One list per kind of single offence (a method, a path, a read method, a non-pair, a repeat, a value that is
    no tuple): the catalog's reasons, with every part of the offending entry (its repr, and the repr of each part) taken
    out, differ from one kind to the next, so the reason says why and does not only show the entry. (A6.2)"""
    checkout = tmp_path / "tree" / "defender"
    for i, source in enumerate(KINDS.values()):
        X.plant_adapter(checkout, f"k{i}", reads=repr(source))
    catalog = rules("Catalog").of_checkout(checkout)
    why: dict[str, str] = {}
    for i, (kind, source) in enumerate(KINDS.items()):
        reason = getattr(catalog.entry(f"k{i}"), X.UNUSABLE_FIELD)
        assert isinstance(reason, str), (kind, reason)
        entries = source if isinstance(source, tuple) else (source,)
        for text in sorted({repr(part) for entry in (*entries, source) for part in (entry if isinstance(entry, tuple) else ())}
                           | {repr(entry) for entry in entries} | {repr(source)}, key=len, reverse=True):
            reason = reason.replace(text, "")
        why[kind] = reason
    same = [(a, b) for a, b in itertools.combinations(why, 2) if why[a] == why[b]]
    assert not same, f"these kinds of offence share one reason once the entries are taken out: {same}: {why}"


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_1504_a61_a_read_method_route_is_taken_by_the_access_parser_but_not_in_a_declared_list(tmp_path, method):
    """Only `READ_ROUTES` excludes the methods that need no declaration: the parser takes `GET /x` in a record's reads, the
    lint and the catalog refuse it in the list. (A6.1)"""
    route = (method, "/x/_a")
    root, catalog = _usable_catalog_and_tree(tmp_path, repr((route,)))
    assert _parser_takes(route, "reads")
    assert _lint_names_reads(root)
    assert getattr(catalog.entry("widget"), X.ENTRY_FIELD) is None


@pytest.mark.parametrize(("source", "usable"), [
    pytest.param("(('POST', '/x/_a'), ('POST', '/x/_a'))", False, id="repeated-route"),
    pytest.param("(('POST', '/x/_a'), ('PUT', '/x/_a'))", True, id="same-path-two-methods"),
    pytest.param("(('POST', '/x/_a'), ('POST', '/x/_b'))", True, id="same-method-two-paths"),
    pytest.param("()", True, id="empty"),
])
def test_1504_a61_the_lint_and_the_catalog_judge_a_whole_list_usable_alike(tmp_path, source, usable):
    """The lint finds the list unusable exactly when the catalog reads no list from it (a repeat); a distinct-route list
    and `()` are usable in both. (A6.1)"""
    root, catalog = _usable_catalog_and_tree(tmp_path, source)
    entry = catalog.entry("widget")
    assert _lint_names_reads(root) is not usable
    assert (getattr(entry, X.ENTRY_FIELD) is not None) is usable
    assert (getattr(entry, X.UNUSABLE_FIELD) is None) is usable


def test_1504_a61_each_reader_of_the_methods_that_need_no_declaration_judges_exactly_them():
    """`defender.kit.access.READ_METHODS` is GET and HEAD; over seeded methods of 0-12 characters (and the earlier pool, the
    spellings of GET and HEAD, and real verbs), the proxy's route check admits a method with no declared route exactly
    when the kit lists it, and Elastic's in-process confinement judges (refuses an undeclared path) exactly then and passes
    any other to the proxy. The lint and the catalog refuse the listed ones in a list: the test above. (A6.1)"""
    from defender.credential_proxy._refusal import Refused
    from defender.credential_proxy._scope import check_route
    from defender.credential_proxy._tokens import READ
    from defender.integrations.confinement import confine_read_endpoint
    from defender.kit.access import READ_METHODS
    from defender.kit.faults import ConfinementFault
    from defender.tenancy import parse_access
    from defender.tests.support.tenancy import _systems1366 as R

    assert set(READ_METHODS) == {"GET", "HEAD"}
    declaration = parse_access(R.declaration("https://widget.example"), system="widget")
    rng = random.Random(SEED + 1)
    methods = [*X.METHOD_POOL, *X.SHAPE_METHODS, *FIXED_METHODS, "PROPFIND", "PATCH", "TRACE",
               *(_method(rng) for _ in range(300)), *(_good_pair(rng)[0] for _ in range(100))]
    for method in methods:
        reads = method in READ_METHODS
        try:
            check_route(declaration, "widget", method, "/undeclared", READ)
            admitted = True
        except Refused:
            admitted = False
        assert admitted is reads, ("proxy", method)
        try:
            confine_read_endpoint("elastic", "http://es:9200/_cat/indices", method=method)
            judged = False
        except ConfinementFault:
            judged = True
        assert judged is reads, ("elastic confinement", method)


# --- A6.1 one owner: no second copy of the method list or the route shape, and each reader takes them from the kit --------

#: Python source the scan below reads: the product tree and the lint scripts, not the tests that exercise them.
SCANNED = ("defender", "tooling/lint")
KIT_ACCESS = "defender/kit/access.py"
#: Where each reader of the rule lives. The kit's names are FORCED in `_reads1504.py`; each reader takes them from the kit.
PROXY, CONFINEMENT = "defender/credential_proxy/_scope.py", "defender/integrations/confinement.py"
LINT, CATALOG, PARSER = ("tooling/lint/lint_catalog_declarations.py", "defender/system_rules/catalog.py",
                         "defender/tenancy/_access.py")
JUDGEMENT = "defender/system_rules/judgement.py"
#: What a reader of the rule may call to use it (the kit's functions; `READ_METHODS` is a value, used through them).
KIT_RULE_FUNCTIONS = ("is_read_method", X.ROUTE_SHAPE_FAULT, X.READ_ROUTES_FAULT)
#: The route method's shape as the access parser spells it (A6.1). The proxy's own incoming-request pattern `[A-Z]{1,16}`
#: is another rule (a request line, not a declared route) and is not this.
ROUTE_METHOD_SHAPE = "[A-Z]{3,10}"
#: Fewer files than this read means the scan lost the tree (a path filter that drops it, e.g. a checkout under a folder named
#: like a skipped one), not that the tree is small.
SCANNED_FLOOR = 100


def _source_trees() -> dict[str, ast.Module]:
    skipped = {"tests", ".venv", "__pycache__", "node_modules"}
    trees = {path.relative_to(REPO).as_posix(): ast.parse(path.read_text(encoding="utf-8"))
             for top in SCANNED for path in sorted((REPO / top).rglob("*.py"))
             if not skipped & set(path.relative_to(REPO).parts)}
    assert KIT_ACCESS in trees, "premise: the scan reads the kit's access module"
    assert len(trees) > SCANNED_FLOOR, f"premise: the scan reads the product tree ({len(trees)} files)"
    return trees


def _is_read_method_literal(node: ast.AST) -> bool:
    """Whether `node` is a tuple, list or set literal of exactly the strings GET and HEAD (any case, any order)."""
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)) or not node.elts:
        return False
    texts = {e.value.upper() for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return len(texts) == len(node.elts) == 2 and texts == {"GET", "HEAD"}


def test_1504_a61_no_module_but_the_kit_binds_its_own_read_method_list_or_route_method_shape():
    """Repo-wide AST scan: outside `defender/kit/access.py` no collection literal equals {GET, HEAD} and no string holds
    the route method shape, so the list and the shape each have the one owner. (A6.1)"""
    methods, shape = [], []
    for rel, tree in _source_trees().items():
        if rel == KIT_ACCESS:
            continue
        for node in ast.walk(tree):
            if _is_read_method_literal(node):
                methods.append(f"{rel}:{node.lineno}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and ROUTE_METHOD_SHAPE in node.value:
                shape.append(f"{rel}:{node.lineno}")
    assert not methods, f"a second list of the methods that need no declaration: {methods}"
    assert not shape, f"a second copy of the route method shape: {shape}"


def _kit_calls(tree: ast.Module, rel: str) -> set[str]:
    """The `defender.kit.access` functions `tree` CALLS, as `_astlib` resolves each call at its site (an alias, a from-import
    or a module attribute counts; a bare import, a mention that is not a call, or a shadowing local does not)."""
    module, package = _astlib.module_and_package(rel.removeprefix("defender/")) if rel.startswith("defender/") else (None, None)
    env = _astlib.module_env(tree, module=module, package=package)
    prefix = f"{X.KIT_ACCESS_MODULE}."
    return {origin.removeprefix(prefix) for node in ast.walk(tree) if isinstance(node, ast.Call)
            if (origin := _astlib.callee(node, env)) and origin.startswith(prefix)}


def test_1504_a61_each_reader_of_the_rule_calls_the_kits_function_and_binds_no_literal_of_its_own():
    """Each reader of the rule (the proxy's route check, Elastic's confinement, the lint, the access parser, the catalog
    reader, the record judgement) makes a call that resolves to a function of `defender.kit.access` (`is_read_method`,
    `route_shape_fault` or `read_routes_fault`): a bare import does not use it. None binds a {GET, HEAD} literal. (A6.1)"""
    trees = _source_trees()
    for rel in (PROXY, CONFINEMENT, LINT, CATALOG, PARSER, JUDGEMENT):
        assert rel in trees, f"premise: {rel} is scanned"
        assert _kit_calls(trees[rel], rel) & set(KIT_RULE_FUNCTIONS), f"{rel} calls none of {KIT_RULE_FUNCTIONS} from {X.KIT_ACCESS_MODULE}"
        own = [n.lineno for n in ast.walk(trees[rel]) if _is_read_method_literal(n)]
        assert not own, f"{rel} binds a {{GET, HEAD}} literal of its own at {own}"


def test_1504_a61_the_route_shape_is_decided_by_calling_the_kits_functions_and_the_list_rule_builds_on_them():
    """The access parser CALLS `route_shape_fault`; the lint and the catalog reader CALL `read_routes_fault`; and
    `read_routes_fault`'s body CALLS `route_shape_fault` (a mention does not count) and uses `READ_METHODS`, so the list
    rule is not a third copy of the shape or the methods. (A6.1)"""
    trees = _source_trees()
    assert X.ROUTE_SHAPE_FAULT in _kit_calls(trees[PARSER], PARSER), f"{PARSER} does not call {X.ROUTE_SHAPE_FAULT}"
    for rel in (LINT, CATALOG):
        assert X.READ_ROUTES_FAULT in _kit_calls(trees[rel], rel), f"{rel} does not call {X.READ_ROUTES_FAULT}"
    functions = [n for n in ast.walk(trees[KIT_ACCESS]) if isinstance(n, ast.FunctionDef) and n.name == X.READ_ROUTES_FAULT]
    assert len(functions) == 1, f"{KIT_ACCESS} does not define exactly one {X.READ_ROUTES_FAULT}"
    env = _astlib.module_env(trees[KIT_ACCESS], module=X.KIT_ACCESS_MODULE)
    own = f"{X.KIT_ACCESS_MODULE}.{X.ROUTE_SHAPE_FAULT}"  # the module's own def, as `module_env` resolves it at the call's scope
    calls = [n for f in functions for n in ast.walk(f) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and env.scope_of.get(n, env).own_defs.get(n.func.id) == own]
    assert calls, f"{X.READ_ROUTES_FAULT} does not call {X.ROUTE_SHAPE_FAULT}"
    used = {n.id for f in functions for n in ast.walk(f) if isinstance(n, ast.Name)}
    assert X.READ_METHODS_NAME in used, f"{X.READ_ROUTES_FAULT} does not use {X.READ_METHODS_NAME}: {used}"


# --- A6.2 / A6.3: a list that is not usable is "no usable list", with its reason, in every reader ------------------------

#: Every source of "no usable list": readable-but-unusable (tagged with the text the reason names) and unreadable or absent.
NO_USABLE_LIST = [pytest.param(source, needles, id=f"unusable-{name}") for name, source, needles in X.UNUSABLE_LISTS] + [
    pytest.param(source, (), id=f"unreadable-{name}") for name, source in X.UNREADABLE_LISTS]
COMPUTED = "tuple([('POST', '/widgets/_find')])"


def _record(reads: tuple[tuple[str, str], ...]) -> Any:
    from defender.tenancy.models import SystemRecord, TenantRecords
    from defender.tests.support.tenancy import _systems1366 as R

    record = SystemRecord(system_id="widget", version=1, adapter_id="widget", settings={"WIDGET_TIMEOUT_SEC": "10"},
                          access=R.declaration("https://widget.example", reads=reads))
    return TenantRecords(systems={"widget": record})


def _served(catalog: Any) -> dict[str, dict[str, Any]]:
    import asyncio

    from defender.api.config_records import ConfigRecords

    items = asyncio.run(ConfigRecords(None, None, catalog, None).list_adapters())  # type: ignore[arg-type]
    return {i.adapter_id: i.model_dump(mode="json") for i in items}


@pytest.mark.parametrize(("source", "needles"), NO_USABLE_LIST)
def test_1504_a62_a_list_that_is_not_usable_has_no_reads_and_one_reason_in_the_catalog_lint_judgement_api_and_validator(
        tmp_path, source, needles):
    """Whatever makes `READ_ROUTES` no usable list: the entry has `reads None` and a reason naming each offending entry;
    the lint names the list; a record is refused at its access part and held as a fault carrying that reason (not another
    adapter's); the API serves it; the validator fails a row with it and prints no route to copy. (A6.2, A6.3, O3, O4)"""
    from defender.kit.faults import ConfigFault
    from defender.kit.settings import RECORDS
    from defender.systems.run_tenant import record_settings

    root, catalog = _usable_catalog_and_tree(tmp_path / "list", source)
    entry = catalog.entry("widget")
    reason = getattr(entry, X.UNUSABLE_FIELD)
    assert getattr(entry, X.ENTRY_FIELD) is None
    assert isinstance(reason, str), reason
    assert reason.strip()
    for needle in needles:
        assert needle in reason, (needle, reason)
    try:
        ast.parse(f"{X.READS_CONSTANT} = {source}")
        assert _lint_names_reads(root)
    except SyntaxError:  # a module that does not parse: the lint names the module, there is no list in it to name
        assert any("widget_adapter.py" in line for line in _lint_lines(root))
    # a computed list is another cause of no usable list: its reason is not this one's, nor is this one's "unreadable"
    computed = getattr(_usable_catalog_and_tree(tmp_path / "computed", COMPUTED)[1].entry("widget"), X.UNUSABLE_FIELD)
    unusable = bool(needles)
    if unusable:
        assert reason != computed, reason
    for reads in ((), (("POST", "/widgets/_fine_one"),)):
        records = _record(reads)
        faults = list(rules("judge_records")(records, None, catalog=catalog))
        assert [f for f in faults if reason in f and RECORDS.part("widget", "access") in f], (reads, reason, faults)
        named = [f for f in faults if any(needle in f for needle in needles)]
        assert named or not needles, (needles, faults)
        assert all(RECORDS.part("widget", "access") in f for f in named), (reads, named)
        held = record_settings(records, catalog=catalog)["access"]["widget"]
        assert isinstance(held, ConfigFault), held
        assert reason in str(held), (reason, str(held))
        if unusable:
            assert not [f for f in faults if computed in f], (computed, faults)
            assert computed not in str(held), str(held)
    item = _served(catalog)["widget"]
    assert item[X.API_FIELD] is None, item
    assert item[X.UNUSABLE_FIELD] == reason, item
    out = _validate_over(root / "defender", "widget")
    lines = sorted({line.strip() for line in reason.splitlines() if line.strip()}, key=len, reverse=True)
    first = reason.splitlines()[0].strip()
    assert [line for line in out.splitlines() if "[✗]" in line and X.READS_CONSTANT in line and first in line], out
    for line in lines:
        assert line in out, (line, out)  # the whole reason is printed, every non-blank line of it
    rest = out
    for line in lines:
        rest = rest.replace(line, "", 1)
    written = re.findall(r"'([^']*/[^']*)'", source or "")  # the strings the list spells (a module that does not parse has no AST)
    for text in (*needles, *written, "/widgets/_find"):
        assert text not in rest, (text, rest)  # nothing to copy is left once the reason is taken out
    assert not [line for line in out.splitlines() if "[✓]" in line and X.READS_ROW_WORD in line], out


def test_1504_a63_the_adapters_listing_serves_a_usable_list_with_no_reason_for_each_planted_and_checkout_adapter(tmp_path):
    """`GET /adapters`' item for a usable list: the routes as `{method, path}` and `reads_unusable: null`, for a planted
    adapter and for each of the checkout's own. (A6.3)"""
    _root, catalog = _usable_catalog_and_tree(tmp_path, "(('POST', '/widgets/_good'), ('PUT', '/widgets/*/mark'))")
    item = _served(catalog)["widget"]
    assert item[X.API_FIELD] == [{"method": "POST", "path": "/widgets/_good"},
                                 {"method": "PUT", "path": "/widgets/*/mark"}], item
    assert item[X.UNUSABLE_FIELD] is None, item
    own = _served(rules("Catalog").of_checkout())
    assert {a: i[X.UNUSABLE_FIELD] for a, i in own.items()} == dict.fromkeys(own)
    assert all(isinstance(i[X.API_FIELD], list) for i in own.values()), own


def test_1504_a63_the_openapi_document_declares_reads_nullable_and_reads_unusable_text_or_null_on_the_adapter_item():
    """`openapi.json`'s adapter item: `reads` is an array or null and `reads_unusable` is a string or null. (A6.3)"""
    import json

    schema = json.loads((REPO / "defender/api/openapi.json").read_text(encoding="utf-8"))["components"]["schemas"]
    props = schema["CatalogAdapter"]["properties"]
    reads = props[X.API_FIELD]["anyOf"]
    assert {"type": "null"} in reads
    assert any(branch.get("type") == "array" for branch in reads), reads
    reason = props[X.UNUSABLE_FIELD]["anyOf"]
    assert sorted(branch.get("type") for branch in reason) == ["null", "string"], reason
