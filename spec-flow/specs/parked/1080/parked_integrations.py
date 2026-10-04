# PARKED 2026-10-04 (scope cut of #1080, human-decided): preserved, NOT collected.
# Moved verbatim out of defender/tests/scripts_1080_split/test_1080_integrations.py by the cut author:
# 21 test function(s) whose demands were parked with an owner issue, plus the
# imports, constants and helpers they use (a helper the live file still uses is COPIED, not
# moved). The file name does not match test_*.py, so pytest never collects it. Each
# demand is a `form: clause` in spec-flow/specs/spec_graph_1080-scripts-split.yaml whose
# `parked.preserved_test` names its function here; the owner adopts the test into its own
# spec (restoring form: test) when it lands. The module docstring below is the source file's,
# unchanged: it describes the whole suite file as it stood before the cut.
# GOLDENS: the files only parked tests read (exitcodes.json, integrations.json, pages/*.html,
# runpage/*.html) moved to ./goldens/ beside this file; every other golden stays in
# defender/tests/scripts_1080_split/goldens/ (a kept test still reads it). `S.golden` and
# `S.GOLDENS` read the suite's folder, so the adopter moves the parked goldens back with the test.
"""#1080 group `integrations`: the generic HTTP check and the fault types, the Elastic grammar,
and the adapter-private endpoint table the adapters hand to the moved check.

What moves (10-03, 70-resolutions.md): the fault types (`AdapterFault`, `ConfigFault`,
`TransportFault`, `UpstreamFault`, `USAGE_EXIT_CODE`) and the generic HTTP check
(`normalize_endpoint`, `confine_read_endpoint`, `guard_outbound`, `TransportCapture`,
`CapturedRequest`, `ConfinementFault`) go to the pinned `defender/integrations/`; the Elastic
grammar (the world-view naming, `confine_index`, `_reach_ok`, the ES|QL text functions and
`esql_payload`) becomes a product Elastic module, found BY SYMBOL (dF0). What stays (M-A (a),
M-B (a)): `scripts/adapters/` with its eight adapters and `_stub_transport.py`; the endpoint
table `READ_ENDPOINT_ALLOWLIST`, adapter-private, which each adapter-side caller PASSES into
the moved check; host-state confinement, with `host_state_adapter`.

Every "as today" expectation is a golden (`goldens/integrations.json`) the base 80888efb
produced over the fixed input tables below. The capture ran the SAME `_section_*` observers
these tests run, with the locator resolving the base definitions (`SPEC1080_AT_BASE`), so the
golden and the test differ only in which definition the locator finds. Outputs go through ONE
normaliser (`_record`): pydantic's version URL is cut from a message, and a record longer than
`_COMPACT_AT` characters is kept as its digest and length (the megabyte rows).

THE TABLE ARGUMENT IS COINED HERE. M-B (a) makes the endpoint table a caller-supplied argument
of `confine_read_endpoint` and `guard_outbound` but names no spelling. This file passes it as
the keyword `TABLE_KW`, in one place (`_tabled`). Rename it there and nowhere else.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import importlib.util
import itertools
import json
import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "integrations"

#: THE MOVED CHECK'S ENDPOINT-TABLE ARGUMENT — coined here, rename HERE. The design (M-B
#: table (a)) makes the table a caller-supplied argument and names no spelling; every call of
#: the moved check in this file goes through `_tabled`, which passes it by this keyword.
TABLE_KW = "table"

#: The staying adapter folder (M-A (a)): the adapters, `_stub_transport.py` and the endpoint
#: table live here until #1172.
ADAPTERS = "defender/scripts/adapters"

STUB_TRANSPORT = f"{ADAPTERS}/_stub_transport.py"

ELASTIC_ADAPTER = S.REPO_ROOT / ADAPTERS / "elastic_adapter.py"

HOST_STATE_ADAPTER = S.REPO_ROOT / ADAPTERS / "host_state_adapter.py"

FAULT_NAMES = ("AdapterFault", "ConfigFault", "TransportFault", "UpstreamFault")

HTTP_CHECK_NAMES = ("normalize_endpoint", "confine_read_endpoint", "guard_outbound",
                    "TransportCapture", "CapturedRequest", "ConfinementFault")

GRAMMAR_NAMES = ("world_view", "is_world_view", "refuse_unnameable_world", "ViewNameError",
                 "VIEW_NAMESPACE", "_reach_ok", "_view_stem", "confine_index",
                 "split_first_command", "split_commands", "opens_with_from")

#: World labels (s191): empty, whitespace, upper case, look-alikes, over-long, already
#: namespaced, wildcard, comma list, date-math, leading hyphen/underscore/plus, cluster:index,
#: `.`/`..`, trailing slash, and the characters an alias cannot carry.
WORLD_LABELS = (
    "a", "a1", "e1a2.b", "base", "", " ", "\t", " a", "a ", "a b",
    "A", "aB", "\u00c9", "\u01c5", "\u0130", "\u00df",
    "\u0430",        # Cyrillic a, a look-alike of `a`
    "a\u200b",       # a trailing zero-width space
    "\uff41",        # fullwidth a
    "a" * 300,       # over-long
    "wv-a", "wv", "wv.a", "a*", "*", "a?", "a,b", "<a-{now/d}>",
    "-a", "_a", "+a", "remote:a", ".", "..", "a/", "a\\b", 'a"b', "a|b", "a\nb", None,
)

#: Corpus patterns a world view is built from (s191, s098).
BASE_PATTERNS = (
    "logs-*", "logs-", "logs*", "logs.*", "logs", "logs-system.auth-*", "security-audit-*",
    "*", "", "**", "logs-*-2026", "logs-**", "wv-*", "wv-a-*", "w*", "wv", "wv-",
    "LOGS-*", "Logs-*", "logs nginx-*", "logs|x-*", 'logs"x-*', "remote:logs-*",
    "-logs-*", "_logs-*", "+logs-*", ".", "..", "logs/", "logs-*,metrics-*",
    "<logs-{now/d}>", "_all", "logs-\u0430-*", "logs-\u200b*", "logs-\n*", None,
)

#: The configured corpus patterns the index checks run against (s192).
CONFIGURED = ("logs-*", "security-audit-*")

#: Index expressions (s192): the view namespace as a substring or in another case, `_all`, a
#: spanning wildcard, comma lists of valid and invalid, an alias, URL-encoded forms.
INDEX_EXPRS = (
    "logs-*", "logs-nginx", "logs-", "logs", "logs*", "l*", "*", "_all", "*-*", "*logs-*",
    "security-audit-2026", "security-audit-*", "logs-*,metrics-*", "logs-nginx,secret",
    "logs-nginx,logs-other", "logs-nginx,", ",logs-nginx", "-logs-*", "logs-*,-logs-secret",
    "alias-logs", "logs", "logs-%2A", "logs%2Dnginx", "%2A", "logs-nginx%2Csecret",
    "wv-a-logs-", "wv-a-logs-nginx", "wv-a-logs-*", "wv-a-logs-nginx.inject", "WV-a-logs-",
    "Wv-a-logs-", "wv-A-logs-", "xwv-a-logs-", "logs-wv-a-x", "wv-b-logs-", "wv-a-other",
    "wv-a-logsecret", "wv-a-", "wv-a", "wv", "wv-a-security-audit-x", "wv-a-logs-%2A",
    "wv-e1a2.b-logs-", "wv-e1a2.b-logs-nginx", "wv-e1a2-logs-", "remote:logs-*",
    "logs-nginx/", "", " ", None, 5, ["logs-*"],
)

INDEX_WORLDS = (None, "a", "e1a2.b")

#: ES|QL text forms (s193): empty, blank, BOM, leading newline, lower-case `from`, quoted
#: pipe, comments, unterminated string, two commands, keyword-named column.
ESQL_TEXTS = (
    "", " ", "\n", "\t\n ", "\ufeffFROM logs-* | LIMIT 1", "\nFROM logs-*\n| LIMIT 1",
    "from logs-* | limit 1", "From logs-*", "FROM logs-*", "FROMlogs-*", "FROM\tlogs-*|LIMIT 1",
    'FROM logs-* | WHERE m RLIKE "a|b" | LIMIT 1', 'FROM "logs|weird" | LIMIT 1',
    "// c | x\nFROM logs-* | LIMIT 1", "FROM logs-* /* a | b */ | LIMIT 1",
    'FROM logs-* | WHERE m == "abc | LIMIT 1', 'FROM logs-* | WHERE m == "a\\"|" | LIMIT 1',
    'FROM logs-* | WHERE m == "a\\\\" | LIMIT 1', "FROM a | LIMIT 1\nFROM b | LIMIT 2",
    "FROM a | LIMIT 1; FROM b", "FROM logs-* | KEEP from, limit, where | WHERE `from` == 1",
    "ROW a = 1 | EVAL b = a", "SHOW INFO", "|", "||", "FROM x |", "| FROM x", "  FROM x",
    "FROM x \\| y", None,
)

#: The megabyte ES|QL row, built here (never stored): 40 000 quoted-pipe stages.
MEGABYTE_ESQL = "FROM logs-*" + ' | WHERE message RLIKE "a|b"' * 40_000

#: A lead-shaped ES|QL query and a raw ES|QL response: the fixture control (s_eval_oracle).
FIXTURE_QUERY = (
    'FROM logs-system.auth-*\n'
    '| WHERE @timestamp >= "2026-07-25T07:45:35.000Z" '
    'AND @timestamp < "2026-07-25T07:48:37.065Z"\n'
    '        AND host.name == "canary-1"\n'
    "| STATS failed_count = COUNT(*) BY source.ip, user.name"
)

FIXTURE_RESP = {
    "columns": [{"name": "failed_count", "type": "long"}, {"name": "source.ip", "type": "ip"},
                {"name": "user.name", "type": "keyword"}],
    "values": [[96, "172.18.0.15", "root"], [3, "172.18.0.15", "admin"]],
    "took": 12,
}

UNBOUNDED_QUERY = 'FROM logs-zeek.ssh-* | WHERE source.ip == "a|b" | LIMIT 1'

WINDOW = (datetime(2026, 7, 18, 7, 17, 6, 32000, tzinfo=UTC),
          datetime(2026, 7, 18, 8, 17, 6, 32000, tzinfo=UTC))

_COLS = [{"name": "total", "type": "long"}]

#: Oracle control rows of unexpected shape (s194): (label, query, raw response).
PAYLOAD_ROWS = (
    ("fixture", FIXTURE_QUERY, FIXTURE_RESP),
    ("missing columns", "FROM logs-*", {"values": [[1]]}),
    ("missing values", "FROM logs-*", {"columns": _COLS}),
    ("missing both", "FROM logs-*", {}),
    ("extra fields", "FROM logs-*",
     {"columns": _COLS, "values": [[1]], "took": 7, "is_partial": False, "x": {"y": [1]}}),
    ("values a string", "FROM logs-*", {"columns": _COLS, "values": "abc"}),
    ("values None", "FROM logs-*", {"columns": _COLS, "values": None}),
    ("values an int", "FROM logs-*", {"columns": _COLS, "values": 5}),
    ("values a dict", "FROM logs-*", {"columns": _COLS, "values": {"a": 1}}),
    ("columns None", "FROM logs-*", {"columns": None, "values": [[1]]}),
    ("columns a string", "FROM logs-*", {"columns": "total", "values": [[1]]}),
    ("ragged rows", "FROM logs-*", {"columns": _COLS, "values": [[1], [1, 2], []]}),
    ("response a list", "FROM logs-*", [["total"], [1]]),
    ("response None", "FROM logs-*", None),
    ("empty query", "", {"columns": _COLS, "values": [[1]]}),
    ("blank query", "  \n", {"columns": _COLS, "values": [[1]]}),
    ("None query", None, {"columns": _COLS, "values": [[1]]}),
    ("non-string query", 5, {"columns": _COLS, "values": [[1]]}),
    ("query with a separator", "FROM a | LIMIT 1", {"columns": _COLS, "values": [[1]]}),
    ("names with separators", "FROM logs-*",
     {"columns": [{"name": "a|b", "type": "keyword"}, {"name": "c,d", "type": "keyword"},
                  {"name": "e\nf", "type": "keyword"}, {"name": "", "type": "keyword"}],
      "values": [["x", "y", "z", "w"]]}),
)

#: Endpoint spellings (s195): percent- and double-encoded dot segments, NUL, `//`, query,
#: fragment, absolute and scheme-relative URLs, trailing slash, non-ASCII, very long paths.
ENDPOINT_CASES = (
    ("identity", "/users/dev.dana", "GET"),
    ("identity", "/users/%2e%2e/secret", "GET"),
    ("identity", "/users/%2E%2E/%2E%2E/secret", "GET"),
    ("identity", "/users/%252e%252e/secret", "GET"),
    ("identity", "/users/%252E%252E/%252E%252E/secret", "GET"),
    ("identity", "/users/..%2fsecret", "GET"),
    ("identity", "/users%2F..%2F..%2Fsecret", "GET"),
    ("identity", "/users/%2e/dev.dana", "GET"),
    ("identity", "/health%00", "GET"),
    ("identity", "/health\x00", "GET"),
    ("identity", "/users/a%00b", "GET"),
    ("identity", "/users/a\x00/../../secret", "GET"),
    ("identity", "//health", "GET"),
    ("identity", "///health", "GET"),
    ("identity", "/users//dev.dana", "GET"),
    ("identity", "/health?x=1", "GET"),
    ("identity", "/health?../../secret", "GET"),
    ("identity", "/secret?/health", "GET"),
    ("identity", "/health#frag", "GET"),
    ("identity", "/secret#/health", "GET"),
    ("identity", "http://evil.example/health", "GET"),
    ("identity", "https://evil.example:8443/users/x?y=1#z", "GET"),
    ("identity", "http://user:pw@evil.example/users/x", "GET"),
    ("identity", "//evil.example/health", "GET"),
    ("identity", "//evil.example//health", "GET"),
    ("identity", "/health/", "GET"),
    ("identity", "/users/", "GET"),
    ("identity", "/users", "GET"),
    ("identity", "/users/d\u00e1n\u0430", "GET"),
    ("identity", "/h\u00e9alth", "GET"),
    ("identity", "/users/%C3%A9", "GET"),
    ("identity", "/users/%ZZ", "GET"),
    ("identity", "/users/" + "a" * 100_000, "GET"),
    ("identity", "/" + "a/.." * 20_000 + "/health", "GET"),
    ("identity", "/health;x=1", "GET"),
    ("identity", "/health\\..\\secret", "GET"),
    ("identity", "", "GET"),
    ("identity", "health", "GET"),
    ("identity", "/./health", "GET"),
    ("identity", "/users/../health", "GET"),
    ("identity", "/../../health", "GET"),
    ("identity", "/users/*", "GET"),
    ("identity", "/users/[a]", "GET"),
    ("identity", None, "GET"),
    ("identity", b"/health", "GET"),
    ("elastic", "http://es:9200/logs-*/_search?ignore_unavailable=true", "POST"),
    ("elastic", "http://es:9200/%2A/_search", "POST"),
    ("elastic", "http://es:9200/a/b/_search", "POST"),
    ("elastic", "http://es:9200/logs-*/_search/../../_security/user", "POST"),
    ("elastic", "http://es:9200/logs-*/_search%2F..%2F..%2F_security", "POST"),
    ("elastic", "http://es:9200/_query?format=json", "POST"),
    ("elastic", "http://es:9200/_query/", "POST"),
    ("elastic", "http://es:9200//_query", "POST"),
    ("elastic", "http://es:9200/_query#/_bulk", "POST"),
    ("ticket", "/tickets?status=open", "GET"),
    ("ticket", "/tickets/SOC-1/comments", "GET"),
    ("ticket", "/tickets/", "POST"),
)

#: Method spellings (s196), each tried against a GET and a POST endpoint.
METHODS = ("GET", "POST", "get", "post", "Get", " GET", "GET ", "GET\n", "\tPOST", "",
           None, "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND",
           "G E T", "G\u0395T", "\u0420OST", "\uff27\uff25\uff34", "GET\x00", "*", "GET|POST",
           "GET,POST", 0, b"GET")

METHOD_ENDPOINTS = (("identity", "/health"), ("elastic", "http://es:9200/_query"))

#: System-name spellings (s197), each tried against a stub and an Elastic endpoint. The known
#: systems with no read endpoints are the adapter roster's host-state and tacit-knowledge and
#: the ticket writer's case-history.
SYSTEMS = ("elastic", "Elastic", "ELASTIC", "identity", "IDENTITY", "threat-intel",
           "threat_intel", "Threat-Intel", "change-mgmt", "change_mgmt", "cmdb", " cmdb",
           "cmdb ", "cmdb\n", "", "unknown", "host-state", "tacit-knowledge", "case-history",
           None, "elastic\x00", "\u0435lastic", "*", "ticket,cmdb", 0)

SYSTEM_ENDPOINTS = (("/health", "GET"), ("http://es:9200/_query", "POST"))

#: Systems a table names with NO entries (s197). The base check reads its own table, which
#: names neither, so the base golden for these rows is its unknown-system verdict: a system
#: with no entries must be judged exactly as one the table does not name.
EMPTY_ENTRY_SYSTEMS = ("host-state", "tacit-knowledge")

#: The fixed (system, url, method) table of s_http_confinement_unchanged.
HTTP_CASES = (
    ("elastic", "http://es:9200/_query?format=json", "POST"),
    ("elastic", "http://es:9200/logs-*/_search?ignore_unavailable=true", "POST"),
    ("elastic", "http://es:9200/_cluster/health", "GET"),
    ("elastic", "http://kibana:5601/api/status", "GET"),
    ("elastic", "http://es:9200/logs-*/_delete_by_query", "POST"),
    ("change-mgmt", "http://stub/changes/CR-1", "GET"),
    ("change-mgmt", "http://stub/changes/CR-1", "POST"),
    ("cmdb", "http://stub/hosts/web-1", "GET"),
    ("cmdb", "http://stub/hosts/web-1/../../admin", "GET"),
    ("identity", "http://stub/users/dev.dana/can_access", "GET"),
    ("identity", "http://stub/users/../../secret", "GET"),
    ("threat-intel", "http://stub/lookup/1.2.3.4", "GET"),
    ("threat-intel", "http://stub/indicators", "DELETE"),
    ("ticket", "http://stub/tickets", "GET"),
    ("ticket", "http://stub/tickets", "POST"),
    ("case-history", "http://stub/tickets", "POST"),
    ("host-state", "http://stub/health", "GET"),
)

#: The parity table (H6, H7): (url, method) under the system `elastic`, the one system the
#: Elastic adapter's request path can name (it fixes its own `SYSTEM`).
PARITY_CASES = (
    ("http://es:9200/_query?format=json", "POST"),
    ("http://es:9200/logs-*/_search?ignore_unavailable=true", "POST"),
    ("http://es:9200/_cluster/health", "GET"),
    ("http://kibana:5601/api/status", "GET"),
    ("http://es:9200/_query", "GET"),
    ("http://es:9200/_cluster/health", "POST"),
    ("http://es:9200/logs-*/_delete_by_query", "POST"),
    ("http://es:9200/_security/user", "GET"),
    ("http://es:9200/logs-*/_search/../../_security/user", "POST"),
    ("http://es:9200/%2e%2e/_query", "POST"),
    ("http://es:9200/_query/%2e%2e/_bulk", "POST"),
    ("http://es:9200/_query", "post"),
    ("http://es:9200/_query", ""),
    ("http://es:9200//_query", "POST"),
    ("//evil.example/_query", "POST"),
    ("http://es:9200/logs-*/_doc/1", "PUT"),
)

#: Cases for the table-less call: two the base table admits, one it refuses.
NO_TABLE_CASES = (
    ("elastic", "http://es:9200/_query", "POST"),
    ("identity", "http://stub/health", "GET"),
    ("identity", "http://stub/secret", "GET"),
)

#: World views a branch lane minted at the base (s213, s098): (pattern, episode token, label).
MINTS = (
    ("logs-*", "e1a2", "a"),
    ("logs-*", "e1a2", "base"),
    ("logs-system.auth-*", "e1a2", "b"),
    ("security-audit-*", "x9", "c1"),
    ("logs-", "e1a2", "a"),
    ("logs.*", "e1a2", "a"),
)

_PYDANTIC_URL = re.compile(r"\n? *For further information visit https://errors\.pydantic\.dev/\S+")

_COMPACT_AT = 2048


def _compact(value: Any) -> Any:
    """`value`, or its digest and length when its JSON exceeds `_COMPACT_AT` characters (the
    megabyte and very-long rows: a golden holds what they produced, not a megabyte of it)."""
    text = json.dumps(value, sort_keys=True, ensure_ascii=True)
    if len(text) <= _COMPACT_AT:
        return value
    return {"compacted": {"sha256": hashlib.sha256(text.encode("ascii")).hexdigest(),
                          "chars": len(text)}}


def _run(fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> tuple[Any, Exception | None]:
    try:
        return fn(*args, **kwargs), None
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return None, e


def _record(value: Any, exc: Exception | None) -> Any:
    """`S.outcome`'s shape for a `_run` result, through the one normaliser."""
    if exc is not None:
        return _compact({"raises": type(exc).__name__,
                         "message": _PYDANTIC_URL.sub("", str(exc))})
    return _compact({"returns": S.canon(value)})


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=True))


def _assert_rows(section: str, observed: Any) -> None:
    """`observed` equals the base golden's `section`, row by row; the message names the first
    rows that differ."""
    expected = S.golden(GOLDEN)[section]
    got = _jsonable(observed)
    if got == expected:
        return
    if isinstance(got, list) and isinstance(expected, list):
        bad = [(i, e, g) for i, (e, g) in enumerate(itertools.zip_longest(expected, got))
               if e != g]
        shown = "\n".join(f"  row {i}: base {e!r}\n         now  {g!r}" for i, e, g in bad[:4])
        raise AssertionError(
            f"{section}: {len(bad)} of {max(len(got), len(expected))} rows differ from what the "
            f"base answered (golden {GOLDEN}.json):\n{shown}")
    raise AssertionError(f"{section}: differs from the base golden:\n  base {expected!r}\n"
                         f"  now  {got!r}")


def _integ(name: str) -> Any:
    """`name` from its home under the pinned `defender/integrations/`."""
    return S.moved(name, home=S.INTEGRATIONS)


def _http() -> SimpleNamespace:
    return SimpleNamespace(**{n: _integ(n) for n in HTTP_CHECK_NAMES})


def _grammar() -> SimpleNamespace:
    """The Elastic grammar, each name from wherever its one definition now lives (dF0)."""
    return SimpleNamespace(**{n: S.moved(n) for n in GRAMMAR_NAMES})


def _faults() -> SimpleNamespace:
    """The fault classes from their home under `defender/integrations/`, and the
    `USAGE_EXIT_CODE` that module exposes (m1 lets it take the value from the flat tier)."""
    module = S.moved_module("AdapterFault", home=S.INTEGRATIONS)
    return SimpleNamespace(**{n: _integ(n) for n in FAULT_NAMES},
                           USAGE_EXIT_CODE=module.USAGE_EXIT_CODE)


def _endpoint_table() -> Any:
    """The adapter-private `READ_ENDPOINT_ALLOWLIST` (M-B table (a)), found by symbol under
    `scripts/adapters/` — wherever in that folder it now sits, and only there."""
    homes = [d for d in S.definitions("READ_ENDPOINT_ALLOWLIST") if S.under(d, ADAPTERS)]
    assert len(homes) == 1, (
        f"READ_ENDPOINT_ALLOWLIST should be defined once, adapter-private, under {ADAPTERS} "
        f"(M-B table (a)); definitions: {list(S.definitions('READ_ENDPOINT_ALLOWLIST'))}")
    return S.module_at(homes[0]).READ_ENDPOINT_ALLOWLIST


def _tabled(fn: Callable[..., Any], kwargs: dict[str, Any], table: Any) -> dict[str, Any]:
    """`kwargs` for a call of the moved check `fn` with `table` supplied under `TABLE_KW`.

    The BASE check (what the locator resolves under the authoring-time self-check,
    `SPEC1080_AT_BASE`) takes no table and reads this same table from its own module under
    `defender/scripts/`, so the table is not passed to a definition there; every definition
    elsewhere gets it, with or without the switch."""
    if fn.__module__.startswith("defender.scripts."):
        return dict(kwargs)
    return {**kwargs, TABLE_KW: table}


def _empty_entry_table(table: Any, system: str) -> Any:
    """A table of the endpoint table's own type that names `system` with no entries."""
    return type(table)({system: ()})


def _load_adapter(path: Path) -> ModuleType:
    """An adapter loaded by path, the way the registry loads it."""
    from defender.runtime import verbs

    return verbs._load_adapter_module(path)


def _record_with_no_systems(root: Path) -> Any:
    """A real run record (#1107) for a planted tenant that configures no system: a request path
    that passes the confinement check then stops at the record's own `ConfigFault` for an
    unconfigured system, before any process or socket is opened."""
    from defender.tests.tenant_1107_settings import _spec1107 as T

    T.plant(root, configs={})
    return T.resolve(root)


def _record_with(root: Path, configs: dict[str, str]) -> Any:
    from defender.tests.tenant_1107_settings import _spec1107 as T

    T.plant(root, configs=configs)
    return T.resolve(root)


def _verb_context(record: Any, run_dir: Path, capture: Any = None) -> Any:
    from defender.runtime.verbs import VerbContext

    return VerbContext(defender_dir=S.DEFENDER, run_dir=run_dir, env={}, tenant=record,
                       capture=capture)


def _import(relpath: str, line: int, dotted: str) -> ModuleType:
    try:
        return importlib.import_module(dotted)
    except ModuleNotFoundError as e:
        raise AssertionError(
            f"{relpath}:{line} imports {dotted}, which no longer exists — a site left on the old "
            f"path ({e})") from e


def _holder(relpath: str, line: int, base: str, attr: str) -> Any:
    """What `from <base> import <attr>` binds: a submodule, or an attribute of `base`."""
    if importlib.util.find_spec(base) is not None:
        mod = _import(relpath, line, base)
        if hasattr(mod, attr):
            return getattr(mod, attr)
    return _import(relpath, line, f"{base}.{attr}")


def _from_import(relpath: str, node: ast.ImportFrom, pkg: list[str], name: str,
                 read_as_attr: set[str]) -> list[tuple[str, Any]]:
    base = node.module or ""
    if node.level:
        parent = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
        base = ".".join([*parent, node.module] if node.module else parent)
    out: list[tuple[str, Any]] = []
    for a in node.names:
        if a.name == name:
            mod = _import(relpath, node.lineno, base)
            assert hasattr(mod, name), (
                f"{relpath}:{node.lineno} imports {name} from {base}, which has no such name")
            out.append((base, getattr(mod, name)))
        elif (a.asname or a.name) in read_as_attr:
            held = _holder(relpath, node.lineno, base, a.name)
            if isinstance(held, ModuleType) and hasattr(held, name):
                out.append((held.__name__, getattr(held, name)))
    return out


def _bindings(relpath: str, name: str) -> list[tuple[str, Any]]:
    """Every object `relpath` binds to `name` through an import — at module level or inside a
    function body — as (the module it is taken from, the object), each import resolved by
    really importing the module it names. Covers `from M import name`, and a module imported
    (under any alias) whose attribute `name` the file reads (`case_ticket.CaseTicketError`)."""
    src = (S.REPO_ROOT / relpath).read_text(encoding="utf-8")
    tree = ast.parse(src, filename=relpath)
    pkg = S.dotted(relpath).split(".")
    if not relpath.endswith("__init__.py"):
        pkg = pkg[:-1]
    read_as_attr = {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                    and n.attr == name and isinstance(n.value, ast.Name)}
    out: list[tuple[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            out += _from_import(relpath, node, pkg, name, read_as_attr)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.asname and a.asname in read_as_attr:
                    held = _import(relpath, node.lineno, a.name)
                    if hasattr(held, name):
                        out.append((a.name, getattr(held, name)))
    return out


def _assert_bound_to(relpath: str, name: str, obj: Any) -> None:
    """Every binding `relpath` holds for `name` IS `obj`, taken from a module outside
    `defender/scripts/` (a binding left on the old path, or a copy, fails)."""
    found = _bindings(relpath, name)
    assert found, f"{relpath} binds no `{name}` through any import"
    for source, got in found:
        assert got is obj, (
            f"{relpath} binds `{name}` from {source} to a different object than its one "
            f"definition ({S.home_of(name)}) — two class objects, so a raise on one side is "
            "missed by the catch on the other")
        if not S.AT_BASE:
            assert not source.startswith("defender.scripts."), (
                f"{relpath} still takes `{name}` from {source}, the old path")


def _assert_imported_from_home(relpath: str, name: str) -> None:
    """`relpath` takes `name` from the module that defines it (or that module's package)."""
    home = S.dotted(S.home_of(name))
    found = _bindings(relpath, name)
    assert found, f"{relpath} binds no `{name}` through any import"
    for source, _ in found:
        assert source in (home, home.rsplit(".", 1)[0]), (
            f"{relpath} takes `{name}` from {source}, not from its home {home}")


def _section_world_labels() -> tuple[list[Any], list[Exception]]:
    g = _grammar()
    rows: list[Any] = []
    raised: list[Exception] = []

    def row(label: str, fn: Callable[..., Any], *args: Any) -> Any:
        value, exc = _run(fn, *args)
        if exc is not None:
            raised.append(exc)
        rows.append({"in": [label, *map(S.canon, args)], "out": _record(value, exc)})
        return value

    for w in WORLD_LABELS:
        row("refuse_unnameable_world", g.refuse_unnameable_world, w)
        row("world_view", g.world_view, "logs-*", w)
        row("is_world_view", g.is_world_view, f"wv-{w}-logs-nginx", ("logs-*",), w)
    for p in BASE_PATTERNS:
        view = row("world_view", g.world_view, p, "a")
        if isinstance(view, str):
            row("is_world_view", g.is_world_view, view, (p,), "a")
        row("_view_stem", g._view_stem, p)
    return rows, raised


def _section_index_exprs() -> tuple[list[Any], list[Exception]]:
    g = _grammar()
    rows: list[Any] = []
    raised: list[Exception] = []
    for index in INDEX_EXPRS:
        for world in INDEX_WORLDS:
            value, exc = _run(g.confine_index, index, CONFIGURED, world_id=world)
            raised += [exc] if exc is not None else []
            rows.append({"in": ["confine_index", S.canon(index), S.canon(world)],
                         "out": _record(value, exc)})
        rows.append({"in": ["is_world_view", S.canon(index), "a"],
                     "out": _record(*_run(g.is_world_view, index, CONFIGURED, "a"))})
        for pattern in CONFIGURED:
            rows.append({"in": ["_reach_ok", S.canon(index), pattern],
                         "out": _record(*_run(g._reach_ok, index, pattern))})
    return rows, raised


def _section_esql() -> list[Any]:
    g = _grammar()
    rows: list[Any] = []
    for text in (*ESQL_TEXTS, MEGABYTE_ESQL):
        shown = _compact(S.canon(text))
        for fn in (g.split_first_command, g.split_commands, g.opens_with_from):
            rows.append({"in": [fn.__name__, shown], "out": _record(*_run(fn, text))})
    return rows


def _section_payloads(esql_payload: Callable[..., Any]) -> list[Any]:
    return [{"in": label, "out": _record(*_run(esql_payload, query, resp))}
            for label, query, resp in PAYLOAD_ROWS]


def _section_endpoints(cases: Iterable[tuple[Any, Any, Any, Any]],
                       ) -> tuple[list[Any], list[Exception], list[Any]]:
    """Each (system, url, method, table) through `normalize_endpoint`, `confine_read_endpoint`
    and `guard_outbound` (with a recording capture), the table supplied."""
    h = _http()
    rows: list[Any] = []
    raised: list[Exception] = []
    captured_objects: list[Any] = []
    for system, url, method, table in cases:
        capture = h.TransportCapture()
        ctx = SimpleNamespace(capture=capture)
        confined = _run(h.confine_read_endpoint, system, url,
                        **_tabled(h.confine_read_endpoint, {"method": method, "verb_class": "r"},
                                  table))
        guarded = _run(h.guard_outbound, ctx, system, url,
                       **_tabled(h.guard_outbound, {"method": method}, table))
        raised += [e for _, e in (confined, guarded) if e is not None]
        captured_objects += list(capture.requests)
        rows.append({
            "in": [S.canon(system), _compact(S.canon(url)), S.canon(method)],
            "normalize_endpoint": _record(*_run(h.normalize_endpoint, url)),
            "confine_read_endpoint": _record(*confined),
            "guard_outbound": _record(*guarded),
            "captured": _compact([[r.system, S.canon(r.url), r.method]
                                  for r in capture.requests]),
        })
    return rows, raised, captured_objects


def _with_base_table(cases: Iterable[tuple[Any, Any, Any]]) -> list[tuple[Any, Any, Any, Any]]:
    table = _endpoint_table()
    return [(s, u, m, table) for s, u, m in cases]


def _system_cases() -> list[tuple[Any, Any, Any, Any]]:
    table = _endpoint_table()
    cases = [(s, u, m, table) for s in SYSTEMS for u, m in SYSTEM_ENDPOINTS]
    cases += [(s, u, m, _empty_entry_table(table, s))
              for s in EMPTY_ENTRY_SYSTEMS for u, m in SYSTEM_ENDPOINTS]
    return cases


def _verdict(lane: Callable[[Any], Any], record: Any, run_dir: Path, cf: type) -> dict[str, Any]:
    """One request through an adapter-side request path, with a recording capture: refused
    (the moved `ConfinementFault`, nothing captured) or admitted (the captured request)."""
    capture = _http().TransportCapture()
    _, exc = _run(lane, _verb_context(record, run_dir, capture))
    captured = [[r.system, r.url, r.method] for r in capture.requests]
    if captured:
        return {"verdict": "admitted", "captured": captured}
    if isinstance(exc, cf):
        return {"verdict": "refused", "fault": type(exc), "message": str(exc)}
    return {"verdict": "neither", "raised": repr(exc)}


def _drive_lanes(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], type]:
    """Each parity case through the Elastic adapter's request path (`_http_json`, loaded by
    path) and the stub transport's (`_request`), both with the real record of a tenant that
    configures no system and a recording capture."""
    cf = _integ("ConfinementFault")
    record = _record_with_no_systems(root / "data")
    elastic = _load_adapter(ELASTIC_ADAPTER)
    transport = S.module_at(STUB_TRANSPORT)
    stub_config = {"BASTION_HOST": "bastion-1080", "TIMEOUT_SEC": "1"}
    on_elastic, on_stub = [], []
    for url, method in PARITY_CASES:
        on_elastic.append(_verdict(
            lambda ctx, u=url, m=method: elastic._http_json(ctx, m, u, {}),
            record, root / "run", cf))
        on_stub.append(_verdict(
            lambda ctx, u=url, m=method: transport._request(
                ctx, stub_config, u, system="elastic", method=m),
            record, root / "run", cf))
    return on_elastic, on_stub, cf


def _parity_rows(verdicts: list[dict[str, Any]]) -> list[Any]:
    return [{"in": [u, m], **{k: v for k, v in d.items() if k != "fault"},
             **({"fault": d["fault"].__name__} if "fault" in d else {})}
            for (u, m), d in zip(PARITY_CASES, verdicts, strict=True)]


def _section_capture_seam(root: Path) -> list[Any]:
    """The capture seam fed a megabyte, binary, empty, many-header or newline-bearing request:
    straight into `TransportCapture.record`, and through the Elastic adapter's request path."""
    h = _http()
    rows: list[Any] = []
    big = "http://es:9200/_query?q=" + "a" * 1_048_576
    direct = (
        ("ordinary", {"system": "elastic", "url": "http://es:9200/_query", "method": "POST"}),
        ("megabyte url", {"system": "elastic", "url": big, "method": "POST"}),
        ("binary url", {"system": "elastic", "url": "http://es:9200/\x00\x01\x7f\x80\xff\ufffd",
                        "method": "GET"}),
        ("empty", {"system": "", "url": "", "method": ""}),
        ("newline in url and method", {"system": "elastic",
                                       "url": "http://es:9200/x\r\nHost: evil.example",
                                       "method": "GET\r\nX-Injected: 1"}),
        ("bytes url", {"system": "elastic", "url": b"http://es:9200/x", "method": "GET"}),
        ("None method", {"system": "elastic", "url": "http://es:9200/x", "method": None}),
    )
    capture = h.TransportCapture()
    for label, kwargs in direct:
        rows.append({"in": ["record", label], "out": _record(*_run(capture.record, **kwargs))})
    rows.append({"in": ["record", "positional"],
                 "out": _record(*_run(capture.record, "elastic", "http://es:9200/x", "GET"))})
    rows.append({"in": ["requests after"],
                 "out": _compact([[type(r).__name__, r.system, S.canon(r.url), r.method]
                                  for r in capture.requests])})
    many = h.TransportCapture()
    for i in range(1000):
        many.record(system="elastic", url=f"http://es:9200/{i}", method="GET")
    rows.append({"in": ["1000 records"],
                 "out": _compact([[r.system, r.url, r.method] for r in many.requests])})
    one = h.CapturedRequest(system="elastic", url="http://es:9200/x", method="GET")
    two = h.CapturedRequest(system="elastic", url="http://es:9200/x", method="GET")
    rows.append({"in": ["CapturedRequest equal and hash"],
                 "out": _record(*_run(lambda: (one == two, hash(one) == hash(two))))})
    rows.append({"in": ["CapturedRequest assign"],
                 "out": _record(*_run(setattr, one, "url", "http://evil.example/"))})

    record = _record_with_no_systems(root / "data")
    elastic = _load_adapter(ELASTIC_ADAPTER)
    lane = (
        ("many headers", "POST", "http://es:9200/_query",
         {"headers": {f"X-H{i}": f"v{i}" for i in range(500)}}),
        ("newline in a header value", "GET", "http://es:9200/_cluster/health",
         {"headers": {"X-Note": "a\r\nInjected: 1"}}),
        ("megabyte url", "POST", big, {}),
        ("megabyte body", "POST", "http://es:9200/_query",
         {"body": elastic.OutboundBody({"query": "FROM x | " + "a" * 1_048_576})}),
        ("empty body", "POST", "http://es:9200/_query", {"body": elastic.OutboundBody({})}),
    )
    for label, method, url, extra in lane:
        seam = h.TransportCapture()
        _, exc = _run(elastic._http_json, _verb_context(record, root / "run", seam), method, url,
                      {}, **extra)
        rows.append({"in": ["elastic request path", label],
                     "raises": type(exc).__name__ if exc is not None else None,
                     "captured": _compact([[type(r).__name__, r.system, r.url, r.method]
                                           for r in seam.requests])})
    return rows


def _section_no_table_positive() -> list[Any]:
    rows, _, _ = _section_endpoints(_with_base_table(NO_TABLE_CASES))
    return rows


def _section_grammar() -> list[Any]:
    g = _grammar()
    rows: list[Any] = [{"in": ["VIEW_NAMESPACE"], "out": S.canon(g.VIEW_NAMESPACE)},
                       {"in": ["ViewNameError bases"],
                        "out": [b.__name__ for b in g.ViewNameError.__mro__]}]
    for p, w in (("logs-*", "a"), ("logs-system.auth-*", "e1a2.b"), ("*", "a"), ("wv-*", "a"),
                 ("logs-*", "a-b"), ("LOGS-*", "a"), ("logs-*-2026", "a")):
        rows.append({"in": ["world_view", p, w], "out": _record(*_run(g.world_view, p, w))})
    for w in ("a", "A", "a-b", "", "e1a2.b"):
        rows.append({"in": ["refuse_unnameable_world", w],
                     "out": _record(*_run(g.refuse_unnameable_world, w))})
    for index in ("wv-a-logs-", "wv-a-logs-nginx", "wv-b-logs-", "wv-a-other", "logs-nginx"):
        rows.append({"in": ["is_world_view", index],
                     "out": _record(*_run(g.is_world_view, index, CONFIGURED, "a"))})
    for index, pattern in (("logs-nginx", "logs-*"), ("logs*", "logs-*"), ("logs-a*", "logs-*"),
                           ("logs-*", "logs-*"), ("logs", "logs-*"), ("logs-x", "logs-x")):
        rows.append({"in": ["_reach_ok", index, pattern],
                     "out": _record(*_run(g._reach_ok, index, pattern))})
    for p in ("logs-*", "logs-", "logs", "*", "logs-**"):
        rows.append({"in": ["_view_stem", p], "out": _record(*_run(g._view_stem, p))})
    for index, world in (("logs-nginx", None), ("wv-a-logs-", "a"), ("wv-a-logs-", None),
                         ("logs-*,x", None), ("*", None), ("-logs", None), ("other", "a")):
        rows.append({"in": ["confine_index", index, world],
                     "out": _record(*_run(g.confine_index, index, CONFIGURED, world_id=world))})
    for q in ('FROM "a|b" | LIMIT 1', "ROW a = 1", "  from x | y", "", "SHOW INFO | x"):
        for fn in (g.split_first_command, g.split_commands, g.opens_with_from):
            rows.append({"in": [fn.__name__, q], "out": _record(*_run(fn, q))})
    return rows


def _section_oracle(controls: ModuleType) -> list[Any]:
    return [
        {"in": ["esql_payload", "fixture control"],
         "out": _record(*_run(controls.esql_payload, FIXTURE_QUERY, FIXTURE_RESP))},
        {"in": ["add_esql_window", UNBOUNDED_QUERY],
         "out": _record(*_run(controls.add_esql_window, UNBOUNDED_QUERY, *WINDOW))},
        {"in": ["measure_controls dry run", UNBOUNDED_QUERY],
         "out": _record(*_run(controls.measure_controls, UNBOUNDED_QUERY,
                              operation_window=WINDOW, dry_run=True))},
    ]


def _section_mints() -> list[Any]:
    """Each base-minted world view met by the later lanes: the grammar, staging's pre-flight
    check and derivation, the index check and the redaction filter."""
    from defender.learning.branch import redaction, staging

    g = _grammar()
    rows: list[Any] = []
    for pattern, episode_token, label in MINTS:
        token = f"{episode_token}.{label}"
        minted, _ = _run(g.world_view, pattern, token)
        rows.append({
            "in": [pattern, episode_token, label],
            "world_view": S.canon(minted),
            "is_world_view": _record(*_run(g.is_world_view, minted, (pattern,), token)),
            "confine_index": _record(*_run(g.confine_index, minted, (pattern,), world_id=token)),
            "stage_name": _record(*_run(staging.stage_name, minted, episode_token=episode_token,
                                        world_id=label, configured_patterns=(pattern,),
                                        door=None)),
            "_derived_names": _record(*_run(staging._derived_names, pattern, token)),
            "redact_model_visible": _record(*_run(redaction.redact_model_visible,
                                                  f"index {minted} refused")),
            "sweep_glob": _record(*_run(staging.sweep_glob, episode_token)),
        })
    return rows


def _section_fault_codes() -> list[Any]:
    f = _faults()
    return [{"in": [n, "exit_code"], "out": S.canon(getattr(f, n).exit_code)} for n in FAULT_NAMES] \
        + [{"in": ["USAGE_EXIT_CODE"], "out": S.canon(f.USAGE_EXIT_CODE)},
           {"in": ["bases"], "out": {n: [b.__name__ for b in getattr(f, n).__mro__]
                                     for n in FAULT_NAMES}}]


# PARKED 2026-10-04 (scope cut): owner #1172; demand s_elastic_grammar_unchanged
def test_1080_world_view_naming_and_esql_grammar_answer_as_before_from_their_new_home():
    """Each of these, imported from its new home, answers a fixed input table exactly as the
    base functions did: `world_view`, `is_world_view`, `refuse_unnameable_world` (including its
    `ViewNameError`), `VIEW_NAMESPACE`, `_reach_ok`, `_view_stem`, `confine_index`,
    `split_first_command`, `split_commands` and `opens_with_from`. `staging`, `stagers/elastic`,
    `estate/registry`, `redaction` and `runtime/branch/_family` import them from there.

    Observed: every name found by symbol outside `defender/scripts/` (one definition each), a
    fixed table through each against the base golden, a refusal's class IS the located
    `ViewNameError`, and each importer's import of each name resolves to the name's home."""
    g = _grammar()
    _assert_rows("grammar", _section_grammar())

    _, exc = _run(g.refuse_unnameable_world, "A")
    assert type(exc) is g.ViewNameError, f"the refusal is {exc!r}, not the moved ViewNameError"

    importers = {
        "defender/learning/branch/staging.py":
            ("VIEW_NAMESPACE", "_reach_ok", "_view_stem", "is_world_view", "world_view"),
        "defender/learning/branch/estate/stagers/elastic.py":
            ("ViewNameError", "refuse_unnameable_world", "world_view", "split_first_command"),
        "defender/learning/branch/estate/registry.py": ("VIEW_NAMESPACE", "is_world_view"),
        "defender/learning/branch/redaction.py": ("VIEW_NAMESPACE",),
        "defender/runtime/branch/_family.py": ("ViewNameError", "refuse_unnameable_world"),
    }
    for relpath, names in importers.items():
        for name in names:
            _assert_imported_from_home(relpath, name)
            if name != "VIEW_NAMESPACE":
                _assert_bound_to(relpath, name, getattr(g, name))


# PARKED 2026-10-04 (scope cut): owner #1172; demand s_eval_oracle_payload
def test_1080_the_eval_oracle_builds_todays_esql_payload_from_the_elastic_module():
    """`evals/oracle_golden/controls.py` takes `esql_payload` and `esql_text` from the Elastic
    module, not from an adapter. The payload it builds for a fixture control is identical to
    the base `elastic_adapter.esql_payload` output.

    Observed: the oracle's `esql_payload`, `split_commands` and `split_first_command` are each
    taken from that name's one home (outside `defender/scripts/`, so not an adapter); its payload
    for the fixture control, and the control query it places with the ES|QL text functions,
    equal the base golden."""
    from defender.evals.oracle_golden import controls

    relpath = "defender/evals/oracle_golden/controls.py"
    for name in ("esql_payload", "split_commands", "split_first_command"):
        home = S.home_of(name)
        if not S.AT_BASE:
            assert not S.under(home, ADAPTERS), f"`{name}` still lives in an adapter file: {home}"
        _assert_imported_from_home(relpath, name)
        _assert_bound_to(relpath, name, S.moved(name))
    _assert_rows("oracle", _section_oracle(controls))


# PARKED 2026-10-04 (scope cut): owner #1172; demand s_http_confinement_unchanged
def test_1080_the_generic_http_check_refuses_and_admits_as_before_from_integrations():
    """`normalize_endpoint`, `confine_read_endpoint` and `guard_outbound`, imported from
    integrations, admit and refuse a fixed table of (system, url, method) cases exactly as at
    the base, raising the moved `ConfinementFault`. `TransportCapture` records a
    `CapturedRequest` as before.

    Observed: the six names found under `defender/integrations/`; the table (with the
    adapter-private endpoint table supplied) against the base golden; every refusal's class IS
    the moved `ConfinementFault`, every captured record a moved `CapturedRequest`; the estate
    registry binds that `ConfinementFault`; and the Elastic adapter, loaded by path, refuses an
    off-table request with it too."""
    h = _http()
    rows, raised, captured = _section_endpoints(_with_base_table(HTTP_CASES))
    _assert_rows("http", rows)
    assert raised
    assert all(type(e) is h.ConfinementFault for e in raised), (
        f"a refusal raised another class: {sorted({type(e).__module__ for e in raised})}")
    assert captured
    assert all(type(r) is h.CapturedRequest for r in captured)

    no_capture = SimpleNamespace()
    value, exc = _run(h.guard_outbound, no_capture, "elastic", "http://es:9200/_query",
                      **_tabled(h.guard_outbound, {"method": "POST"}, _endpoint_table()))
    assert exc is None, f"a context with no capture is not admitted: {exc!r}"
    assert value is None

    _assert_bound_to("defender/learning/branch/estate/registry.py", "ConfinementFault",
                     h.ConfinementFault)
    elastic = _load_adapter(ELASTIC_ADAPTER)
    _, exc = _run(elastic._http_json, SimpleNamespace(capture=None), "DELETE",
                  "http://es:9200/logs-*", {})
    assert type(exc) is h.ConfinementFault, f"the Elastic adapter refused with {exc!r}"


# PARKED 2026-10-04 (scope cut): owner #1172; demand s_fault_identity_across_homes
def test_1080_a_fault_an_adapter_raises_is_the_class_the_platform_catches(tmp_path):
    """A fault raised by an adapter loaded by path is an instance of the class the platform
    catches. That covers `query_tool`'s and `lead_zero/_capture`'s `AdapterFault`, `run_tenant`'s
    and `tenant_settings`' `ConfigFault`, and `staging`'s `TransportFault`. There is one `faults`
    module object, never a duplicate, so the exception class is the same object.
    `USAGE_EXIT_CODE` keeps its value, 64.

    Observed: the Elastic adapter is loaded by the registry's own loader and made to raise an
    `UpstreamFault`, a `TransportFault` and a `ConfigFault` (a planted Elastic config missing its
    required keys); each is caught by the class every named catch site binds (module-level or
    function-local imports, resolved); and a fresh child that loads the adapter by path and
    imports every catch site holds ONE class object per fault name, defined in ONE module —
    loading all eight adapters, so an adapter still importing a stale copy is a second object."""
    f = _faults()
    elastic = _load_adapter(ELASTIC_ADAPTER)
    record = _record_with(tmp_path / "data", {"elastic": (
        "ELASTIC_TRANSPORT=docker-exec\nELASTIC_DOCKER_CONTEXT=no-such-context-1080\n")})
    ctx = _verb_context(record, tmp_path / "run")
    upstream = _run(elastic.resolve_sort, "sideways")[1]
    transport = _run(elastic._raise_on_es_error, 503, {"error": {"reason": "down"}}, "probe")[1]
    config = _run(elastic.load_config, ctx)[1]
    assert type(upstream) is f.UpstreamFault, repr(upstream)
    assert type(transport) is f.TransportFault, repr(transport)
    assert type(config) is f.ConfigFault, repr(config)

    sites = (
        ("defender/runtime/query_tool.py", "AdapterFault", (upstream, transport, config)),
        ("defender/runtime/lead_zero/_capture.py", "AdapterFault", (upstream, transport, config)),
        ("defender/runtime/run_tenant.py", "ConfigFault", (config,)),
        ("defender/runtime/tenant_settings.py", "ConfigFault", (config,)),
        ("defender/learning/branch/staging.py", "TransportFault", (transport,)),
    )
    for relpath, name, faults in sites:
        _assert_bound_to(relpath, name, getattr(f, name))
        for source, cls in _bindings(relpath, name):
            for fault in faults:
                try:
                    raise fault
                except cls:
                    pass
                except Exception as e:  # noqa: BLE001 — the miss is the finding
                    raise AssertionError(f"{relpath}'s `{name}` (from {source}) missed {e!r}") from e

    assert f.USAGE_EXIT_CODE == 64
    for relpath in ("defender/runtime/query_tool.py", "defender/runtime/tools/_bash.py",
                    "defender/runtime/tools/__init__.py",
                    "defender/learning/branch/estate/registry.py"):
        for source, value in _bindings(relpath, "USAGE_EXIT_CODE"):
            assert value == 64, f"{relpath} reads USAGE_EXIT_CODE {value!r} from {source}"

    homes = {n: S.dotted(S.home_of(n, home=S.INTEGRATIONS)) for n in FAULT_NAMES}
    probe = (
        "import importlib, json, sys\n"
        "from pathlib import Path\n"
        "from defender.runtime import verbs\n"
        "args = json.loads(sys.argv[1])\n"
        "for adapter in args['adapters']:\n"
        "    verbs._load_adapter_module(Path(adapter))\n"
        "for m in args['sites']:\n"
        "    importlib.import_module(m)\n"
        "out = {}\n"
        "for name in args['names']:\n"
        "    objs = {}\n"
        "    for mod in list(sys.modules.values()):\n"
        "        v = getattr(mod, '__dict__', {}).get(name)\n"
        "        if isinstance(v, type) and v.__name__ == name:\n"
        "            objs[id(v)] = v.__module__\n"
        "    out[name] = sorted(set(objs.values())) + [len(objs)]\n"
        "print(json.dumps(out))\n"
    )
    adapters = sorted(str(p) for p in (S.REPO_ROOT / ADAPTERS).glob("*_adapter.py"))
    assert len(adapters) == 8, f"the adapter roster under {ADAPTERS} is {adapters}"
    args = {"adapters": adapters, "names": list(FAULT_NAMES),
            "sites": ["defender.runtime.query_tool", "defender.runtime.lead_zero._capture",
                      "defender.runtime.run_tenant", "defender.runtime.tenant_settings",
                      "defender.learning.branch.staging"]}
    child = S.python("-c", probe, json.dumps(args))
    assert child.returncode == 0, child.stderr.decode(errors="replace")[-2000:]
    seen = json.loads(child.stdout.decode().strip().splitlines()[-1])
    for name in FAULT_NAMES:
        assert seen[name] == [homes[name], 1], (
            f"`{name}`: a process that loads the adapters by path and imports the platform's catch "
            f"sites holds {seen[name][-1]} class object(s) from {seen[name][:-1]} — one, from "
            f"{homes[name]}, is what a catch needs")


# PARKED 2026-10-04 (scope cut): owner #1172; demand m1_faults_codes_from_exit_codes
def test_1080_the_fault_types_take_their_codes_from_the_flat_tier():
    """The integrations `faults` module imports its exit codes from `defender/_exit_codes.py`,
    and each fault class's `exit_code` and `USAGE_EXIT_CODE` keep their base values.

    Observed: the module defining the fault classes under `defender/integrations/` has a
    module-level import from `defender._exit_codes` and binds `USAGE_EXIT_CODE` through an
    import, not a literal of its own; each class's `exit_code`, `USAGE_EXIT_CODE` and the class
    hierarchy equal the base golden."""
    _assert_rows("fault_codes", _section_fault_codes())
    relpath = S.home_of("AdapterFault", home=S.INTEGRATIONS)
    S.module_at(S.EXIT_CODES)
    source = (S.REPO_ROOT / relpath).read_text(encoding="utf-8")
    imports = [st for st in S.import_statements(relpath, source)
               if st.module == "defender._exit_codes"
               or (st.module == "defender" and "_exit_codes" in st.names)]
    assert any(st.top_level for st in imports), (
        f"{relpath} imports nothing from defender/_exit_codes.py at module level")
    assert "USAGE_EXIT_CODE" not in S.module_level_names(source, relpath), (
        f"{relpath} still defines USAGE_EXIT_CODE itself instead of importing it")


# PARKED 2026-10-04 (scope cut): owner #1172; demand s024
def test_fault_raised_by_adapter_private_confinement_is_caught_by_learning_and_the_query_tool(
    tmp_path,
):
    """A refused host-state call still raises a fault that is an AdapterFault subclass and the
    same class object the query tool's adapter-fault handler and learning's estate registry
    catch: both handlers still catch it after the generic check and fault types moved. Where
    host-state confinement lives (RX2) does not change that; the fault identity does not split
    across homes.

    Observed: the host-state adapter, loaded by path the registry's way, refuses a verb aimed
    at a host outside its inventory, and the host-state check (found by symbol under the
    adapters folder, where it stays) refuses a program outside its list; each raise IS the moved
    `ConfinementFault`, a subclass of the moved `AdapterFault`, and is caught by the query tool's
    `AdapterFault` and the estate registry's `ConfinementFault`."""
    f = _faults()
    cf = _integ("ConfinementFault")
    assert issubclass(cf, f.AdapterFault)
    host = _load_adapter(HOST_STATE_ADAPTER)
    ctx = _verb_context(_record_with_no_systems(tmp_path / "data"), tmp_path / "run")
    refusals = [_run(host.VERBS["proc-tree"], ctx, host="elasticsearch")[1]]
    homes = [d for d in S.definitions("confine_host_state_call") if S.under(d, ADAPTERS)]
    assert len(homes) == 1, (
        f"host-state confinement stays with the adapters (M-B host-state (a)): "
        f"{list(S.definitions('confine_host_state_call'))}")
    check = S.module_at(homes[0]).confine_host_state_call
    refusals.append(_run(check, "rm", "web-1")[1])
    for exc in refusals:
        assert type(exc) is cf, f"the host-state refusal is {exc!r}, not the moved ConfinementFault"

    from defender.learning.branch.estate import registry
    from defender.runtime import query_tool

    _assert_bound_to("defender/runtime/query_tool.py", "AdapterFault", f.AdapterFault)
    _assert_bound_to("defender/learning/branch/estate/registry.py", "ConfinementFault", cf)
    for exc in refusals:
        for handler in (query_tool.AdapterFault, registry.ConfinementFault):
            try:
                raise exc
            except handler:
                pass


# PARKED 2026-10-04 (scope cut): owner #1172; demand s080
def test_a_runtime_module_loaded_at_start_reaches_the_elastic_module_which_reaches_back_into_runtime():
    """A cold start of the query tool (runtime), the learning staging module and the Elastic
    module succeeds in every first-import order, with no ImportError or partially initialised
    module: the world-view naming's new home and its runtime/settings imports form no cycle.

    Observed: six fresh children, one per order of the three modules, each importing them in
    that order; none raises, and every module-level definition of each (and of `redaction` and
    `runtime/branch/_family`, which sit between them) is present afterwards."""
    elastic = S.dotted(S.home_of("world_view"))
    trio = ("defender.runtime.query_tool", "defender.learning.branch.staging", elastic)
    also = ["defender.learning.branch.redaction", "defender.runtime.branch._family"]
    probe = (
        "import ast, importlib, json, sys\n"
        "order, also = json.loads(sys.argv[1]), json.loads(sys.argv[2])\n"
        "errors, missing = [], {}\n"
        "for m in order:\n"
        "    try:\n"
        "        importlib.import_module(m)\n"
        "    except Exception as e:\n"
        "        errors.append([m, type(e).__name__, str(e)])\n"
        "for m in order + also:\n"
        "    mod = sys.modules.get(m)\n"
        "    if mod is None:\n"
        "        missing[m] = ['<not imported>']\n"
        "        continue\n"
        "    body = ast.parse(open(mod.__file__, 'rb').read()).body\n"
        "    names = [n.name for n in body if isinstance(n, (ast.FunctionDef,\n"
        "             ast.AsyncFunctionDef, ast.ClassDef))]\n"
        "    names += [t.id for n in body if isinstance(n, ast.Assign) for t in n.targets\n"
        "              if isinstance(t, ast.Name)]\n"
        "    gone = [n for n in names if n not in vars(mod)]\n"
        "    if gone:\n"
        "        missing[m] = gone\n"
        "print(json.dumps({'errors': errors, 'missing': missing}))\n"
    )
    for order in itertools.permutations(trio):
        child = S.python("-c", probe, json.dumps(list(order)), json.dumps(also))
        assert child.returncode == 0, child.stderr.decode(errors="replace")[-2000:]
        seen = json.loads(child.stdout.decode().strip().splitlines()[-1])
        assert seen == {"errors": [], "missing": {}}, f"cold start in order {order}: {seen}"


# PARKED 2026-10-04 (scope cut): owner #1172; demand s081
def test_fault_vocabulary_is_importable_under_two_dotted_names_at_once():
    """The fault classes are one set of class objects at their new home; no leftover file,
    re-export or stale copy at the old dotted name exists, so an adapter loaded by path that
    raises a fault is caught by the platform as that same class, and an isinstance/except
    check is true. (s_fault_identity_across_homes.)

    Observed: the old dotted name `defender.scripts.adapters.faults` resolves to nothing (no
    file, no package, no re-export) and each fault class has one definition, under
    `defender/integrations/`; positive control: an adapter loaded by path raises a fault the
    moved classes catch."""
    f = _faults()
    assert importlib.util.find_spec("defender.scripts.adapters.faults") is None, (
        "the old dotted name defender.scripts.adapters.faults still imports — a second module "
        "object, so a second set of fault classes")
    for name in FAULT_NAMES:
        defs = S.definitions(name)
        assert defs == (S.home_of(name, home=S.INTEGRATIONS),), (
            f"`{name}` is defined at {list(defs)} — one definition, at its new home")
    defs = S.definitions("USAGE_EXIT_CODE")
    assert len(defs) == 1, f"USAGE_EXIT_CODE is defined at {list(defs)} — one definition"
    assert S.AT_BASE or not S.under(defs[0], "defender/scripts"), (
        f"USAGE_EXIT_CODE is still defined at {defs[0]}, under scripts/")
    elastic = _load_adapter(ELASTIC_ADAPTER)
    exc = _run(elastic.resolve_sort, "sideways")[1]
    assert isinstance(exc, f.AdapterFault), repr(exc)
    assert type(exc) is f.UpstreamFault, repr(exc)


# PARKED 2026-10-04 (scope cut): owner #1172; demand s098
def test_learning_edits_the_same_branch_files_while_world_view_naming_moves():
    """The world-view naming moves as a pure move: names, outputs and behavior are identical
    to before the move, whichever neighboring change lands first (#1112 items 3 and 7: 'move
    them, don't change them'). A tree with either merged yields the same world-view strings for
    the same inputs.

    Observed (the half a single tree can show): the world-view strings minted for a fixed
    table, the namespace, and the sweep glob the staging lane builds from it equal the base
    golden, and the branch files that read the naming (`staging`, `_family`, `redaction`) take
    it from its new home."""
    g = _grammar()
    namespace = S.golden(GOLDEN)["grammar"][0]["out"]
    assert namespace == g.VIEW_NAMESPACE
    views = [{"in": [p, w], "out": _record(*_run(g.world_view, p, w))}
             for p in BASE_PATTERNS for w in ("a", "e1a2.b")]
    _assert_rows("views", views)
    _assert_rows("mints", _section_mints())
    _assert_imported_from_home("defender/learning/branch/staging.py", "world_view")
    _assert_imported_from_home("defender/learning/branch/redaction.py", "VIEW_NAMESPACE")
    _assert_imported_from_home("defender/runtime/branch/_family.py", "refuse_unnameable_world")


# PARKED 2026-10-04 (scope cut): owner #1172; demand s191
def test_world_label_forms():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). World labels (empty, whitespace, upper case,
    look-alikes, over- long, already namespaced, wildcard, comma list, date-math, leading
    hyphen/underscore/plus, `cluster:index`, `.`/`..`, trailing slash) are named or refused by
    the same grammar. #1112 items 3 and 7: move it, don't change it.

    Observed: every label through `refuse_unnameable_world`, `world_view` and `is_world_view`
    (and every corpus pattern through `world_view` and `_view_stem`) against the base golden;
    each refusal IS the moved `ViewNameError`."""
    rows, raised = _section_world_labels()
    _assert_rows("world_labels", rows)
    view_error = S.moved("ViewNameError")
    named = [e for e in raised if type(e).__name__ == "ViewNameError"]
    assert named
    assert all(type(e) is view_error for e in named)


# PARKED 2026-10-04 (scope cut): owner #1172; demand s192
def test_index_expressions_given_to_the_view_and_index_checks():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). Index expressions with the view namespace as a
    substring or other case, `_all`, a spanning wildcard, a comma list of valid and invalid, an
    alias or a URL-encoded form are confined or refused as today.

    Observed: every expression through `confine_index` (no world, and two worlds),
    `is_world_view` and `_reach_ok` against the base golden; each refusal IS the moved
    `ConfinementFault`."""
    rows, raised = _section_index_exprs()
    _assert_rows("index_exprs", rows)
    cf = _integ("ConfinementFault")
    refused = [e for e in raised if type(e).__name__ == "ConfinementFault"]
    assert refused
    assert all(type(e) is cf for e in refused)


# PARKED 2026-10-04 (scope cut): owner #1172; demand s193
def test_esql_text_forms():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). ES|QL text (empty, blank, BOM, leading newline,
    lower-case `from`, quoted pipe, comments, unterminated string, two commands, keyword-named
    column, megabyte) is handled as today.

    Observed: each text through `split_first_command`, `split_commands` and `opens_with_from`,
    from the Elastic module, against the base golden (the megabyte row by digest)."""
    _assert_rows("esql", _section_esql())


# PARKED 2026-10-04 (scope cut): owner #1172; demand s194
def test_oracle_control_rows_of_unexpected_shape():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). An oracle control missing a field, with an extra
    or wrong-typed field, an empty query or a name containing a separator is built or refused
    exactly as today by the payload builder wherever it lives.

    Observed: each row through `esql_payload`, found by symbol, and through the name the
    oracle's `controls` module binds, against the base golden."""
    from defender.evals.oracle_golden import controls

    _assert_rows("payloads", _section_payloads(S.moved("esql_payload")))
    _assert_rows("payloads", _section_payloads(controls.esql_payload))


# PARKED 2026-10-04 (scope cut): owner #1172; demand s195
def test_endpoint_spellings_that_try_to_slip_a_check():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). Endpoints with percent-encoded or double-encoded
    dot segments, a NUL, `//`, a query string, a fragment, an absolute or scheme-relative URL, a
    trailing slash, non-ASCII or a very long path are allowed or refused exactly as today by the
    same check; none newly slips through. (s_http_confinement_unchanged.)

    Observed: each spelling through the moved `normalize_endpoint`, `confine_read_endpoint` and
    `guard_outbound` (the adapter-private table supplied) against the base golden, including
    what the capture recorded; each refusal IS the moved `ConfinementFault`."""
    rows, raised, _ = _section_endpoints(_with_base_table(ENDPOINT_CASES))
    _assert_rows("endpoints", rows)
    cf = _integ("ConfinementFault")
    refused = [e for e in raised if type(e).__name__ == "ConfinementFault"]
    assert refused
    assert all(type(e) is cf for e in refused)


# PARKED 2026-10-04 (scope cut): owner #1172; demand s196
def test_method_spellings():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). A lower-case, padded, empty, unusual, None or
    look-alike method is judged as today.

    Observed: each method against a GET-only and a POST-only endpoint, through the moved
    check with the adapter-private table supplied, against the base golden."""
    cases = [(s, u, m) for m in METHODS for s, u in METHOD_ENDPOINTS]
    rows, raised, _ = _section_endpoints(_with_base_table(cases))
    _assert_rows("methods", rows)
    cf = _integ("ConfinementFault")
    assert all(type(e) is cf for e in raised if type(e).__name__ == "ConfinementFault")


# PARKED 2026-10-04 (scope cut): owner #1172; demand s197
def test_system_name_spellings_given_to_the_check():
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). A system name that is upper-case,
    hyphen-versus-underscore, padded, empty, unknown or known with no allowed endpoints is
    judged as today; a system with no entries has no reachable endpoint.

    Observed: each spelling against a stub and an Elastic endpoint through the moved check
    with the adapter-private table, then a table of the same type naming a system with no
    entries: that system reaches nothing, judged exactly as the base judged a system the table
    does not name (the base golden for those rows)."""
    rows, raised, _ = _section_endpoints(_system_cases())
    _assert_rows("systems", rows)
    empty = rows[-len(EMPTY_ENTRY_SYSTEMS) * len(SYSTEM_ENDPOINTS):]
    assert all("raises" in r["confine_read_endpoint"] and not r["captured"] for r in empty)


# PARKED 2026-10-04 (scope cut): owner #1172; demand s198
def test_outbound_capture_of_very_large_or_binary_requests(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap,
    cluster and rename; O5 where it applies). The capture seam records a megabyte, binary,
    empty or many-header request, or a header value with a newline, as today.

    Observed: `TransportCapture.record` and `CapturedRequest` from integrations fed each shape
    directly, and the Elastic adapter's request path (loaded by path, a real record) sending
    many headers, a newline-bearing header value, a megabyte URL and a megabyte body, each
    against the base golden. The seam has no header or body channel at the base, so what is
    pinned for those is the (system, url, method) it records."""
    _assert_rows("capture", _section_capture_seam(tmp_path))


# PARKED 2026-10-04 (scope cut): owner #1172; demand s213
def test_world_view_name_minted_by_an_earlier_branch_lane_met_by_a_later_one():
    """A world-view name minted by an earlier branch lane and left in a staged estate or an
    episode stamp is recognised by a later lane after the grammar moved, because the grammar
    is moved unchanged (#1112 items 3 and 7: move them, don't change them): the name is still a
    world view and the lane treats it identically.

    Observed: each name the base minted (golden strings) is re-minted identically, is a world
    view of its world, passes the index check under that world, passes staging's pre-flight
    check and derivation, and is scrubbed by the redaction filter, all as the base golden."""
    rows = _section_mints()
    _assert_rows("mints", rows)
    g = _grammar()
    for row in S.golden(GOLDEN)["mints"]:
        pattern, episode_token, label = row["in"]
        assert g.is_world_view(row["world_view"], (pattern,), f"{episode_token}.{label}") is True


# PARKED 2026-10-04 (scope cut): owner #1172; demand read_endpoint_table_gives_the_same_verdict_on_the_stub_transport_lane
def test_1080_the_stub_transport_lane_admits_and_refuses_the_endpoint_table_as_the_elastic_adapter_lane_does(  # noqa: E501
    tmp_path,
):
    """Over one fixed table of (system, url, method) cases, the stub transport's request path,
    which passes its own adapter-private endpoint table into the moved check (M-B table (a)),
    admits and refuses each case with the same verdict, and the same moved `ConfinementFault`,
    as the elastic adapter's request path does. A case that one caller admits and the other
    refuses is a failure.

    Observed: the shared table is (url, method) under the system `elastic` (the Elastic
    adapter's request path fixes its system). Each case runs through the stub transport's
    `_request` and the Elastic adapter's `_http_json` (loaded by path), each with a real record
    of a tenant that configures no system and a recording capture, so an admitted request is
    recorded and then stops at the record's own fault, before any process. Verdicts must match
    case by case, with the refusal class the moved `ConfinementFault` on both; the stub lane's
    verdicts also equal the base golden."""
    on_elastic, on_stub, cf = _drive_lanes(tmp_path)
    for (url, method), stub, el in zip(PARITY_CASES, on_stub, on_elastic, strict=True):
        assert stub == el, (
            f"{method} {url}: the stub transport's request path says {stub}, the Elastic "
            f"adapter's says {el}")
        if stub["verdict"] == "refused":
            assert stub["fault"] is cf
    _assert_rows("parity", _parity_rows(on_stub))


# PARKED 2026-10-04 (scope cut): owner #1172; demand read_endpoint_table_gives_the_same_verdict_on_the_elastic_adapter_lane
def test_1080_the_elastic_adapter_lane_admits_and_refuses_the_endpoint_table_as_the_stub_transport_lane_does(  # noqa: E501
    tmp_path,
):
    """Over one fixed table of (system, url, method) cases, the elastic adapter's request path,
    which passes the adapter-private endpoint table into the moved check (M-B table (a)),
    admits and refuses each case with the same verdict, and the same moved `ConfinementFault`,
    as the stub transport's request path does.

    Observed: as for the stub-transport lane, seen from the Elastic adapter's side: its
    verdicts match the stub transport's case by case, its refusals are the moved
    `ConfinementFault`, and its verdicts equal the base golden."""
    on_elastic, on_stub, cf = _drive_lanes(tmp_path)
    for (url, method), el, stub in zip(PARITY_CASES, on_elastic, on_stub, strict=True):
        assert el == stub, (
            f"{method} {url}: the Elastic adapter's request path says {el}, the stub "
            f"transport's says {stub}")
        if el["verdict"] == "refused":
            assert el["fault"] is cf
    _assert_rows("parity", _parity_rows(on_elastic))


# PARKED 2026-10-04 (scope cut): owner #1172; demand guard_outbound_called_without_a_table_raises_and_admits_nothing
def test_1080_a_call_that_supplies_no_endpoint_table_raises_and_admits_nothing():
    """`guard_outbound` and `confine_read_endpoint`, called with no endpoint table, raise and
    admit nothing: they do not fall back to an empty or a default table, and the unsafe state a
    caller that supplies none would otherwise construct is not constructible (M-B table (a)
    makes the table a caller-supplied argument). The same call with the table supplied admits
    and refuses as at the base (s195, s196, s197).

    Observed: for two cases the base table admits and one it refuses, each check called with no
    table, and with an explicit None, raises; nothing is returned and nothing is captured; the
    raise is not a `ConfinementFault` (a refusal is a verdict, and no verdict exists without a
    table) and differs from what an explicitly empty table answers. Positive control: the same
    calls with the adapter-private table supplied answer as the base golden."""
    h = _http()
    table = _endpoint_table()
    empty = type(table)({})
    for system, url, method in NO_TABLE_CASES:
        for extra in ({}, {TABLE_KW: None}):
            value, exc = _run(h.confine_read_endpoint, system, url, method=method,
                              verb_class="r", **extra)
            assert exc is not None, (
                f"confine_read_endpoint({system!r}, {url!r}, {method!r}) with no table "
                f"{'' if not extra else '(None) '}admitted it, returning {value!r}")
            assert not isinstance(exc, h.ConfinementFault), (
                f"with no table the check refused as if the table were empty: {exc!r}")
            with_empty = _run(h.confine_read_endpoint, system, url, method=method,
                              verb_class="r", **{TABLE_KW: empty})
            assert _record(None, exc) != _record(*with_empty), (
                "a call with no table answers exactly as one with an empty table")

            capture = h.TransportCapture()
            value, exc = _run(h.guard_outbound, SimpleNamespace(capture=capture), system, url,
                              method=method, **extra)
            assert exc is not None, (
                f"guard_outbound({system!r}, {url!r}, {method!r}) with no table admitted it")
            assert not isinstance(exc, h.ConfinementFault), (
                f"with no table the guard refused as if the table were empty: {exc!r}")
            assert not capture.requests, (
                f"guard_outbound with no table recorded {capture.requests} — it was admitted")
    _assert_rows("no_table_positive", _section_no_table_positive())
