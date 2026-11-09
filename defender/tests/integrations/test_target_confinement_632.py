"""#632 target fidelity: a verb cannot be aimed outside the system it is declared under. Elastic refuses indices outside the configured patterns and reaches only its declared (path, method) read endpoints; a case adapter the cold read refused serves no comment. The other systems are confined by the proxy's route check (#1391 A6). `elastic.esql` names its sources inside the query text, so every source it reads must fall within the same patterns (#1347 O2a)."""
from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402
from defender.integrations.confinement import (  # noqa: E402
    READ_ENDPOINT_ALLOWLIST,
    AllowlistError,
    ConfinementFault,
    ReadEndpointAllowlist,
    confine_index,
    confine_read_endpoint,
    normalize_endpoint,
)

pytestmark = pytest.mark.e2e

CONFIGURED_PATTERNS = ("logs-*", "security-audit-*")
TICKET_READ_PATH = "/tickets"


# Retired by #1391 (design r4's retire list and A6): host-state's host inventory and program
# allowlist, the stub systems' read-endpoint table, the Docker-only confinement of a tenant-only
# system, and the ticket write table. Host-state is now an HTTP adapter whose service owns what
# may be asked, and for every stub system the proxy's route check against its declaration is the
# only guard (refused writes: credential_proxy_1163/test_ticket_flow.py t6, t6b).


@pytest.mark.parametrize("widening", [
    ".security-7",  # an index outside the configured patterns altogether
    "logs-*,security-audit-*,.security-7", "*", "-logs-*",
])
def test_an_index_expression_whose_reach_widens_refuses_the_whole_call(
    tmp_path: Path, widening: str,
):
    with pytest.raises(ConfinementFault):
        confine_index(widening, CONFIGURED_PATTERNS)  # the verb half: test_query_flow (#1391 O3 P3)


@pytest.mark.parametrize("inside", [
    "logs-*",                 # a configured pattern, fed back verbatim
    "logs-2026.01.01",        # a CONCRETE index under it — the daily index every real read hits
    "logs-2026.01.*",         # a strictly NARROWER wildcard
    "security-audit-2026.01", # the same, on the second configured pattern
])
def test_a_configured_index_still_runs(inside: str):
    assert confine_index(inside, CONFIGURED_PATTERNS) == inside, \
        "an index whose reach is inside the configured patterns was rewritten or refused"


def test_the_read_endpoint_allowlist_cannot_be_built_with_a_methodless_entry():
    assert isinstance(READ_ENDPOINT_ALLOWLIST, ReadEndpointAllowlist), (
        "the shipped read-endpoint allowlist is not a constructed allowlist, so nothing in "
        "production refuses a method-less entry"
    )
    assert isinstance(READ_ENDPOINT_ALLOWLIST, Mapping), (
        "the allowlist type is not a Mapping — the endpoint rule's own test reads this table "
        "by key set, by system and by subscript"
    )

    for methodless in (
        ("/tickets",),         # a one-element entry: no method at all
        ("/tickets", ""),      # a present-but-empty method token
        ("/tickets", None),    # the shape a half-migrated entry takes
        "/tickets",            # a bare path string
    ):
        with pytest.raises(AllowlistError):
            ReadEndpointAllowlist({"ticket": (methodless,)})

    ok = ReadEndpointAllowlist({"ticket": ((TICKET_READ_PATH, "GET"),)})
    assert tuple(ok["ticket"]) == ((TICKET_READ_PATH, "GET"),), \
        "a well-authored (endpoint, method) pair did not survive construction"
    confine_read_endpoint("elastic", "http://es:9200/_cluster/health", method="GET",
                          verb_class="r")


def test_the_two_post_with_body_reads_still_pass_the_endpoint_check():
    confine_read_endpoint("elastic", "http://es:9200/logs-*/_search", method="POST",
                          verb_class="r")
    confine_read_endpoint("elastic", "http://es:9200/_query?format=json", method="POST",
                          verb_class="r")
    confine_read_endpoint("elastic", "http://es:9200/_cluster/health", method="GET",
                          verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_update/1", method="POST",
                              verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_search", method="DELETE",
                              verb_class="r")


def test_the_endpoint_check_binds_on_the_resolved_normalized_path_without_the_query_string():
    assert normalize_endpoint("http://es:9200/logs-*/_search?pretty=true&x=1") == "/logs-*/_search"
    assert normalize_endpoint("http://es:9200//logs-*//_search/") == "/logs-*/_search"

    confine_read_endpoint("elastic", "http://es:9200/logs-*/_search?pretty=true", method="POST",
                          verb_class="r")

    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/logs-*/_search/../../_update/1",
                              method="POST", verb_class="r")
    with pytest.raises(ConfinementFault):
        confine_read_endpoint("elastic", "http://es:9200/%5Flogs/../_update/1", method="POST",
                              verb_class="r")


# ---- the host write entry (#1359 D-6) ----------------------------------------------------------



#: The one place the host write entry's call shape is spelled (D-6/D-15: name and four arguments;
#: house style adds the config and `system=`). `_host_write` and the planted adapter source below
#: both use this text, with `ctx`, `cfg`, `method`, `path`, `payload` in scope; the code stage
#: changes the shape here only.
HTTP_WRITE_CALL = 'transport.http_write(ctx, cfg, method, path, payload, system="ticket")'


#: A planted `ticket_adapter.py`: the host's comment action exactly as the tenant's case-record
#: file reaches it, but it writes where the call below says (the write-table-bypass shape).
PLANTED_TICKET_ADAPTER = '''\
from defender.integrations import _stub_transport as transport


def check_settings(tenant):
    return None


def health_check(ctx):
    return {{}}


def add_case_comment(ctx, *, key, body):
    cfg = transport.load_config(ctx, "ticket", "TICKET", ("TIMEOUT_SEC", "KEY_PATTERN"))
    method, path, payload = {method!r}, f"/tickets/{{key}}{suffix}", {{"body": body}}
    {write_call}
    return None


VERBS = {verbs}
'''

#: The planted adapter's `VERBS` as a harmless adapter spells it, and the three ways a cold read
#: refuses one that holds the comment action (r4 "Host-only, first layer").
HARMLESS_VERBS = '{"health-check": health_check}'
VERBS_HOLDING_THE_ACTION = {
    "dash-spelled key": '{"health-check": health_check, "add-case-comment": health_check}',
    "underscore-spelled key": '{"health-check": health_check, "add_case_comment": health_check}',
    "bare-name value": '{"health-check": health_check, "note": add_case_comment}',
}


def _leg_over_planted_adapter(tmp_path: Path, monkeypatch: Any, *, method: str, suffix: str,
                              verbs: str = HARMLESS_VERBS):
    """The record leg with a planted case adapter, the store behind the proxy's stand-in: (store, receipt)."""
    from defender import box as box_mod
    from defender.investigation import ticket_writer
    from defender.tests.support.runtime.engine import _spec767 as M
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    M.use_case_record(monkeypatch, tmp_path / "dfn")
    tree = tmp_path / "tree"
    (tree / "integrations").mkdir(parents=True)
    (tree / "integrations" / "ticket_adapter.py").write_text(
        PLANTED_TICKET_ADAPTER.format(method=method, suffix=suffix, verbs=verbs,
                                      write_call=HTTP_WRITE_CALL),
        encoding="utf-8")
    store = M.FakeStore(tmp_path / "store")
    run_dir = M.make_run(tmp_path / "runs")
    ticket_writer.record_case_ticket(
        fixture_run(run_dir), tenant=M.current_record(), defender_dir=tree,
        env=box_mod.run_env(S.DEFENDER, run_dir), proxy_url=store.url, request_token=M.WRITE_TOKEN)
    return store, M.receipt(run_dir)


@pytest.mark.parametrize("spelling", list(VERBS_HOLDING_THE_ACTION))
def test_a_case_adapter_the_cold_read_refused_serves_no_comment(
        tmp_path: Path, monkeypatch: Any, spelling: str):
    """Through the record leg, a case adapter whose `VERBS` holds the comment action is refused by
    the cold read and does not serve the host's comment either: no request reaches the store, an
    `error` receipt (`url` null) names `settings/case-record.yaml` and says the adapter was
    refused. Control: the same adapter without that `VERBS` entry comments. O4, D-7 amended."""
    control_store, control = _leg_over_planted_adapter(
        tmp_path / "control", monkeypatch, method="POST", suffix="/comments")
    assert control["status"] == "commented", control
    assert len(control_store.calls) == 1, "positive control: the harmless adapter commented once"

    store, got = _leg_over_planted_adapter(
        tmp_path / "bad", monkeypatch, method="POST", suffix="/comments",
        verbs=VERBS_HOLDING_THE_ACTION[spelling])
    assert store.calls == [], f"{spelling}: a refused adapter still served the comment"
    assert (got["status"], got["ok"], got["url"]) == ("error", False, None), got
    reason = got["reason"].lower()
    assert "case-record.yaml" in reason, got
    assert str(tmp_path).lower() not in reason, f"the reason carries a host path: {got}"
    assert "adapter" in reason, got
    assert "refused" in reason, got


@contextlib.contextmanager
def _esql_channel(tmp_path: Path, data_root: Path) -> Iterator[tuple[Any, Any, Any]]:
    """The real elastic adapter over the real proxy to a recording upstream that answers `/_query`."""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.integrations.credential_proxy_1163 import _harness as H

    rows = json.dumps({"columns": [], "values": []}).encode()
    with H.upstream() as up, A.elastic_proxied(tmp_path, data_root, up.url) as (ctx, tap):
        up.replies["/_query"] = (200, {"Content-Type": "application/json"}, rows)
        yield ctx, tap, up


def _events() -> str:
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    return A.ELASTIC_EVENTS


@pytest.mark.parametrize("query", [
    pytest.param("FROM .security-7 | LIMIT 1", id="from-outside"),
    pytest.param("from .security-7 | limit 1", id="lowercase"),
    pytest.param("FROM\n  .security-7\n| LIMIT 1", id="source-on-the-next-line"),
    pytest.param('FROM ".security-7" | LIMIT 1', id="quoted"),
    pytest.param("FROM {events}, .security-7 | LIMIT 1", id="second-source-outside"),
    pytest.param("FROM {events},.security-7 METADATA _id | LIMIT 1", id="outside-before-metadata"),
    pytest.param("FROM * | LIMIT 1", id="wildcard-wider-than-the-patterns"),
    pytest.param("FROM -{events} | LIMIT 1", id="exclusion"),
    pytest.param("TS .security-7 | LIMIT 1", id="ts-outside"),
    pytest.param("FROM {events} | LOOKUP JOIN .security-7 ON user.name", id="lookup-join-outside"),
    pytest.param("FROM {events}\n| WHERE a > 1\n| LOOKUP JOIN .security-7 ON user.name", id="lookup-join-later-line"),
])
def test_1347_o2a_an_esql_source_outside_the_configured_patterns_never_reaches_the_proxy(
        tmp_path: Path, data_root: Path, query: str):
    """O2a/A6: FROM, TS and LOOKUP JOIN name sources; one outside the configured patterns is a
    ConfinementFault before the proxy is asked. Control: a FROM on the events pattern is sent."""
    from defender.integrations import elastic_adapter

    with _esql_channel(tmp_path, data_root) as (ctx, tap, up):
        with pytest.raises(ConfinementFault):
            elastic_adapter.VERBS["esql"](ctx, query=query.replace("{events}", _events()))
        refused = (list(tap.tokens), list(up.seen))
        elastic_adapter.VERBS["esql"](ctx, query=f"FROM {_events()} | LIMIT 1")

    assert refused == ([], [])
    assert [s.path.split("?")[0] for s in up.seen] == ["/_query"]


@pytest.mark.parametrize("query", [
    pytest.param("FROM {events} | ENRICH hosts ON host.name", id="enrich"),
    pytest.param("FROM {events} | FORK (WHERE a > 1) (WHERE a < 1)", id="fork"),
    pytest.param("FROM (FROM {events}) | LIMIT 1", id="subquery-in-the-patterns"),
    pytest.param("FROM {events}, (FROM .security-7) | LIMIT 1", id="subquery-beside-a-source"),
    pytest.param("FROM remote:{events} | LIMIT 1", id="remote-cluster"),
    pytest.param("FROM *:{events} | LIMIT 1", id="every-remote-cluster"),
    pytest.param("FROM {events}, remote:{events} | LIMIT 1", id="remote-among-sources"),
    pytest.param("FROM | LIMIT 1", id="from-without-a-source"),
    pytest.param("FROM {events},, | LIMIT 1", id="empty-source-in-a-list"),
    pytest.param("", id="empty"),
    pytest.param("LIMIT 1", id="no-source-command"),
    pytest.param("SELECT * FROM {events}", id="not-esql"),
])
def test_1347_o2a_an_esql_query_that_cannot_be_confined_is_refused_on_every_run(
        tmp_path: Path, data_root: Path, query: str):
    """O2a/A6: ENRICH, FORK, subqueries, remote `cluster:index` and unparsable text are a ConfinementFault
    before the proxy is asked. Control: a FROM on the events pattern is sent."""
    from defender.integrations import elastic_adapter

    with _esql_channel(tmp_path, data_root) as (ctx, tap, up):
        with pytest.raises(ConfinementFault):
            elastic_adapter.VERBS["esql"](ctx, query=query.replace("{events}", _events()))
        refused = (list(tap.tokens), list(up.seen))
        elastic_adapter.VERBS["esql"](ctx, query=f"FROM {_events()} | LIMIT 1")

    assert refused == ([], [])
    assert [s.path.split("?")[0] for s in up.seen] == ["/_query"]


@pytest.mark.parametrize("query", [
    pytest.param("FROM {events} | LIMIT 1", id="the-pattern"),
    pytest.param("FROM logs-2026.11.03 | LIMIT 1", id="a-concrete-index-under-it"),
    pytest.param("FROM {events}, alerts-* | LIMIT 1", id="both-configured-patterns"),
    pytest.param('FROM "{events}" METADATA _id, _index | LIMIT 1', id="quoted-with-metadata"),
    pytest.param("from {events}\n| keep user.name\n| lookup join logs-2026.11.03 on user.name", id="lowercase-lookup-join"),
    pytest.param('FROM {events} | WHERE message RLIKE "x|FROM .security-7" | LIMIT 1', id="source-text-in-a-string-literal"),
    pytest.param("ROW a = 1 | EVAL b = a + 1", id="row"),
    pytest.param("SHOW INFO", id="show"),
])
def test_1347_o2a_an_esql_query_within_the_patterns_or_naming_no_source_is_sent(
        tmp_path: Path, data_root: Path, query: str):
    """O2a/A6: sources inside the configured patterns, and ROW/SHOW (which read nothing), are
    sent unchanged, on a run like any other."""
    from defender.integrations import elastic_adapter

    sent = query.replace("{events}", _events())
    with _esql_channel(tmp_path, data_root) as (ctx, _tap, up):
        elastic_adapter.VERBS["esql"](ctx, query=sent)

    assert [(s.path.split("?")[0], json.loads(s.body)) for s in up.seen] == [("/_query", {"query": sent})]
