"""#632 target fidelity: a verb cannot be aimed outside the system it is declared under. Elastic refuses indices outside the configured patterns and reaches only its declared (path, method) read endpoints; a case adapter the cold read refused serves no comment. The other systems are confined by the proxy's route check (#1391 A6). Not covered: `elastic.esql` selects its target inside the FROM clause, which the verb-level check does not reach."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402
from defender.kit.faults import ConfinementFault
from defender.integrations.confinement import (  # noqa: E402
    READ_ENDPOINT_ALLOWLIST,
    AllowlistError,
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
from defender.kit import transport


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
