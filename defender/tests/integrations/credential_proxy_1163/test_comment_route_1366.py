"""#1366 C1/K5/C5: each catalog case adapter declares the route its comment action sends, the request it sends matches
that route at the proxy, and a stored record whose route is no longer covered is a case-settings fault at the leg.

Entry points: the adapter module's `comment_route(settings)` over the prefixed settings a system record holds; the
adapter's `add_case_comment` through the real proxy in front of a recording upstream (the ready-made rig); the record
leg (`ticket_writer.record_case_ticket`) over a published tenant whose stored access does or does not cover the route.
"""
from __future__ import annotations

import contextlib
import dataclasses
import importlib
import itertools
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender._paths import adapters_under
from defender.credential_proxy._refusal import Refused
from defender.credential_proxy._scope import check_route
from defender.credential_proxy._tokens import READ_WRITE
from defender.kit.faults import ConfigFault, ConfinementFault, TransportFault, UpstreamFault
from defender.tenancy import parse_access
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _ready_made1359 as RM
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

KEY = C.TICKET_KEY
TICKET = RM.Vendor("ticket", "ticket", 'TICKET_KEY_PATTERN="[A-Za-z0-9-]+"\n', "/t", ("POST", "/tickets/*/comments"),
                   lambda k: f"/tickets/{k}/comments", "POST", lambda base, k: f"{base}/tickets/{k}")
#: (id, vendor, the route design C1 names for these settings). The vendor's env is the settings the route is read from.
VARIANTS = [
    ("jira-cloud", RM.JIRA_NO, ("POST", "/rest/api/3/issue/*/comment")),
    ("jira-service-desk", RM.JIRA_YES, ("POST", "/rest/servicedeskapi/request/*/comment")),
    ("servicenow", RM.SERVICENOW, ("PATCH", f"/api/now/table/{RM.TABLE}/*")),
    ("servicenow-incident", dataclasses.replace(RM.SERVICENOW, env='SERVICENOW_TABLE="incident"\n'),
     ("PATCH", "/api/now/table/incident/*")),
    ("servicenow-mixed-case", dataclasses.replace(RM.SERVICENOW, env='SERVICENOW_TABLE="X1_y_9"\n'),
     ("PATCH", "/api/now/table/X1_y_9/*")),
    ("ticket", TICKET, ("POST", "/tickets/*/comments")),
]
variants = pytest.mark.parametrize(("vendor", "expected"), [pytest.param(v, r, id=i) for i, v, r in VARIANTS])


def _adapter(system: str):
    return importlib.import_module(f"defender.integrations.{system.replace('-', '_')}_adapter")


def _settings(vendor: RM.Vendor) -> dict[str, str]:
    """The prefixed settings a record of `vendor` holds: the rig's config.env, as stored."""
    return R.parse_config_env(A.env_text(vendor.system, extra=vendor.env))


def _declared(vendor: RM.Vendor) -> tuple[str, str]:
    method, pattern = _adapter(vendor.system).comment_route(_settings(vendor))
    return method, pattern


def _catalog() -> list[tuple[str, object]]:
    """Every adapter module the product carries, by membership of the adapters directory."""
    names = [p.name.removesuffix("_adapter.py") for p in sorted(adapters_under(DEFENDER).glob("*_adapter.py"))]
    return [(name, _adapter(name)) for name in names]


# --- C1: the declaration -----------------------------------------------------------------------------------------

@variants
def test_1366_c1_a_case_adapter_declares_its_comment_route_from_its_settings(vendor, expected):
    """The route is (method, pattern relative to the base), the key the one `*`, settings literals filled. (#1366 C1)"""
    assert _declared(vendor) == expected


def test_1366_c1_every_catalog_adapter_with_a_comment_action_declares_a_route_the_tests_cover():
    """Class by membership: each adapter defining `add_case_comment` has a callable `comment_route`, and a variant above
    exercises it, so a new case adapter cannot slip past the request-matches-route test. (#1366 C1, K5)"""
    case = {s for s, m in _catalog() if callable(getattr(m, "add_case_comment", None))}
    assert case, "no catalog adapter offers a comment action: the census saw nothing"
    undeclared = sorted(s for s in case if not callable(getattr(_adapter(s), "comment_route", None)))
    assert undeclared == [], f"case adapters with no comment_route: {undeclared}"
    covered = {v.system for _, v, _ in VARIANTS}
    assert case <= covered, f"no variant covers {sorted(case - covered)}"


def test_1366_c1_an_adapter_without_a_comment_action_has_no_route():
    """Every catalog adapter that defines no `add_case_comment` declares no route: absent, or None. (#1366 C1)"""
    plain = [(s, m) for s, m in _catalog() if not callable(getattr(m, "add_case_comment", None))]
    assert plain, "the census found no non-case adapter"
    routed = [s for s, m in plain
              if getattr(m, "comment_route", None) is not None and m.comment_route({}) is not None]
    assert routed == [], f"adapters offering no comment action but declaring a route: {routed}"


#: Every string of up to two characters over an alphabet holding the three forbidden ones: the class a settings
#: literal can fall in, by membership (a hand-picked list invites a check that handles exactly that list).
_LITERALS = ["".join(p) for n in (0, 1, 2) for p in itertools.product("a*/\\", repeat=n)]
_FORBIDDEN = [s for s in _LITERALS if not s or set(s) & set("*/\\")]
_FINE = [s for s in _LITERALS if s and not set(s) & set("*/\\")]


def test_1366_c1_a_table_literal_that_is_empty_or_holds_a_separator_or_star_is_the_adapters_settings_fault():
    """Any TABLE that is empty or holds `*`, `/` or `\\` is refused naming the key; the rest yield the filled route. (#1366 C1)"""
    module = _adapter("servicenow")
    base = {"SERVICENOW_TIMEOUT_SEC": "10"}
    wrongly_accepted, unnamed = [], []
    for literal in _FORBIDDEN:
        try:
            module.comment_route({**base, "SERVICENOW_TABLE": literal})
        except ConfigFault as fault:
            if "SERVICENOW_TABLE" not in str(fault):
                unnamed.append((literal, str(fault)))
        else:
            wrongly_accepted.append(literal)
    assert wrongly_accepted == [], f"accepted without a settings fault: {wrongly_accepted!r}"
    assert unnamed == [], f"a settings fault that does not name the key: {unnamed!r}"
    for literal in _FINE:
        assert tuple(module.comment_route({**base, "SERVICENOW_TABLE": literal})) == (
            "PATCH", f"/api/now/table/{literal}/*")


# --- C1: the route is in the proxy's grammar ----------------------------------------------------------------------

@variants
def test_1366_c1_the_declared_route_is_in_the_proxy_route_grammar(vendor, expected):
    """The access parser accepts the route as a write; the proxy's own matcher admits it with the key in the `*`, and
    refuses a different literal, a different segment count and another method. (#1366 C1)"""
    method, pattern = _declared(vendor)
    access = parse_access(R.declaration("http://store.internal:8000", writes=((method, pattern),)),
                          system=vendor.system)
    sent = pattern.replace("*", KEY)
    check_route(access, vendor.system, method, sent, READ_WRITE)  # control: admitted
    segments = sent.split("/")
    broken = [sent + "/x", "/".join(segments[:-1]),
              *("/".join([*segments[:i], "zz", *segments[i + 1:]]) for i in range(1, len(segments))
                if segments[i] != KEY)]
    for path in broken:
        with pytest.raises(Refused):
            check_route(access, vendor.system, method, path, READ_WRITE)
    with pytest.raises(Refused):
        check_route(access, vendor.system, "DELETE", sent, READ_WRITE)


# --- K5: the request sent matches the route declared ---------------------------------------------------------------

def _declaring(tmp: Path, data_root: Path, vendor: RM.Vendor, route: tuple[str, str]):
    """`vendor`'s settings behind the real proxy whose declaration lists exactly `route` as its one write."""
    return RM.planted(tmp, data_root, dataclasses.replace(vendor, write=route))


@variants
def test_1366_k5_the_request_add_case_comment_sends_is_the_route_the_adapter_declares(
        vendor, expected, tmp_path, data_root, checkout_roster):
    """With only the declared route as the proxy's write, the comment reaches the upstream once, as that method and
    path with the key in the `*`; the proxy's own matcher admits what the upstream saw. (#1366 K5)"""
    route = _declared(vendor)
    with _declaring(tmp_path, data_root, vendor, route) as rig:
        rig.comment(checkout_roster, KEY)
        (seen,) = rig.sent()
    method, pattern = route
    path = seen.path.split("?")[0]
    assert (seen.method, path) == (method, vendor.base_path + pattern.replace("*", KEY))
    declared = parse_access(R.declaration("http://x.test", writes=(route,)), system=vendor.system)
    check_route(declared, vendor.system, seen.method, path.removeprefix(vendor.base_path), READ_WRITE)


def test_1366_k5_a_request_off_the_declared_route_is_refused_by_the_proxy_and_never_reaches_the_upstream(
        tmp_path, data_root, checkout_roster):
    """Control for the channel: the service-desk adapter under the cloud adapter's declared route sends nothing the
    proxy admits, so a mismatch between sent request and declared route would show here. (#1366 K5)"""
    with _declaring(tmp_path, data_root, RM.JIRA_YES, _declared(RM.JIRA_NO)) as rig:
        with pytest.raises((ConfigFault, ConfinementFault, TransportFault, UpstreamFault)):  # the proxy's refusal is a ConfinementFault
            rig.comment(checkout_roster, KEY)
        assert rig.sent() == []


# --- C5, run side: a stored record that no longer covers its route -------------------------------------------------

def _not_covering(r: tuple[str, str]) -> dict[str, tuple[tuple, tuple]]:
    """label -> (reads, writes) built from the declared route `r`; each leaves the stored access not covering `r` (C2)."""
    method, pattern = r
    return {
        "no-write-route": ((), ()),
        "other-path": ((), ((method, pattern.rsplit("/", 1)[0] + "/elsewhere"),)),
        "other-method": ((), (("PUT" if method != "PUT" else "POST", pattern),)),
        "literal-where-the-adapter-has-a-star": ((), ((method, pattern.replace("*", KEY)),)),
        "longer": ((), ((method, pattern + "/x"),)),
        "shorter": ((), ((method, pattern.rsplit("/", 1)[0]),)),
        "read-route-matching-the-comment-route": ((r,), (r,)),
        "read-route-literal-matching-the-comment-route": (((method, pattern.replace("*", "ABC-1")),), (r,)),
    }


@contextlib.contextmanager
def _stored(tmp: Path, data_root: Path, vendor: RM.Vendor, reads: tuple, writes: tuple) -> Iterator[RM.Rig]:
    """The case-record tenant of `vendor` whose STORED record's access holds exactly `reads` and `writes`: the run's record
    and the proxy's port are built from that record (#1366 R10: `run_tenant_for(..., records=)`). The published folder
    still carries the vendor's covering declaration, so a leg that judged the folder would pass where the record fails."""
    from defender.tests.integrations.credential_proxy_1163._target import proxy

    with H.upstream() as up:
        base = vendor.declared_base(up)
        spec = RM.records_of(vendor, base, leg=True, reads=reads, writes=writes)
        with published_tenant(tmp / "forge", root=data_root, files=RM.files_for(vendor, base, leg=True)) as t:
            store = H.FakeStore({(t.tenant_id, vendor.system): T.basic_set(RM.USER, RM.PASSWORD)})
            tap = RM.RequestTap(proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store,
                                                          records={t.tenant_id: spec})))
            with H.serve_asgi(tap) as url:
                yield RM.Rig(vendor, up, t, url, tap, tmp, spec)


_LEG = [(i, v, r) for i, v, r in VARIANTS if i in ("jira-service-desk", "servicenow", "ticket")]
_BROKEN = [pytest.param(v, r, label, id=f"{i}-{label}") for i, v, r in _LEG for label in _not_covering(r)]


@pytest.mark.parametrize(("vendor", "route", "label"), _BROKEN)
def test_1366_c5_a_stored_record_that_no_longer_covers_the_route_is_a_case_settings_fault_nothing_is_sent(
        vendor, route, label, tmp_path, data_root):
    """The leg's verdict is the settings fault: an error receipt naming the case system, no call to the proxy, none to
    the store, and not the proxy's refusal. (#1366 C5, C2)"""
    reads, writes = _not_covering(route)[label]
    with _stored(tmp_path, data_root, vendor, reads, writes) as rig:
        receipt = rig.leg("leg")
        assert receipt is not None, label
        assert (receipt["ok"], receipt["status"]) == (False, "error"), receipt
        assert vendor.system in receipt["reason"], receipt
        assert "the credential proxy refused" not in receipt["reason"].lower(), receipt
        assert rig.tap.bodies == [], "the proxy was sent the comment"
        assert rig.sent() == [], "the store was reached"


@pytest.mark.parametrize(("vendor", "route"), [pytest.param(v, r, id=i) for i, v, r in VARIANTS])
def test_1366_c5_a_stored_record_that_covers_the_route_comments_whatever_else_it_declares(
        vendor, route, tmp_path, data_root):
    """Control on the same channel: the declared route (alone, or among unrelated reads and writes that do not match
    it) is covered, and the comment lands. (#1366 C5, C2)"""
    unrelated_read = ("POST", route[1] + "/x")  # a different segment count never matches the comment route
    unrelated_write = ("PUT", "/elsewhere/*")
    for label, reads, writes in (("alone", (), (route,)),
                                 ("among-others", (unrelated_read,), (unrelated_write, route))):
        with _stored(tmp_path / label, data_root, vendor, reads, writes) as rig:
            receipt = rig.leg("leg")
            assert receipt is not None, label
            assert (receipt["ok"], receipt["status"]) == (True, "commented"), (label, receipt)
            assert len(rig.sent()) == 1, label
