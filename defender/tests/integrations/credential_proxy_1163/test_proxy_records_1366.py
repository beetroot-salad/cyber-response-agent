"""#1366 slice P (proxy): the proxy enforces the tenant's current system record (O7, P5, K3, R13, R14).

Two kinds of case. Hermetic ones (no marker) run the real proxy app over a records-port double that hands back the record
the test last set (a data source, deciding nothing) and the real `OpenBaoStore` over the KV stand-in. Postgres ones
(`postgres` marker, skipped locally without `DEFENDER_TEST_POSTGRES_DSN`, failing in CI) run the same app over
`PostgresSystemRecords` logged in as a member of the read-only role, with records written by the operator command.
Existing proxy tests do not come here: they go through `_tenant.deps(...)`, which hands the legacy export folders in
through `R.ExportRecords`. No case gives the proxy a data root: it has none.
"""
from __future__ import annotations

import contextlib
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

IDENTITY = {"IDENTITY_TIMEOUT_SEC": "10"}
BASE = T.BASE_PATH
GRANT_RW = {("identity", "rw")}
TENANT = "66130000-0000-4000-8000-000000000001"
OLD_KEY = "canary-old-generation-key-1366"
NEW_KEY = H.CANARY_KEY
OAUTH = "oauth-client-credentials"


# --- hermetic: a records-port double and the real proxy -------------------------------------------------------------

class _Port:
    """`SystemRecordsPort` double: hands back the record the test put (None when there is none); keeps what was asked."""

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], Any] = {}
        self.asked: list[tuple[str, str]] = []

    def put(self, record: Any) -> None:
        self.records[(TENANT, record.system_id)] = record

    def current_system(self, tenant_id: str, system_id: str) -> Any:
        self.asked.append((tenant_id, system_id))
        return self.records.get((tenant_id, system_id))


def _record(access: str, *, version: int = 1, generation: int = 1, enabled: bool = True, system: str = "identity") -> Any:
    from defender.tenancy.models import SystemRecord

    return SystemRecord(system_id=system, version=version, adapter_id=system, enabled=enabled,
                        settings=dict(IDENTITY), access=access, credential_generation=generation)


def _path(generation: int, tenant: str = TENANT, system: str = "identity") -> str:
    return f"{tenant}/{system}/g{generation}"


def _static(key: str) -> Any:
    return R.credential_set({"api_key": key})


@dataclass
class _Wire:
    port: _Port
    kv: R.KvStandIn
    audit: Any
    up: H.Upstream
    client: Any
    signer: H.FakeSigner

    @property
    def base(self) -> str:
        return self.up.url + BASE

    def ask(self, method: str = "GET", path: str = "/users/x", *, grant: set[tuple[str, str]] = T.GRANT_R,
            url: str | None = None, system: str = "identity") -> dict[str, Any]:
        tok = T.token(TENANT, grant, signer=self.signer)
        return T.ask(self.client, tok, system, method, url if url is not None else f"{self.base}{path}")


@contextlib.contextmanager
def _wire(held: dict[str, Any] | None = None):
    signer, port, kv, audit = H.FakeSigner(), _Port(), R.KvStandIn(held), H.AuditRecorder()
    client = T.client_of(proxy().ProxyDeps(records=port, store=R.proxy_credentials(kv),
                                           verifier=H.PairedVerifier(signer), audit=audit))
    with H.upstream() as up:
        yield _Wire(port, kv, audit, up, client, signer)


@pytest.mark.parametrize("state", ["no-record-or-deleted", "disabled"])
def test_1366_o7_a_system_with_no_current_record_or_a_disabled_one_is_refused_on_the_next_call_and_nothing_is_sent(state):
    """A call that was sent is, once the record is gone (none, or deleted: the port answers None) or disabled, a
    configuration refusal with nothing sent, though its credentials are stored. (#1366 O7)"""
    with _wire({_path(1): _static(NEW_KEY)}) as w:
        w.port.put(_record(H.declaration(w.base)))
        assert w.ask()["fault"] is None, "control: the enabled record is served"

        if state == "disabled":
            w.port.put(_record(H.declaration(w.base), version=2, enabled=False))
        else:
            w.port.records.clear()
        refused = w.ask()

        assert refused["fault"] == "ConfigFault", refused
        assert w.up.paths() == [f"{BASE}/users/x"], "only the control reached the upstream"
        assert len(w.port.asked) == 2


@pytest.mark.parametrize(("method", "target", "fault"), [
    pytest.param("GET", "outside-base-path", "ConfigFault", id="path-outside-the-base"),
    pytest.param("GET", "another-origin", "ConfigFault", id="another-origin"),
    pytest.param("POST", "undeclared-write", "ConfinementFault", id="write-route-not-declared"),
])
def test_1366_o7_an_address_outside_the_current_records_base_or_routes_is_refused_unsent(method, target, fault):
    """The call is judged against the current record's base and routes: each refused with its class and nothing sent,
    while a declared write (control, same channel) is sent. (#1366 O7)"""
    with _wire({_path(1): _static(NEW_KEY)}) as w, H.upstream() as other:
        w.port.put(_record(H.declaration(w.base, writes=(("POST", "/tickets"),))))
        urls = {"outside-base-path": f"{w.up.url}/other/users/x", "another-origin": f"{other.url}{BASE}/users/x",
                "undeclared-write": f"{w.base}/orders"}
        assert w.ask("POST", "/tickets", grant=GRANT_RW)["fault"] is None, "control: a declared write is sent"
        sent_before = list(w.up.paths())

        refused = w.ask(method, grant=GRANT_RW, url=urls[target])

        assert refused["fault"] == fault, refused
        assert (w.up.paths(), other.seen) == (sent_before, [])


def test_1366_o7_a_record_edit_between_two_calls_takes_effect_on_the_next_call():
    """A write route added then dropped between calls: the same call is refused, sent, refused (no caching of the
    record; the same credentials serve all three). (#1366 O7)"""
    with _wire({_path(1): _static(NEW_KEY)}) as w:
        write = {"method": "POST", "path": "/tickets", "grant": GRANT_RW}
        w.port.put(_record(H.declaration(w.base)))
        first = w.ask(**write)
        w.port.put(_record(H.declaration(w.base, writes=(("POST", "/tickets"),)), version=2))
        second = w.ask(**write)
        w.port.put(_record(H.declaration(w.base), version=3))
        third = w.ask(**write)

        assert [a["fault"] for a in (first, second, third)] == ["ConfinementFault", None, "ConfinementFault"]
        assert [s.path for s in w.up.seen] == [f"{BASE}/tickets"]


def test_1366_o7_a_moved_system_refuses_the_old_base_and_has_no_credentials_until_set_at_the_new_generation():
    """After the record moves to another base (generation 2): the old base is refused unsent; the new base is refused
    "no credential set" though generation 1's key is stored, and only `g2` is read from then on; once `g2` is set the
    call is sent with the new key, never the old. (#1366 O7, P5)"""
    with _wire({_path(1): _static(OLD_KEY)}) as w:
        old, new = w.base, f"{w.up.url}/api/v3"
        w.port.put(_record(H.declaration(old)))
        assert w.ask()["fault"] is None, "control"
        w.port.put(_record(H.declaration(new), version=2, generation=2))

        at_old = w.ask(url=f"{old}/users/x")
        unset = w.ask(url=f"{new}/users/x")
        w.kv.held[_path(2)] = [_static(NEW_KEY)]
        at_new = w.ask(url=f"{new}/users/x")

        assert at_old["fault"] == "ConfigFault", at_old
        assert unset["fault"] == "ConfigFault", unset
        assert "no credential set" in str(unset["detail"]), unset
        assert at_new["fault"] is None, at_new
        assert [(s.path, s.headers.get("Authorization")) for s in w.up.seen] == [
            (f"{BASE}/users/x", f"Bearer {OLD_KEY}"), ("/api/v3/users/x", f"Bearer {NEW_KEY}")]
        assert set(w.kv.read_paths()[1:]) == {_path(2)}, "after the move only the current generation's path is read"


def test_1366_r13_credentials_are_read_at_the_records_generation_and_never_the_legacy_path():
    """Sets at the legacy path and at g1 and g3 with the record at generation 2: the call is refused for want of a set
    at g2, and every read was of g2. (#1366 R13, P5)"""
    held = {f"{TENANT}/identity": _static(OLD_KEY), _path(1): _static(OLD_KEY), _path(3): _static(OLD_KEY)}
    with _wire(held) as w:
        w.port.put(_record(H.declaration(w.base), version=3, generation=2))

        refused = w.ask()

        assert refused["fault"] == "ConfigFault", refused
        assert "no credential set" in str(refused["detail"]), refused
        assert w.up.seen == []
        assert set(w.kv.read_paths()) == {_path(2)}


@pytest.mark.parametrize("interleaved_refusal", [True, False], ids=["a-run-between", "back-to-back"])
def test_1366_k3_a_deleted_and_re_created_system_does_not_reuse_the_old_generations_access_token(interleaved_refusal):
    """Delete + re-create with an identical declaration and a new secret at g2 (its KV version 1, like g1's): a new
    token exchange carries the new secret and the API call uses the new token. A cache hit on the first would show as
    one exchange. (#1366 K3)"""
    issued: list[str] = []
    new_secret = "canary-recreated-secret-1366"
    first = R.credential_set({"client_id": H.CLIENT_ID, "client_secret": H.CANARY_SECRET}, kind=OAUTH)
    with H.upstream() as auth, _wire({_path(1): first}) as w:
        auth.replies["/token"] = H.token_endpoint(issued)
        decl = H.declaration(w.base, scheme=H.oauth_scheme(auth.url + "/token"))
        w.port.put(_record(decl))
        assert (w.ask()["fault"], w.ask()["fault"]) == (None, None)
        assert issued == ["AT-1-canary-1163"], "control: the second call reused the cached token"

        w.port.records.clear()
        if interleaved_refusal:
            assert w.ask()["fault"] == "ConfigFault"
        w.port.put(_record(decl, version=3, generation=2))
        w.kv.held[_path(2)] = [R.credential_set({"client_id": H.CLIENT_ID, "client_secret": new_secret}, kind=OAUTH)]
        again = w.ask()

        assert again["fault"] is None, again
        assert len(issued) == 2, "the old access token was reused"
        assert len(auth.seen) == 2
        assert H.carries(auth.seen[1], new_secret, client_id=H.CLIENT_ID)
        assert not H.carries(auth.seen[1], H.CANARY_SECRET, client_id=H.CLIENT_ID)
        assert w.up.seen[-1].header("Authorization") == f"Bearer {issued[1]}"


def test_1366_o7_the_audit_trail_names_the_version_not_the_commit_and_has_it_before_route_and_credential_refusals():
    """A sent call, a route refusal and a no-credentials refusal each leave one record carrying the record's version
    (7, 7, 8: not a constant) and no `commit`. (#1366 O7)"""
    with _wire({_path(1): _static(NEW_KEY)}) as w:
        w.port.put(_record(H.declaration(w.base), version=7))
        w.ask()
        w.ask("POST", "/tickets", grant=GRANT_RW)
        w.port.put(_record(H.declaration(w.base), version=8, generation=2))
        w.ask()

        records = w.audit.records
        assert [(r["outcome"], r["version"]) for r in records] == [
            ("sent 200", 7), ("ConfinementFault", 7), ("ConfigFault", 8)]
        assert not any("commit" in r for r in records), records
        assert {(r["tenant"], r["system"]) for r in records} == {(TENANT, "identity")}


def test_1366_o7_a_database_that_cannot_be_reached_is_a_transport_fault_and_nothing_is_sent():
    """The records read of a port whose database address refuses connections answers `TransportFault`, unsent and
    before any credential read; the control is the same proxy over a reachable record source. (#1366 O7)"""
    from defender.credential_proxy._records import PostgresSystemRecords

    dead = f"postgresql://nobody:pw@127.0.0.1:{H.free_port()}/none"
    signer, kv, audit = H.FakeSigner(), R.KvStandIn({_path(1): _static(NEW_KEY)}), H.AuditRecorder()
    with contextlib.closing(PostgresSystemRecords(dead)) as port, H.upstream() as up:
        client = T.client_of(proxy().ProxyDeps(records=port, store=R.proxy_credentials(kv),
                                               verifier=H.PairedVerifier(signer), audit=audit))
        answer = T.ask(client, T.token(TENANT, T.GRANT_R, signer=signer), "identity", "GET", f"{up.url}{BASE}/users/x")

    assert answer["fault"] == "TransportFault", answer
    assert up.seen == []
    assert kv.read_paths() == []


# --- Postgres: the real read-only login, records written by the operator command ------------------------------------

@dataclass
class _Pg:
    t: Any
    op: R.Operator
    kv: R.KvStandIn
    up: H.Upstream
    dsn: str
    stack: contextlib.ExitStack

    @property
    def base(self) -> str:
        return self.up.url + BASE

    def proxy_for(self, *, granted: bool = True) -> tuple[Callable[..., dict[str, Any]], Any]:
        """A proxy over a fresh read-only login (member of the role, or with no grant) and a caller of identity."""
        from defender.credential_proxy._records import PostgresSystemRecords

        login = self.stack.enter_context(R.proxy_login(self.dsn, granted=granted))
        records = self.stack.enter_context(contextlib.closing(PostgresSystemRecords(login)))
        signer, audit = H.FakeSigner(), H.AuditRecorder()
        client = T.client_of(proxy().ProxyDeps(records=records, store=R.proxy_credentials(self.kv),
                                               verifier=H.PairedVerifier(signer), audit=audit))

        def ask(method: str = "GET", path: str = "/users/x", grant: set[tuple[str, str]] = T.GRANT_R) -> dict[str, Any]:
            return T.ask(client, T.token(self.t.tenant_id, grant, signer=signer), "identity", method, f"{self.base}{path}")

        return ask, audit


@contextlib.contextmanager
def _pg(tmp_path, data_root, dsn, capsys, monkeypatch, held: dict[str, Any] | None = None):
    """A registered, imported tenant (the fixture's systems), a recording upstream and a KV stand-in holding `held`
    (`<t>` in a key is the tenant's id)."""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", dsn)
    with (contextlib.ExitStack() as stack, H.upstream() as up,
          published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as t):
        register_tenant(dsn, t.tenant_id, data_root=t.data_root)
        kv = R.KvStandIn({k.replace("<t>", t.tenant_id): v for k, v in (held or {}).items()})
        yield _Pg(t, R.Operator(t.tenant_id, dsn, tmp_path / "op", capsys, kv=kv), kv, up, dsn, stack)


@pytest.mark.postgres
def test_1366_o7_the_proxy_sends_to_the_current_records_base_with_its_generations_credentials_until_it_is_deleted(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    """identity moved to the upstream (version 2, generation 2): a call is sent there with the set at `g2` (the
    pre-generation path and `g1` are never read) and audited with version 2; once identity is deleted the same call is a
    configuration refusal and nothing is sent. (#1366 O7, P5)"""
    held = {"<t>/identity": _static("pre-1366-key"), "<t>/identity/g1": _static("old-generation-key"),
            "<t>/identity/g2": _static(NEW_KEY)}
    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch, held) as w:
        assert w.op.set_system("identity", replaces=1, config=IDENTITY, access=H.declaration(w.base))[0] == 0
        assert w.op.numbers("identity")[-1] == (2, 2, False), "premise: the move raised the generation"
        ask, audit = w.proxy_for()

        sent = ask()

        assert sent["fault"] is None, sent
        assert [(s.path, s.headers.get("Authorization")) for s in w.up.seen] == [
            (f"{BASE}/users/x", f"Bearer {NEW_KEY}")]
        assert w.kv.read_paths() == [_path(2, w.t.tenant_id)]
        assert (audit.records[-1]["system"], audit.records[-1]["version"]) == ("identity", 2)

        assert w.op.delete_system("identity", replaces=2)[0] == 0
        refused = ask()

        assert refused["fault"] == "ConfigFault", refused
        assert len(w.up.seen) == 1, "a deleted system's call reached the upstream"


@pytest.mark.postgres
def test_1366_o7_the_records_port_reuses_its_connection_and_still_reads_the_newest_version(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """Three reads through one port hold one database session, and a read after a write sees the write; a kept session the
    server closed is replaced, and the read answers rather than failing. (#1366 O7)"""
    from psycopg.conninfo import conninfo_to_dict

    from defender.credential_proxy._records import PostgresSystemRecords
    from defender.tests.support.shared._postgres1339 import execute

    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch) as w:
        login = w.stack.enter_context(R.proxy_login(w.dsn))
        user = conninfo_to_dict(login)["user"]
        port = w.stack.enter_context(contextlib.closing(PostgresSystemRecords(login)))

        def sessions() -> list[Any]:
            return [r[0] for r in execute(w.dsn, "SELECT pid FROM pg_stat_activity WHERE usename = %s", (user,))]

        assert port.current_system(w.t.tenant_id, "identity").version == 1
        assert port.current_system(w.t.tenant_id, "identity").version == 1
        assert w.op.set_system("identity", replaces=1, config=IDENTITY, access=H.declaration(w.base))[0] == 0
        assert port.current_system(w.t.tenant_id, "identity").version == 2, "a kept session read a stale version"
        held = sessions()
        assert len(held) == 1, held

        execute(w.dsn, "SELECT pg_terminate_backend(%s)", (held[0],))
        assert port.current_system(w.t.tenant_id, "identity").version == 2
        settle = time.monotonic() + 5  # the terminated session leaves the activity view on its own time
        while held[0] in sessions() and time.monotonic() < settle:
            time.sleep(0.05)
        assert len(sessions()) == 1, sessions()


@pytest.mark.postgres
def test_1366_o7_a_kept_connection_whose_read_times_out_is_not_read_again_past_the_deadline(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """The records table is held locked, so a read on the kept session runs into its own statement timeout: that is a
    slow database, not a stale session, so the read fails within the request's deadline rather than being tried again
    on a fresh session with a fresh budget. (#1366 O7)"""
    import psycopg

    from defender.credential_proxy._deadline import Deadline, answering
    from defender.credential_proxy._records import PostgresSystemRecords
    from defender.kit.faults import TransportFault

    budget = 1.5
    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch) as w:
        login = w.stack.enter_context(R.proxy_login(w.dsn))
        port = w.stack.enter_context(contextlib.closing(PostgresSystemRecords(login)))
        assert port.current_system(w.t.tenant_id, "identity").version == 1  # premise: one kept session
        with psycopg.connect(w.dsn) as holder:
            holder.execute("LOCK TABLE tenancy.system_versions IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            with answering(Deadline.after(budget)), pytest.raises(TransportFault):
                port.current_system(w.t.tenant_id, "identity")
            took = time.monotonic() - started
            holder.rollback()

    assert took < budget + 0.5, f"the read took {took:.2f}s against a {budget}s deadline"


@pytest.mark.postgres
def test_1366_r13_an_imported_system_is_refused_until_credentials_are_set_at_its_generation(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """The tenant was imported (seeded) and identity then moved to generation 2; the only stored set is at the legacy path:
    the call is refused as a configuration fault naming no stored credential set, nothing is sent, and the legacy path
    is never read; after `set-credentials` writes `g2` the same call goes through. (#1366 R13, O7)"""
    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch, {"<t>/identity": _static("pre-1366-key")}) as w:
        assert w.op.set_system("identity", replaces=1, config=IDENTITY, access=H.declaration(w.base))[0] == 0
        assert w.op.numbers("identity")[-1][:2] == (2, 2), "premise: a generation-2 version"
        ask, _ = w.proxy_for()

        refused = ask()

        assert refused["fault"] == "ConfigFault", refused
        assert "no credential set" in str(refused["detail"]), refused
        assert (w.up.seen, w.kv.read_paths()) == ([], [_path(2, w.t.tenant_id)])

        assert w.op.set_credentials("identity", {"api_key": NEW_KEY}, for_version=2)[0] == 0
        assert ask()["fault"] is None


@pytest.mark.postgres
def test_1366_o7_an_operators_edits_between_calls_apply_to_the_next_call_without_resetting_credentials(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """On one running proxy: disabling identity refuses the next call unsent, re-enabling serves it again, and a route
    edit (same generation) admits a write, all with the one set at `g2`; the audited versions follow. (#1366 O7)"""
    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch, {"<t>/identity/g2": _static(NEW_KEY)}) as w:
        decl = H.declaration(w.base)
        assert w.op.set_system("identity", replaces=1, config=IDENTITY, access=decl)[0] == 0
        ask, audit = w.proxy_for()

        assert ask()["fault"] is None
        assert w.op.set_system("identity", replaces=2, config=IDENTITY, access=decl, disabled=True)[0] == 0
        assert ask()["fault"] == "ConfigFault"
        assert len(w.up.seen) == 1, "a disabled system's call was sent"
        assert w.op.set_system("identity", replaces=3, config=IDENTITY, access=decl)[0] == 0
        assert ask()["fault"] is None
        assert ask("POST", "/tickets", GRANT_RW)["fault"] == "ConfinementFault"
        writes = H.declaration(w.base, writes=(("POST", "/tickets"),))
        assert w.op.set_system("identity", replaces=4, config=IDENTITY, access=writes)[0] == 0
        assert ask("POST", "/tickets", GRANT_RW)["fault"] is None

        assert [g for _, g, _ in w.op.numbers("identity")[1:]] == [2, 2, 2, 2], "premise: only the base move raised it"
        assert [(r["outcome"], r["version"]) for r in audit.records if r["outcome"] == "sent 200"] == [
            ("sent 200", 2), ("sent 200", 4), ("sent 200", 5)]


@pytest.mark.postgres
def test_1366_r14_a_login_without_the_roles_grant_is_a_configuration_fault_and_nothing_is_sent(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """The same record read through a login that is a member of the role is served (control); through one with no grant
    the query is refused and the call is `ConfigFault`, unsent. (#1366 R14, O7)"""
    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch, {"<t>/identity/g2": _static(NEW_KEY)}) as w:
        assert w.op.set_system("identity", replaces=1, config=IDENTITY, access=H.declaration(w.base))[0] == 0
        served, _ = w.proxy_for(granted=True)
        assert served()["fault"] is None, "control: the member is served"
        sent_before = list(w.up.paths())

        refused = w.proxy_for(granted=False)[0]()

        assert refused["fault"] == "ConfigFault", refused
        assert w.up.paths() == sent_before


_INSERT = ("INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled, settings, access, "
           "credential_generation, deleted, author, written_at) "
           "VALUES (%s, 'identity', 99, 'identity', true, '{}'::jsonb, 'x', 1, false, 'intruder', now())")


@pytest.mark.postgres
@pytest.mark.parametrize("statement", [
    pytest.param(_INSERT, id="insert"),
    pytest.param("UPDATE tenancy.system_versions SET enabled = false WHERE tenant_id = %s", id="update"),
    pytest.param("DELETE FROM tenancy.system_versions WHERE tenant_id = %s", id="delete"),
    pytest.param("TRUNCATE tenancy.system_versions", id="truncate"),
    pytest.param("SELECT count(*) FROM tenancy.case_versions WHERE tenant_id = %s", id="read-case-table"),
    pytest.param("SELECT count(*) FROM tenancy.records_mark WHERE tenant_id = %s", id="read-mark"),
    pytest.param("SELECT count(*) FROM tenancy.tenants WHERE id = %s", id="read-tenants"),
])
def test_1366_r14_a_member_of_the_proxy_role_reads_current_records_and_is_refused_everything_else(
        statement, migrated_database):  # noqa: F811
    """A login that is a member of `defender_proxy_reader` reads the system versions (control); each write to them, and a
    read of the case table, the mark or the tenants table, is refused for lack of privilege, and the rows are unchanged.
    (#1366 R14)"""
    import psycopg

    tid = str(uuid.uuid4())
    register_tenant(migrated_database, tid)
    before = R.current_records(migrated_database, tid)
    with R.proxy_login(migrated_database) as login:
        rows = execute(login, "SELECT system_id, version FROM tenancy.system_versions WHERE tenant_id = %s", (tid,))
        assert {s for s, _ in rows} == R.FIXTURE_SYSTEMS, "control: the member reads the seeded versions"

        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            execute(login, statement, (tid,) if "%s" in statement else ())

    assert R.current_records(migrated_database, tid) == before


@pytest.mark.postgres
def test_1366_o7_the_proxy_built_from_operator_config_reads_records_through_the_configured_dsn(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811
    """The shipped assembly (`create_app_from_config`, no `ProxyDeps` built by the test) takes the read-only login's DSN
    from the config key `records_dsn` and reads the tenant's current record through it: identity moved to the upstream
    (version 2, generation 2) is sent with the `g2` set and audited to the configured file with version 2; the same
    config with a login that has no grant refuses the call unsent (control: the DSN is what decides). (#1366 O7)"""
    import json

    import httpx

    from defender.tests.integrations.credential_proxy_1163._target import app_from_config

    with _pg(tmp_path, data_root, migrated_database, capsys, monkeypatch, {"<t>/identity/g2": _static(NEW_KEY)}) as w:
        assert w.op.set_system("identity", replaces=1, config=IDENTITY, access=H.declaration(w.base))[0] == 0

        def openbao(request: httpx.Request) -> httpx.Response:
            if "/transit/verify/" in request.url.path:
                return httpx.Response(200, json={"data": {"valid": True}})
            return w.kv.handler(request)

        def ask_through(login: str, audit_file: Any) -> dict[str, Any]:
            from fastapi.testclient import TestClient

            config = {"openbao_token": "t", "kv_mount": R.KV_MOUNT, "records_dsn": login, "audit_path": str(audit_file)}
            client = TestClient(app_from_config(config, transport=httpx.MockTransport(openbao)))
            return T.ask(client, T.token(w.t.tenant_id, T.GRANT_R, signer=H.FakeSigner()), "identity", "GET",
                         f"{w.base}/users/x")

        with R.proxy_login(w.dsn, granted=False) as ungranted:
            refused = ask_through(ungranted, tmp_path / "refused.jsonl")
        assert refused["fault"] == "ConfigFault", refused
        assert w.up.seen == [], "a login without the grant must not read the record"

        with R.proxy_login(w.dsn) as granted:
            sent = ask_through(granted, tmp_path / "audit.jsonl")

        assert sent["fault"] is None, sent
        assert [(s.path, s.headers.get("Authorization")) for s in w.up.seen] == [
            (f"{BASE}/users/x", f"Bearer {NEW_KEY}")]
        written = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()]
        assert [(r["system"], r["version"]) for r in written] == [("identity", 2)]
