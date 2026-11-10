"""#1359 slice C machinery: the ready-made Jira and ServiceNow adapters' vendor shapes, a tenant
planted as `/connect` would leave it, and the real proxy in front of a recording fake upstream.
Plants data and records; nothing here judges what the adapters must do."""
from __future__ import annotations

import base64
import contextlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from defender.box import run_env
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE
from defender.tests.support.runtime.engine._spec767 import write_report
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

USER = "svc-1359"
PASSWORD = H.CANARY_KEY
#: What the proxy must put on the upstream request for the stored basic credential.
BASIC_AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
TABLE = "sn_si_incident"
BODY = ("Verdict: benign — scheduled backup\n\n"
        "*Narrative* {\"k\": 1} <b>x</b> & café ✓\nlast line")


@dataclass(frozen=True)
class Vendor:
    """One configured shape: the system, its config lines, its base path at the fake upstream,
    the one write route `/connect` declares, and the path (under the base) a key is sent to."""

    id: str
    system: str
    env: str
    base_path: str
    write: tuple[str, str]
    route: Callable[[str], str]
    method: str
    link: Callable[[str, str], str | None]

    def declared_base(self, up: H.Upstream) -> str:
        return up.url + self.base_path


JIRA_NO = Vendor("jira-no", "jira", 'JIRA_SERVICE_DESK="no"\n', "/jira",
                 ("POST", "/rest/api/3/issue/*/comment"),
                 lambda k: f"/rest/api/3/issue/{k}/comment", "POST",
                 lambda base, k: f"{base}/browse/{k}")
JIRA_YES = Vendor("jira-yes", "jira", 'JIRA_SERVICE_DESK="yes"\n', "/jira",
                  ("POST", "/rest/servicedeskapi/request/*/comment"),
                  lambda k: f"/rest/servicedeskapi/request/{k}/comment", "POST",
                  lambda base, k: f"{base}/browse/{k}")
SERVICENOW = Vendor("servicenow", "servicenow", f'SERVICENOW_TABLE="{TABLE}"\n', "/sn",
                    ("PATCH", f"/api/now/table/{TABLE}/*"),
                    lambda k: f"/api/now/table/{TABLE}/{k}", "PATCH",
                    lambda base, k: None)
VENDORS = (JIRA_NO, JIRA_YES, SERVICENOW)
#: Vendors of one adapter module (their `check_settings` is the module's).
SYSTEMS = ("jira", "servicenow")
OK_JSON = {"Content-Type": "application/json"}


class RequestTap:
    """An ASGI wrapper that records each request body the proxy is sent (what the adapter built)."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.bodies: list[bytes] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks: list[bytes] = []

        async def tapped() -> Any:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                if not message.get("more_body"):
                    self.bodies.append(b"".join(chunks))
            return message

        await self.app(scope, tapped, send)


@dataclass
class Rig:
    vendor: Vendor
    up: H.Upstream
    t: Any
    url: str
    tap: RequestTap
    tmp: Path
    #: The `R.RecordsSpec` this rig's tenant holds (#1366: the run's record and the proxy's port are built from it, not
    #: from the published folders); `R.DERIVED` = what the published `settings/` stands for (`R.derive`); None = NOT imported.
    records: Any = R.DERIVED

    def token(self, mode: str = "rw") -> str:
        return T.token(self.t.tenant_id, {(self.vendor.system, mode)})

    def record(self) -> Any:
        return T.run_record(self.t, self.records)

    def reply(self, key: str, status: int, body: Any = None) -> None:
        self.up.replies[self.vendor.base_path + self.vendor.route(key)] = (
            status, OK_JSON, json.dumps({} if body is None else body).encode())

    def module(self, roster: Any) -> Any:
        return S.mod("systems.verbs").fresh_adapter_module(roster, self.vendor.system)

    def comment(self, roster: Any, key: str, body: str = BODY) -> str | None:
        """The adapter's comment action called straight, as the record leg calls it."""
        ctx = A.ctx_for(self.tmp, self.record(), self.url, self.token())
        return self.module(roster).add_case_comment(ctx, key=key, body=body)

    def read(self, roster: Any, key: str) -> Any:
        """The adapter's read of a case's comments called straight, as the record leg calls it."""
        ctx = A.ctx_for(self.tmp, self.record(), self.url, self.token())
        return getattr(self.module(roster), C.READBACK_ACTION)(ctx, key=key)

    def leg(self, name: str, key: str | None = C.TICKET_KEY) -> dict[str, Any] | None:
        """The record leg at run end over a run whose record names `key`; its receipt."""
        rec = C.CaseRunRecorder(self.tmp / name)
        run = rec.materialize(C.plant_alert(self.tmp / f"in-{name}", key=key))
        write_report(rec.run_dir_at)  # a readable report: the template renders over it
        C.record_leg()(run, tenant=self.record(), defender_dir=DEFENDER,
                       env=run_env(DEFENDER, rec.run_dir_at), request_token=self.token(),
                       proxy_url=self.url)
        return S.receipt(rec.run_dir_at)

    def sent(self) -> list[H.Seen]:
        return list(self.up.seen)


def files_for(v: Vendor, base: str, *, env: str | None = None,
              access: bool = True, leg: bool = False) -> dict[str, str]:
    """Repo files `/connect` leaves for `v`: config.env, access.yaml with the one write route,
    the case-record file (#1345 O5: the alert mapping is a database row, not a repo file; the record leg reads the run's record)."""
    decl = H.declaration(base, scheme=H.basic_scheme(), writes=(v.write,))
    files = A.system_files(v.system, decl, env_extra=v.env)
    if env is not None:
        files[f"settings/systems/{v.system}/config.env"] = env
    if not access:
        files.pop(ACCESS_FILE.format(system=v.system))
    if leg:
        files[f"settings/{C.CASE_RECORD_REL}"] = C.case_record_text(v.system)
    return files


def records_of(v: Vendor, base: str, *, env: str | None = None, access: bool = True, leg: bool = False,
               reads: tuple[tuple[str, str], ...] = (), writes: tuple[tuple[str, str], ...] | None = None) -> R.RecordsSpec:
    """The records of `v` configured as `/connect` leaves it, as DATA (#1366: the run's record and the proxy's port are
    built from these, no folder): its settings (`env`, else the suite's `env_text` plus the vendor's lines), its access
    (`base`, the basic scheme, `reads`, and `writes` -- default the vendor's one write route; none with `access=False`),
    and with `leg` the case record naming it."""
    settings = R.parse_config_env(env if env is not None else A.env_text(v.system, extra=v.env))
    text = (H.declaration(base, scheme=H.basic_scheme(), reads=reads, writes=(v.write,) if writes is None else writes)
            if access else "")
    case = None
    if leg:
        body = yaml.safe_load(C.case_record_text(v.system))["comment"]["body"]
        case = R.CaseSpec(v.system, str(body))
    return R.RecordsSpec({v.system: R.SysSpec(settings, text)}, case)


@contextlib.contextmanager
def planted(tmp: Path, data_root: Path, v: Vendor, *, env: str | None = None,
            access: bool = True, leg: bool = False) -> Iterator[Rig]:
    """`v` configured as `/connect` leaves it (with `leg`, also its case-record file,
    which only the record-leg tests need), the real proxy served in front of a fake upstream
    holding the stored basic credential. Unless a test says otherwise the upstream answers 200. The tenant's records
    (`records_of`) are handed to the run's record and the proxy's port explicitly."""
    from defender.tests.integrations.credential_proxy_1163._target import proxy

    with H.upstream() as up:
        base = v.declared_base(up)
        files = files_for(v, base, env=env, access=access, leg=leg)
        with published_tenant(tmp / "forge", root=data_root, files=files) as t:
            spec = records_of(v, base, env=env, access=access, leg=leg)
            store = H.FakeStore({(t.tenant_id, v.system): T.basic_set(USER, PASSWORD)})
            tap = RequestTap(proxy().create_app(T.deps({t.tenant_id: T.exports_of(t)}, store,
                                                       records={t.tenant_id: spec})))
            with H.serve_asgi(tap) as url:
                yield Rig(v, up, t, url, tap, tmp, spec)
