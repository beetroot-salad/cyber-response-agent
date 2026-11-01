"""#1163 repair (proxy side): the in-process signer outlives its AppRole login. The login token
is short-lived, so a write-back token minted long after run start is still signed, and a
rotation of the tenant's generation in between is followed (A24)."""
from __future__ import annotations

from typing import Any

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

ROLE, SECRET = "role-1163-own", "secret-1163-own"
NEW_ROLE, NEW_SECRET = "role-1163-rotated", "secret-1163-rotated"
TABLE = """\
dispositions:
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
"""


class _Tickets:
    """The `ticket_writer` seam of `run.main`: records each leg's keyword arguments."""

    def __init__(self) -> None:
        self.legs: dict[str, dict[str, Any]] = {}

    def open_case_ticket(self, run: Any, **kw: Any) -> None:
        self.legs["open"] = kw

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.legs["record"] = kw


def test_r8_the_signer_logs_in_again_when_its_login_token_has_expired(tmp_path, data_root):
    """The login token that signed the open leg's write-back token expires before the record
    leg; that leg's write-back token is still signed, with a second login. A1, A7, r7 A20."""
    configs = dict(S.config_texts("t1163"))
    configs["identity"] = A.env_text("identity")
    configs["case-history"] = A.env_text("case-history")
    folder = S.plant(data_root, configs=configs, table=TABLE)
    for system in ("identity", "case-history"):
        for rel, text in H.access_files(system, H.declaration("http://x.invalid/api")).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8")
    fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    records = A.Records(data_root, {S.PLAYGROUND_ID: [fields]})
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    tickets = _Tickets()

    def expire_logins(_run_dir: Any) -> None:
        # runs between the open leg and the record leg: every login so far has expired
        bao.revoked.extend(sign.client_token for sign in bao.signs)

    rec = S.RunRecorder(tmp_path / "run", before_lifecycle=expire_logins)
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), data_root,
                                         update_ticket=True), rec, ticket_writer=tickets,
                              proxy_url="http://proxy.invalid", issuer_transport=bao,
                              directory=records.directory)

    assert (rc, refused) == (0, None)
    assert len(bao.logins) >= 2, "the expired login was replaced by another login"
    assert len(bao.signs) == 2, "open write-back, record write-back (no read token was asked)"
    assert bao.signs[1].client_token != bao.signs[0].client_token
    assert bao.signs[1].key == proxy().transit_key_for(S.PLAYGROUND_ID)
    assert tickets.legs["record"]["request_token"], "the record leg got its write-back token"
    assert A.grant_of(A.claims_of_payload(bao.signs[1].payload)) == [("case-history", "rw")]


def test_r9_a_rotation_between_the_legs_is_followed_by_the_next_login(tmp_path, data_root):
    """The generation rotates, and the old login token dies, between the legs: the record leg's
    login uses the new generation's sign pair (the old file is gone), not a cached one. A24."""
    configs = dict(S.config_texts("t1163"))
    configs["identity"] = A.env_text("identity")
    configs["case-history"] = A.env_text("case-history")
    folder = S.plant(data_root, configs=configs, table=TABLE)
    for system in ("identity", "case-history"):
        for rel, text in H.access_files(system, H.declaration("http://x.invalid/api")).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8")
    old = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE, sign_secret=SECRET)
    new = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=NEW_ROLE,
                       sign_secret=NEW_SECRET, salt="g2")
    records = A.Records(data_root, {S.PLAYGROUND_ID: [old]})
    bao = A.OpenBaoStandIn({ROLE: SECRET, NEW_ROLE: NEW_SECRET})
    tickets = _Tickets()

    def rotate(_run_dir: Any) -> None:
        records.rotate(S.PLAYGROUND_ID, new)
        old["sign_secret_file"].unlink()
        bao.revoked.extend(sign.client_token for sign in bao.signs)

    rec = S.RunRecorder(tmp_path / "run", before_lifecycle=rotate)
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), data_root,
                                         update_ticket=True), rec, ticket_writer=tickets,
                              proxy_url="http://proxy.invalid", issuer_transport=bao,
                              directory=records.directory)

    assert (rc, refused) == (0, None)
    assert bao.logins == [(ROLE, SECRET), (NEW_ROLE, NEW_SECRET)]
    first, second = bao.signs
    assert (bao.role_of(first), bao.role_of(second)) == (ROLE, NEW_ROLE)
    assert tickets.legs["record"]["request_token"], "the record leg got its write-back token"
