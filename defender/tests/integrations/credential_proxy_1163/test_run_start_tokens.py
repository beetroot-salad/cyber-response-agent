"""#1163 run start mints the run's tokens after the run copy is taken: a read token for the
query tool and a write-back token for the ticket writer, each on its own carrier."""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
"""


class TicketRecorder:
    """The `ticket_writer` seam of `run.main`: records each leg's keyword arguments."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def open_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(("open", kw))

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(("record", kw))


def _plant(data_root, *, identity_on_proxy: bool) -> None:
    configs = dict(S.config_texts("t1163"))
    if identity_on_proxy:
        configs["identity"] = H.HTTP_PROXY_IDENTITY_ENV
    folder = S.plant(data_root, configs=configs, table=TABLE)
    if identity_on_proxy:
        for rel, text in H.access_files(
                "identity", H.declaration("http://identity.invalid/")).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8")


def test_r1_run_start_mints_a_read_token_and_a_write_back_token(tmp_path, data_root, caplog):
    """The lifecycle gets a read token over the run's granted systems; the ticket writer gets
    `rw` on the ticket system only; both name this tenant and run; neither leaks. O8, O10, O4."""
    caplog.set_level(logging.DEBUG)
    _plant(data_root, identity_on_proxy=True)
    rec, tickets, signer = S.RunRecorder(tmp_path / "run"), TicketRecorder(), H.FakeSigner()
    alert = S.plant_alert(tmp_path / "in")
    rc, refused = S.drive_run(S.run_argv(alert, data_root, update_ticket=True), rec,
                              ticket_writer=tickets, signer=signer)

    assert refused is None, refused
    assert rc == 0
    assert len(signer.payloads) == 2
    life = rec.lifecycle_calls[0]
    read = H.claims_of(life["read_token"])
    write_back = H.claims_of(dict(tickets.calls)["open"]["request_token"])
    assert dict(tickets.calls)["record"]["request_token"] == dict(tickets.calls)["open"][
        "request_token"]
    run_id = rec.run_dir_at.name
    assert {k: read[k] for k in ("tenant", "investigation")} == {
        "tenant": S.PLAYGROUND_ID, "investigation": run_id}
    assert sorted(map(tuple, read["grant"])) == [("cmdb", "r"), ("identity", "r")]
    assert {k: write_back[k] for k in ("tenant", "investigation")} == {
        "tenant": S.PLAYGROUND_ID, "investigation": run_id}
    assert [tuple(g) for g in write_back["grant"]] == [("case-history", "rw")]
    now = datetime.now(UTC).timestamp()
    assert read["exp"] > now
    assert write_back["exp"] > now

    for tok in (life["read_token"], dict(tickets.calls)["open"]["request_token"]):
        assert tok not in repr(life["tenant"]), "a token sits on the shared tenant record"
        assert tok not in caplog.text
        assert tok not in H.text_under(rec.run_dir_at)


def test_r2_a_run_with_no_http_proxy_system_mints_nothing(tmp_path, data_root):
    """Probe (open in the design): a run none of whose systems is `http-proxy` never reaches the
    signer, so existing replays need no OpenBao. Working expectation, not a design decision."""
    _plant(data_root, identity_on_proxy=False)
    rec, tickets, signer = S.RunRecorder(tmp_path / "run"), TicketRecorder(), H.FakeSigner()
    alert = S.plant_alert(tmp_path / "in")
    rc, refused = S.drive_run(S.run_argv(alert, data_root, update_ticket=True), rec,
                              ticket_writer=tickets, signer=signer)

    assert refused is None, refused
    assert rc == 0
    assert signer.payloads == []
    assert rec.lifecycle_calls[0].get("read_token") is None
