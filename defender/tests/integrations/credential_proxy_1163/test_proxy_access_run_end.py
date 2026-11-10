"""#1363 O7: a run that loses its access to the credential proxy ends `proxy-access`, its own non-zero
exit class, silent, with no system marked down; a fault with no origin is unchanged. Driven through
`run.main` with the real investigation (`_spec1222.run_alert`), the ProviderDown suite's door."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.investigation import ticket_writer
from defender.kit.faults import ConfigFault
from defender.records import run_end
from defender.systems import system_status
from defender.tests.runtime.providers import _spec1243 as P
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

PROXY_ACCESS = "proxy-access"
#: The new ending's exit code (left to the contract by the design): the next free one in the table.
PROXY_ACCESS_EXIT = 8
LEAD = "l-001"
CORR = "CORR-1363: correlation summary delivered."
#: Names no proxy itself, so an ending that only echoes it does not name the credential proxy.
DETAIL = "PROXY-ACCESS-1363: the request token has expired"


def _proxied_fault(origin: str | None) -> Any:
    """The fault the proxy client raises for a token the proxy refused as expired: a ConfigFault with
    origin `access`; `None` is the same fault from before origins (the control), which today marks the
    system not configured (G17)."""
    def make() -> BaseException:
        fault = ConfigFault(DETAIL)
        if origin is not None:
            fault.origin = origin
        return fault
    return make


def _drive(tmp_path: Path, origin: str | None) -> S.Drive:
    return S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={S.L3: [S.text(CORR)],
               LEAD: [S.query("cmdb", "get-host", {"host": "web-1"}), S.text("Summary: unreached.")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_proxied_fault(origin)))


def test_1363_o7_an_access_fault_mid_run_ends_it_proxy_access_silent_and_non_zero(tmp_path: Path) -> None:
    """The run ends `proxy-access` naming the credential proxy and the detail, writes no report and no
    row for the call, marks no system down, and exits the class's own code. #1363 O7, D4."""
    d = _drive(tmp_path, "access")
    assert d.raised is None, f"the run crashed instead of ending {PROXY_ACCESS}: {d.raised!r}"
    summary = d.summary or {}
    assert summary.get("truncated_by") == PROXY_ACCESS, summary
    reason = str(summary.get("exit_reason") or "")
    assert "credential proxy" in reason.lower() and "PROXY-ACCESS-1363" in reason, reason
    rec = P.sidecar(d.folder)
    assert rec is not None and rec["truncated_by"] == PROXY_ACCESS, rec
    assert not d.paths.report.exists(), "a proxy-access run wrote report.md"
    assert [r for r in d.rows if r.get("system") == "cmdb"] == [], "the lost call wrote a query row"
    assert system_status.down_cause(d.run_state, "cmdb") is None, "our access loss marked cmdb down"
    assert d.breaker.get("total_failures", 0) == 0, d.breaker
    assert d.rc == PROXY_ACCESS_EXIT, d.rc
    assert run_end.exit_code_of(PROXY_ACCESS) == PROXY_ACCESS_EXIT
    assert PROXY_ACCESS_EXIT not in P.TAKEN_EXITS | {P.PROVIDER_DOWN_EXIT}
    assert ticket_writer.comments_on(PROXY_ACCESS, closed_before_cut=False) is False, (
        "a proxy-access run comments (the run-side check is test_r1_a_run_that_will_not_comment_...)")


@pytest.mark.parametrize("origin", [None, "system"], ids=["no-origin", "system"])
def test_1363_o7_control_the_same_fault_not_ours_marks_the_system_down_and_the_run_goes_on(
        tmp_path: Path, origin: str | None) -> None:
    """Positive control on the same channels: the same ConfigFault with no origin, or the system's,
    marks cmdb not configured (G17) and the run reaches its close, exit 0. #1363 O7, N1."""
    d = _drive(tmp_path, origin)
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") != PROXY_ACCESS, d.summary
    assert system_status.down_cause(d.run_state, "cmdb") is not None, "control: the channel shows a down system"
    assert d.rc == 0, d.rc


def test_1363_o7_proxy_access_is_a_word_of_the_run_end_vocabulary() -> None:
    """The ending is one of the run-end words the session store, run end and job end validate. #1363 O7."""
    assert getattr(run_end, "TRUNCATED_BY_PROXY_ACCESS", None) == PROXY_ACCESS
    assert PROXY_ACCESS in run_end.TRUNCATED_BY_VALUES
    assert run_end.parse_record({"truncated_by": PROXY_ACCESS, "closed_before_cut": False}) is not None
