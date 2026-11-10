"""#1363 r8.4: shared machinery for the `request-cut` exit class (a `request`-origin fault is an
uncharged failed call). No test functions (underscore-prefixed, never collected)."""
from __future__ import annotations

from collections.abc import Callable

from defender.kit.faults import ConfigFault, ConfinementFault, TransportFault

#: The queries-table exit code of a `request`-origin fault. The design leaves the number to the
#: contract (free: outside 0-2, 64-78, 124-255 and not negative). The code stage must use this value,
#: or this constant must be re-pointed: it is the one place the contract names the number.
REQUEST_CUT_EXIT = 3

FAULT_CLASSES = {"ConfigFault": ConfigFault, "TransportFault": TransportFault,
                 "ConfinementFault": ConfinementFault}


def request_fault(kind: type, detail: str) -> Callable[[], BaseException]:
    """A factory for the fault the proxy client raises for one malformed or cut request: `kind`
    carrying `detail` and origin `request`."""
    def make() -> BaseException:
        fault = kind(detail)
        fault.origin = "request"
        return fault
    return make


def real_proxy_request_faults() -> dict[str, tuple[type, str]]:
    """The proxy's own `request`-origin refusals for a request body that was not read, by name:
    `(fault class, detail)` exactly as `credential_proxy._app` words them, read off the proxy's
    parser rather than copied, so a reworded detail is followed."""
    from defender.credential_proxy._app import _broken_reply, _parse_request, _Unread
    from defender.credential_proxy._refusal import Refused

    out: dict[str, tuple[type, str]] = {}
    for name, why in (("over-the-size-limit", _Unread.TOO_LARGE), ("did-not-arrive-in-time", _Unread.TOO_SLOW),
                      ("caller-left", _Unread.PEER_LEFT)):
        try:
            _parse_request(why)
        except Refused as refused:
            out[name] = (FAULT_CLASSES[refused.fault], refused.detail)
        else:
            raise AssertionError(f"the proxy parsed an unread body ({name})")
    # The run itself cut a reply the system had begun to send: the record the proxy builds with
    # `reader_fault=True` (_app ~353/356). The proxy client raises its fault kind (`fault`) from that
    # record (`raise_proxy_fault`), and a reader fault is the run's own cut, so origin `request`.
    cut = _broken_reply("cmdb", 200, "the run was too slow reading it", reader_fault=True)
    assert cut.reader_fault and cut.fault in FAULT_CLASSES, cut
    out["reader-cut-the-reply"] = (FAULT_CLASSES[cut.fault], cut.detail)
    return out
