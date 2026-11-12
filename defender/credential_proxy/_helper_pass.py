"""A job container's read pass, asked of its per-job host helper over the job socket (#1170 O5, O6, H2): the one
way every in-container caller (the investigation entry, a learning sibling, pre-flight) gets its access.

It is the process's one access holder (`RequestAccess`, #1363 O1), whose sign is a `pass` asked of the helper: the
helper signs each pass (the job holds no sign login) for an id it minted, with the grant and lifetime it decided
(`PASS_LIFETIME_SEC`, the holder's own `TOKEN_SEC`), and the holder asks again by its one reuse rule. A refusal (the
job fenced, the helper signalled) or a helper that is gone is the asking call's `AdapterFault`, which the holder
latches as a failed sign and tells its owner, as a run's own failed sign is; nothing is retried here."""
from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from defender import job_socket
from defender.kit.access import RequestAccess
from defender.kit.faults import AdapterFault


def helper_access(ask: Callable[..., dict[str, Any]], ident: str, proxy_url: str, *,
                  clock: Callable[[], float] | None = None,
                  on_fault: Callable[[AdapterFault], None] | None = None) -> RequestAccess:
    """The access holder of the run at `ident`, its passes asked of the job's helper (`ask`, the job socket's client)
    and presented to the proxy at `proxy_url`. `clock` and `on_fault` are the holder's (`RequestAccess`); no `clock` is
    the wall clock as it is when the holder is built, not when this module was imported."""

    def mint(_expires_at: float) -> str:
        try:
            return str(ask("pass", id=str(ident))["token"])
        except job_socket.Refused as refused:
            raise AdapterFault(f"the job's host helper refused a pass ({refused.code}): {refused}") from None
        except (OSError, ValueError, KeyError, TypeError) as lost:
            raise AdapterFault(f"no pass from the job's host helper: {type(lost).__name__}: {lost}") from None

    return RequestAccess(proxy_url, mint, clock=time.time if clock is None else clock, on_fault=on_fault)
