"""A job container's read pass, asked of its per-job host helper over the job socket (#1170 O5, O6, H2): the one
way every in-container caller (the investigation entry, a learning sibling, pre-flight) gets its `RequestAccess`.

The helper signs each pass (the job holds no sign login) for an id it minted, with the grant and lifetime it
decided; `job_socket.PassHolder` holds it and asks again once it is within `PASS_REUSE_MARGIN_SEC` of its expiry. A
refusal (the job fenced, the helper signalled) or a helper that is gone is the asking call's `AdapterFault`, which
the verb layer records as the proxy's own fault (`kit.proxy_client`); nothing is retried here."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from defender import job_socket
from defender.credential_proxy._tokens import PASS_REUSE_MARGIN_SEC
from defender.kit.access import RequestAccess
from defender.kit.faults import AdapterFault


def helper_access(ask: Callable[..., dict[str, Any]], ident: str, proxy_url: str) -> RequestAccess:
    """Where the callers of the run at `ident` get their read pass from the job's helper (`ask`, the job socket's
    client), presented to the proxy at `proxy_url`."""
    held = job_socket.PassHolder(ask, str(ident), margin=PASS_REUSE_MARGIN_SEC)

    def token() -> str:
        try:
            return held.token()
        except job_socket.Refused as refused:
            raise AdapterFault(f"the job's host helper refused a pass ({refused.code}): {refused}") from None
        except (OSError, ValueError, KeyError, TypeError) as lost:
            raise AdapterFault(f"no pass from the job's host helper: {type(lost).__name__}: {lost}") from None

    return RequestAccess(proxy_url, token)
