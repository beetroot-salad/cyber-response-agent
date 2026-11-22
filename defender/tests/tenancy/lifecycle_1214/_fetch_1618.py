"""#1618 (flow 5): the host actor's prepare reads the tenant's knowledge through the fetch child, not a clone.

FORCED: the seam name `HostActor(..., fetch=)` replaces `publish=`; its one shape and the whole seam list are in
`knowledge_1618._support`. Here the seam is `K.Fetch` over the REAL fetch child, served the lifecycle forge's own bare repositories
over a real git listener (`GitHTTP`, which accepts the issuer fake's token for the tenant being fetched). Faults are made by remote
state only: `refuse_next_fetch("down")` points the next ask at a closed port (Forgejo unreachable), `("auth")` makes the listener
reject the next upload-pack; each heals after that one ask.
"""
from __future__ import annotations

import socket
from typing import Any

from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld
from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
from defender.tests.tenancy.tenant_1108_delivery._support import GitHTTP
from defender.lifecycle import HostActor


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class FetchWorld(LifecycleWorld):
    """`LifecycleWorld` whose host actor has the fetch seam (`fetch=`) in place of the first-publish seam."""

    git_listener: GitHTTP | None = None

    def _listener(self) -> GitHTTP:
        if self.git_listener is None:
            self.git_listener = GitHTTP(self.forge.root, token="unset")
        return self.git_listener

    def refuse_next_fetch(self, how: str) -> None:
        """Arm one remote-state fault for the next fetch ask: `down` (the forge's git port is closed) or `auth` (the listener rejects it)."""
        server = self._listener()
        if how == "down":
            self.fetch.once(lambda: self._aim(lambda _t: f"http://127.0.0.1:{_closed_port()}/dead.git"),
                            lambda: self._aim(self._origin))
        else:
            self.fetch.once(lambda: server.refuse.add("git-upload-pack"), lambda: server.refuse.discard("git-upload-pack"))

    @staticmethod
    def _accept(server: GitHTTP, tenant: str) -> None:
        server.token = issuer_token(tenant)

    def _aim(self, origin_of: Any) -> None:
        self.fetch.origin_of = origin_of

    def _origin(self, tenant_id: str) -> str:
        return f"{self._listener().url}/tenants/{tenant_id}.git"

    def new_host(self, tenants: Any, **overrides: Any) -> Any:
        if not hasattr(self, "fetch"):
            server = self._listener()
            self.fetch = K.fetch_seam(None, self.tmp_path / "fetch-work", origin_of=self._origin,
                                      before=lambda tenant: self._accept(server, tenant))
        parts: dict[str, Any] = {
            "forge": self.forge.client(None), "openbao_login": self.openbao.client(None), "git": self.git, "fetch": self.fetch,
            "config": self.config, "clock": self.clock, **overrides}
        return HostActor(tenants, **parts)

    def close(self) -> None:
        if self.git_listener is not None:
            self.git_listener.close()
        super().close()
