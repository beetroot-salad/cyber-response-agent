"""#1537 (design r3.1, "One classifier for refusals"): the one table of fault shapes and the cause each is counted as.

The loop's tests drive each row through every counting path (in-review reconcile, lapsed recovery, the delivery not
opening) and the migration's test backfills the text each row parks with (`note_refusal` writes "the forge refused N times:
<fault text>"), so one table says what a 401, a 403, a statusless credential failure, a misconfiguration and so on
are. NO test functions, NO policy: `cause` is the design's answer, `park_text` is an observed text.
"""
from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from typing import Any

CREDENTIAL = "forge_credential_refused"
UNAVAILABLE = "delivery_unavailable"
REFUSED = "forge_refused"
#: What `note_refusal` writes ahead of the fault's text when the ceiling parks the batch.
PARK = "the forge refused 3 times: "


_STATUS_LINES = {401: "401 Unauthorized", 403: "403 Forbidden", 404: "404 Not Found", 422: "422 Unprocessable Entity"}
_MORE = "For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/"
_OPEN = "the tenant {tenant}'s delivery refused: "


def _read(status: int, path: str) -> str:
    return (f"Forgejo GET failed: Client error '{_STATUS_LINES[status]}' for url 'http://forge.invalid/api/v1/repos/tenants/fixture/"
            f"{path}' {_MORE}{status}")


@dataclasses.dataclass(frozen=True)
class Fault:
    name: str
    cause: str
    #: The status the forge answers a read with (reconcile, recovery); None: a fault no forge answer carries.
    forge_status: int | None = None
    #: How the delivery's open fails at its edge: attributes set on the tenant's issuer fake (`status`, `body`) ...
    issuer: dict[str, Any] | None = None
    #: ... or a named step: `secret_store:<status>` (the AppRole login answers it), `secret_file_gone`, `secret_file_empty`, `no_wiring`.
    step: str | None = None
    #: What the reason of a park by this fault says after the park's prefix, by the path that counted it: `reviews`, `pulls`
    #: (the forge's refused read) or `open` (the delivery not opening), as the real paths wrote it (probed 2026-11-17) with the
    #: forge's address, the tenant id (`{tenant}`) and the secret file (`{file}`) normalised. The migration backfills these.
    texts: dict[str, str] = dataclasses.field(default_factory=dict)

    def park_text(self, path: str) -> str:
        return PARK + self.texts[path]


def _forge(status: int, cause: str, **kw: Any) -> Fault:
    return Fault(str(status), cause, forge_status=status, texts={
        "reviews": _read(status, "pulls/7/reviews?page=1&limit=50"), "pulls": _read(status, "pulls?state=all&page=1&limit=50"),
        **kw.pop("texts", {})}, **kw)


FAULTS: tuple[Fault, ...] = (
    _forge(401, CREDENTIAL, issuer={"status": 401}, texts={"open": _OPEN + "Vault identity token request failed"}),
    _forge(403, CREDENTIAL, issuer={"status": 403}, texts={"open": _OPEN + "Vault identity token request failed"}),
    _forge(404, REFUSED),
    _forge(422, REFUSED),
    Fault("statusless credential failure", CREDENTIAL, issuer={"body": {"data": {}}},
          texts={"open": _OPEN + "Vault returned no identity token"}),
    Fault("secret store 403", CREDENTIAL, step="secret_store:403", texts={"open": (
        _OPEN + "the issuer AppRole login failed: OpenBao refused tenant {tenant}'s delivery AppRole login (HTTP 403)")}),
    Fault("misconfigured credential", UNAVAILABLE, step="secret_file_gone", texts={"open": (
        _OPEN + "tenant {tenant}'s delivery secret file {file} could not be read: No such file or directory")}),
    Fault("secret file holds no secret id", UNAVAILABLE, step="secret_file_empty", texts={"open": (
        _OPEN + "tenant {tenant}'s delivery secret file {file} does not hold one secret id")}),
    Fault("no usable forge wiring", UNAVAILABLE, step="no_wiring", texts={"open": (
        "the tenant {tenant} has no usable forge wiring: tenant {tenant} has no forge wiring recorded: its repository is not "
        "bound to a forge")}),
)
FORGE_FAULTS = tuple(f for f in FAULTS if f.forge_status is not None)
OPEN_FAULTS = tuple(f for f in FAULTS if "open" in f.texts)


def normalised(reason: str, tenant: str) -> str:
    """A stored park reason with the parts that differ by run (the forge's port, the tenant id, the secret file) made fixed."""
    import re

    text = re.sub(r"http://127\.0\.0\.1:\d+", "http://forge.invalid", reason).replace(tenant, "{tenant}")
    return re.sub(r"secret file \S+ (could not|does not)", r"secret file {file} \1", text)


def secret_store_credential(t: Any, scene: Any, status: int) -> Any:
    """The tenant's real credential provider over the fake OpenBao of `scene` (a `minting`), with the AppRole login answering
    `status`: the secret store's refusal, met at the issuer transport."""
    import httpx

    from defender.learning.author.version_control import forge_credential

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(status, json={"errors": ["permission denied"]})
        return scene.bao.handle(request)

    config = SimpleNamespace(issuer_url="https://openbao.test/v1/identity/oidc", openbao_url="https://openbao.test", ca_cert=None)
    return forge_credential(t.tenant_id, "drain", directory=t.directory, config=config, transport=httpx.MockTransport(handle))
