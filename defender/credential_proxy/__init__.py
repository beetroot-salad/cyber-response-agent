"""The credential-injecting proxy (#1163): the one holder of customer system credentials.

Adapters reach an `http-proxy` system by posting to the proxy with a request token; the proxy
checks the token, the tenant's merged access declaration and the route, applies the stored
credential, sends, passes the reply on as it arrives and audits. The OpenBao store and transit signer/verifier, the token
mint, the request signer (`request_signer`) and the audit sink live here too. Run it with `python -m defender.credential_proxy`."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.credential_proxy._app import (
        PROXY_PATH as PROXY_PATH,
        ProxyDeps as ProxyDeps,
        create_app as create_app,
        create_app_from_config as create_app_from_config,
    )
    from defender.credential_proxy._audit import (
        AUDIT_KEYS as AUDIT_KEYS,
        FileAuditSink as FileAuditSink,
    )
    from defender.credential_proxy._credentials import (
        CredentialSet as CredentialSet,
    )
    from defender.credential_proxy._launcher import (
        TenantRequestSigner as TenantRequestSigner,
        request_signer as request_signer,
        signing_access as signing_access,
    )
    from defender.credential_proxy._openbao import (
        OpenBaoSecrets as OpenBaoSecrets,
        OpenBaoStore as OpenBaoStore,
        TransitVerifier as TransitVerifier,
        store_policies as store_policies,
        transit_key_for as transit_key_for,
    )
    from defender.credential_proxy._tokens import (
        mint_request_token as mint_request_token,
        read_access as read_access,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("PROXY_PATH", "ProxyDeps", "create_app", "create_app_from_config",), "_app"),
    **dict.fromkeys(("AUDIT_KEYS", "FileAuditSink",), "_audit"),
    **dict.fromkeys(("CredentialSet",), "_credentials"),
    **dict.fromkeys(("TenantRequestSigner", "request_signer", "signing_access",), "_launcher"),
    **dict.fromkeys(("OpenBaoSecrets", "OpenBaoStore", "TransitVerifier", "store_policies", "transit_key_for",), "_openbao"),
    **dict.fromkeys(("mint_request_token", "read_access",), "_tokens"),
}

__getattr__ = lazy_door(globals(), _HOMES)
