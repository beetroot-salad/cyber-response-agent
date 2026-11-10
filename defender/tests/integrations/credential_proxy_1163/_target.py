"""#1163 sketch: every production name these cases need that the design does not name.

Imported at call time, never at collection, so a missing module is each case's own red. Every
name here is a WORKING choice made by the sketch author and listed as a gap in the contract map;
the case that forced it is named beside it.
"""
from __future__ import annotations

import importlib
from typing import Any


def proxy() -> Any:
    """The proxy package (new top-level, place in ORDER undecided). Names used:
    `create_app(ProxyDeps)` (Q1, S1-S6), `ProxyDeps(data_root=, store=, verifier=, audit=[, max_response_bytes=])`
    (A26: the proxy keeps no tenant list; a tenant's exports are `<data_root>/<id>/exports/`;
    `max_response_bytes` is the response cap's seam, O7), `CredentialSet(kind=, fields=, version=)` (Q1; kind stored, r5 A4), `mint_request_token(signer, tenant_id=,
    investigation=, grant=, expires_at=)` (Q1, S6), `OpenBaoStore(addr=, token=, mount=)` (B2),
    `TransitVerifier(addr=, token=)` whose `verify(payload, signature, *, tenant_id)` uses the key
    `transit_key_for(tenant_id)` on the fixed `transit/` mount (B3, A11, A25, A26);
    `store_policies(kv_mount=)` -> `{"writer", "proxy"}` policy texts (B1, A25: no per-tenant
    signing policy; the proxy's is KV read plus `transit/verify/request-token-*`);
    `transit_key_for(tenant_id) -> str`, the tenant's transit key name (the one
    naming rule; tests call it, never recompute it); `FileAuditSink(path)` with `.record(entry)` (A13); and the shipped assembly
    `create_app_from_config(config, **seam)`, `config` a mapping of the operator's settings:
    `openbao_token` (the proxy role's), `kv_mount`, `data_root`, `audit_path` (A13, A26). The
    OpenBao address is the deployment's (https) and is not configuration; `seam` is the test
    seam of r8.3 (`SEAM_ADDR`, `SEAM_TRANSPORT` below)."""
    return importlib.import_module("defender.credential_proxy")


def request_signer(tenant_id: str, *, directory: Any, transport: Any = None) -> Any:
    """`defender.credential_proxy.request_signer(tenant_id, *, directory, transport=None)` (r8.5 A24'): the one public
    builder of the request signer, an object with `sign(payload: bytes) -> str`; building it sends nothing."""
    return proxy().request_signer(tenant_id, directory=directory, transport=transport)


#: The keyword names of `create_app_from_config`'s test seam (r8.3 names a seam taking an address
#: and a transport, not its spelling): a WORKING CHOICE, a gap in the contract map.
SEAM_ADDR = "openbao_addr"
SEAM_TRANSPORT = "transport"
#: The config keys r8.2 A26 and #1412 remove: unknown keys now.
REMOVED_CONFIG_KEYS = ("tenant_keys", "tenant_exports", "transit_mount", "openbao_addr",
                       "max_response_bytes", "data_root")  # #1366: `data_root` is replaced by `records_dsn`


def app_from_config(config: Any, *, addr: str | None = None, transport: Any = None) -> Any:
    """`create_app_from_config(config)` with the test seam set: OpenBao at `addr` (a test's server)
    and/or over `transport` (an `httpx` transport); neither: the deployment's own address."""
    seam: dict[str, Any] = {}
    if addr is not None:
        seam[SEAM_ADDR] = addr
    if transport is not None:
        seam[SEAM_TRANSPORT] = transport
    return proxy().create_app_from_config(config, **seam)


def transit_verifier(addr: str, token: str) -> Any:
    """The proxy's verifier over the fixed `transit/` mount at `addr` (WORKING CHOICE: the
    constructor takes no mount and no key map, A25/A26)."""
    return proxy().TransitVerifier(addr=addr, token=token)


def secrets_writer() -> Any:
    """The API's write-only secret port over OpenBao: `OpenBaoSecrets(addr=, token=, mount=)`
    with the existing `put_credentials` / `has_credentials` (B1)."""
    return importlib.import_module("defender.credential_proxy")


#: The proxy's one endpoint for the http-proxy transport (S1): POST, `Authorization: Bearer
#: <request token>`, JSON `{system, method, url, headers, body}`; answers 200 with JSON
#: `{status, headers, body, fault, detail}`, `fault` one of None, "ConfigFault",
#: "ConfinementFault", "UpstreamFault".
PROXY_PATH = "/v1/request"
#: The access declaration's place in the tenant's settings (design's example path).
ACCESS_FILE = "settings/systems/{system}/access.yaml"
#: The keys of a proxy audit record (r5 A4): `outcome` is `sent <status>` or the fault class;
#: `path` is relative to the declared base; `version` is the system record's version applied (#1366 O7; was `commit`).
AUDIT_KEYS = ("tenant", "system", "investigation", "version", "method", "path", "outcome")


# --- Names the design does not settle (r6 repair 2, F3). Working choices, listed as gaps. ------

def request_access_type() -> Any:
    """`defender.kit.access.RequestAccess`: the run's handle on the proxy (address + request
    token) handed to the lifecycle (O10, A7). Used by test_w2."""
    return importlib.import_module("defender.kit.access").RequestAccess


#: `RunState.access`: the attribute of `defender.investigation.run_state.RunState` that holds the
#: run's `RequestAccess` (test_w2 reads it if present; never assigns it).
RUN_STATE_ACCESS_ATTR = "access"


#: The shipped program `python -m defender.credential_proxy` (O5; test_m1, test_m2): the module
#: run, the environment variables naming its operator config file and port, the config key naming
#: an OpenBao token file, the text it logs when it refuses to start, and its refusal exit code.
PROXY_PROGRAM_MODULE = "defender.credential_proxy"
PROXY_ENV_CONFIG = "DEFENDER_CREDENTIAL_PROXY_CONFIG"
PROXY_ENV_PORT = "DEFENDER_CREDENTIAL_PROXY_PORT"
PROXY_CONFIG_TOKEN_FILE_KEY = "openbao_token_file"
PROXY_REFUSAL_LOG = "credential proxy cannot start"
PROXY_REFUSAL_EXIT = 2
