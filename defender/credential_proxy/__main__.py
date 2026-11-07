"""Serve the credential proxy (#1163 H4: a long-lived service in dev, the same program in
production, H1).

    python -m defender.credential_proxy

Operator configuration, all read at start:
- `DEFENDER_CREDENTIAL_PROXY_CONFIG` (required): the path of a JSON file holding the mapping
  `create_app_from_config` takes: `openbao_token` (the proxy role's login) or
  `openbao_token_file` (a file holding it), `kv_mount`, `data_root` (the data root, mounted
  read-only: each tenant's exports are `<data_root>/<tenant id>/exports/`, so the proxy keeps no
  tenant list), `audit_path` (the append-only audit file), and optionally
  `upstream_timeout_sec`. OpenBao is the deployment's fixed address and transit mount, not
  configuration; a config still naming `openbao_addr`, `transit_mount`, `tenant_keys`,
  `tenant_exports` or `max_response_bytes` refuses to start (#1163 A26, #1412). The token is read from files only, never from
  the environment.
- `DEFENDER_CREDENTIAL_PROXY_HOST` (default `127.0.0.1`; a compose service sets `0.0.0.0` to
  listen on the compose network) and `DEFENDER_CREDENTIAL_PROXY_PORT` (default `8411`).
- Logging: as every defender program (`defender._log.configure_from_env`).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import uvicorn

from defender import _io
from defender._log import configure_from_env
from defender.credential_proxy._app import create_app_from_config
from defender.credential_proxy._connections import DeliveryLimited
from defender.kit.faults import ConfigFault

CONFIG_ENV = "DEFENDER_CREDENTIAL_PROXY_CONFIG"
HOST_ENV = "DEFENDER_CREDENTIAL_PROXY_HOST"
PORT_ENV = "DEFENDER_CREDENTIAL_PROXY_PORT"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8411

_logger = logging.getLogger(__name__)


def operator_config(path: Path) -> dict:
    """The configuration mapping in the JSON file at `path`; `ConfigFault` naming what is wrong."""
    try:
        config = json.loads(_io.read_text_utf8(path))
    except (OSError, ValueError) as e:
        raise ConfigFault(f"{path}: not a readable JSON configuration ({type(e).__name__})") from None
    if not isinstance(config, dict):
        raise ConfigFault(f"{path}: the configuration must be a JSON object")
    return config


def main() -> int:
    where = os.environ.get(CONFIG_ENV)
    if not where:
        _logger.error("%s must name the proxy's configuration file", CONFIG_ENV)
        return 2
    try:
        port = int(os.environ.get(PORT_ENV, str(DEFAULT_PORT)))
    except ValueError:
        _logger.error("%s must be a port number", PORT_ENV)
        return 2
    try:
        app = create_app_from_config(operator_config(Path(where)))
    except ConfigFault as fault:
        _logger.error("the credential proxy cannot start: %s", fault.detail)
        return 2
    except OSError as e:  # the audit file cannot be opened for append
        _logger.error("the credential proxy cannot start: %s", e)
        return 2
    host = os.environ.get(HOST_ENV, DEFAULT_HOST)
    _logger.info("credential proxy on http://%s:%d", host, port)
    # `log_config=None` keeps uvicorn on the handlers `configure_from_env` installed.
    uvicorn.run(app, host=host, port=port, log_config=None, http=DeliveryLimited)
    return 0


if __name__ == "__main__":
    configure_from_env()
    sys.exit(main())
