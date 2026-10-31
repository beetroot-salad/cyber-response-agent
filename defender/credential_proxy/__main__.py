"""Serve the credential proxy (#1163 H4: a long-lived service in dev, the same program in
production, H1).

    python -m defender.credential_proxy

Operator configuration, all read at start:
- `DEFENDER_CREDENTIAL_PROXY_CONFIG` (required): the path of a JSON file holding the mapping
  `create_app_from_config` takes: `openbao_addr`, `openbao_token` (the proxy role's login),
  `kv_mount`, `transit_mount`, `tenant_keys` ({tenant id: transit key}), `tenant_exports`
  ({tenant id: that tenant's `exports/` folder, mounted read-only}), `audit_path` (the
  append-only audit file), and optionally `max_response_bytes` and `upstream_timeout_sec`.
  Instead of `openbao_token` the file may name `openbao_token_file`, a file holding the token.
  The token is read from files only, never from the environment.
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
from defender.kit.faults import ConfigFault

CONFIG_ENV = "DEFENDER_CREDENTIAL_PROXY_CONFIG"
HOST_ENV = "DEFENDER_CREDENTIAL_PROXY_HOST"
PORT_ENV = "DEFENDER_CREDENTIAL_PROXY_PORT"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8411

_logger = logging.getLogger(__name__)


def operator_config(path: Path) -> dict:
    """The configuration mapping in the JSON file at `path`, with `openbao_token_file` read
    into `openbao_token`; `ConfigFault` naming what is wrong (never the token)."""
    try:
        config = json.loads(_io.read_text_utf8(path))
    except (OSError, ValueError) as e:
        raise ConfigFault(f"{path}: not a readable JSON configuration ({type(e).__name__})") from None
    if not isinstance(config, dict):
        raise ConfigFault(f"{path}: the configuration must be a JSON object")
    token_file = config.pop("openbao_token_file", None)
    if token_file is not None:
        if "openbao_token" in config:
            raise ConfigFault(f"{path}: give openbao_token or openbao_token_file, not both")
        try:
            config["openbao_token"] = _io.read_text_utf8(Path(token_file)).strip()
        except (OSError, ValueError) as e:
            raise ConfigFault(f"{token_file}: the OpenBao token file cannot be read "
                              f"({type(e).__name__})") from None
    return config


def main() -> int:
    where = os.environ.get(CONFIG_ENV)
    if not where:
        _logger.error("%s must name the proxy's configuration file", CONFIG_ENV)
        return 2
    try:
        port = int(os.environ.get(PORT_ENV, str(DEFAULT_PORT)))
        app = create_app_from_config(operator_config(Path(where)))
    except ValueError:
        _logger.error("%s must be a port number", PORT_ENV)
        return 2
    except ConfigFault as fault:
        _logger.error("the credential proxy cannot start: %s", fault.detail)
        return 2
    except OSError as e:  # the audit file cannot be opened for append
        _logger.error("the credential proxy cannot start: %s", e)
        return 2
    host = os.environ.get(HOST_ENV, DEFAULT_HOST)
    _logger.info("credential proxy on http://%s:%d", host, port)
    # `log_config=None` keeps uvicorn on the handlers `configure_from_env` installed.
    uvicorn.run(app, host=host, port=port, log_config=None)
    return 0


if __name__ == "__main__":
    configure_from_env()
    sys.exit(main())
