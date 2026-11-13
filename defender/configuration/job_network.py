"""The docker network a job container joins (#1170 N5): the one owner of its rule.

A `production` deployment must name the network (`NETWORK_ENV`): docker's default network reaches whatever the host
reaches, OpenBao and the database included when they listen on the host. No deployment may name the host's own network.
A `dev` deployment that names none joins docker's default, as the dev container's jobs daemon expects."""
from __future__ import annotations

import os
from collections.abc import Mapping

from . import _env

NETWORK_ENV = "DEFENDER_JOB_NETWORK"
_HOST_NETWORK = "host"


def job_network(environ: Mapping[str, str] = os.environ) -> str | None:
    """The network's name, None for docker's default (`dev` only), or `ValueError` naming what to set."""
    network = (environ.get(NETWORK_ENV) or "").strip() or None
    if network == _HOST_NETWORK:
        raise ValueError(f"{NETWORK_ENV}={_HOST_NETWORK} would give the job the host's own network; name a network "
                         "that reaches only the credential proxy and the model provider")
    if network is None and _env.deployment() != "dev":
        raise ValueError(f"{NETWORK_ENV} is not set: name the docker network the job reaches the credential proxy and "
                         "the model provider from, with OpenBao and the database off it")
    return network
