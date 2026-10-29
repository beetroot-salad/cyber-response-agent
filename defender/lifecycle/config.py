"""`LifecycleConfig` (#1214 DC-13): what the management service and the host actor are configured
with, read once at process entry (`from_env`) and injected in tests.

Secrets (the forge admin token, the OpenBao management login) are values here, never in a repr;
`from_env` reads each from a file the environment names, never from the environment itself."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from defender import _io
from defender.configuration.issuer import ISSUER_URL, OPENBAO_URL

#: The environment `from_env` reads (the dev container and the hosted units set them). The issuer
#: and OpenBao's address are the deployment's fixed service names (`configuration.issuer`), never
#: read from the environment.
FORGE_URL_ENV = "DEFENDER_LIFECYCLE_FORGE_URL"
FORGE_TOKEN_FILE_ENV = "DEFENDER_LIFECYCLE_FORGE_ADMIN_TOKEN_FILE"
OPENBAO_LOGIN_FILE_ENV = "DEFENDER_LIFECYCLE_OPENBAO_LOGIN_FILE"
OPENBAO_CA_ENV = "DEFENDER_LIFECYCLE_OPENBAO_CA"
INTEGRATION_ENV = "DEFENDER_LIFECYCLE_INTEGRATION_CONTAINER"
SECRETS_DIR_ENV = "DEFENDER_LIFECYCLE_SECRETS_DIR"
POLL_ENV = "DEFENDER_LIFECYCLE_POLL_INTERVAL"
DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"


class ConfigRefused(Exception):
    """The lifecycle cannot be configured as given; the message names what is wrong."""


@dataclass(frozen=True, kw_only=True)
class LifecycleConfig:
    """The lifecycle's settings (DC-13, F-11).

    `issuer_url` is OpenBao's OIDC issuer (https; the integration's `--issuer`, Forgejo fetches its
    discovery document) and `openbao_url` its address (https as well: the AppRole secret and the
    management login never travel in cleartext): the deployment's fixed service names by default
    (`configuration.issuer`), a test's own when it injects them. `integration_command`
    names where the fixed integration command runs (dev: the Forgejo container `docker exec`
    enters). `template_dir` is the committed template tenant.
    `secrets_dir` holds one folder per tenant with one file per installed secret, outside every
    tenant's folder. `poll_interval` is the wait between passes (seconds), `lock_keepalive` the bound
    after which the database drops a dead worker's tenant lock (seconds, RC-2), `teardown_wait` how
    long teardown waits for the host lock after SIGTERM before SIGKILL (seconds). `oidc_key` and
    `token_policy` are the deployment's signing key and its one templated policy."""

    issuer_url: str = ISSUER_URL
    forge_url: str
    forge_admin_token: str = field(repr=False)
    openbao_url: str = OPENBAO_URL
    openbao_login: str = field(repr=False)
    integration_command: str
    template_dir: Path
    secrets_dir: Path
    data_root: Path
    poll_interval: float = 5.0
    lock_keepalive: int = 30
    teardown_wait: float = 10.0
    openbao_ca: Path | None = None
    oidc_key: str = "default"
    token_policy: str = "defender-tenant-token"

    def __post_init__(self) -> None:
        for name in ("template_dir", "secrets_dir", "data_root"):
            object.__setattr__(self, name, Path(getattr(self, name)))
        issuer = urlsplit(self.issuer_url)
        if issuer.scheme != "https" or not issuer.hostname or self.issuer_url.endswith("/"):
            raise ConfigRefused(f"the issuer URL {self.issuer_url!r} must be https, with no trailing slash")
        for name, schemes in (("forge_url", ("http", "https")), ("openbao_url", ("https",))):
            parsed = urlsplit(getattr(self, name))
            if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password:
                raise ConfigRefused(f"{name} {getattr(self, name)!r} must be an {'/'.join(schemes)} address with no credentials")
        if not self.forge_admin_token or not self.openbao_login or not self.integration_command:
            raise ConfigRefused("the forge admin token, the OpenBao login and the integration command are required")
        if not (self.poll_interval > 0 and self.lock_keepalive > 0 and self.teardown_wait > 0):
            raise ConfigRefused("poll_interval, lock_keepalive and teardown_wait are positive numbers of seconds")
        root = self.data_root
        if not (self.secrets_dir.is_absolute() and root.is_absolute()):
            raise ConfigRefused("the secrets directory and the data root are absolute paths")
        # Judged on resolved paths: a `..` or a link must not smuggle the secrets into a tenant's folder.
        secrets, tenants_root = self.secrets_dir.resolve(), root.resolve()
        if secrets == tenants_root or tenants_root in secrets.parents:
            raise ConfigRefused(f"the secrets directory {self.secrets_dir} must lie outside the data root {root}")

    @property
    def ca_cert(self) -> Path | None:
        """`openbao_ca` under the name `forge_credential` reads (the PEM file OpenBao is trusted by)."""
        return self.openbao_ca

    @classmethod
    def from_env(cls, *, template_dir: Path) -> LifecycleConfig:
        """The config of `python -m defender.lifecycle`, from the environment (secrets from the
        files it names)."""
        missing = [n for n in (FORGE_URL_ENV, FORGE_TOKEN_FILE_ENV, OPENBAO_LOGIN_FILE_ENV, INTEGRATION_ENV,
                               SECRETS_DIR_ENV, DATA_ROOT_ENV)
                   if not os.environ.get(n)]
        if missing:
            raise ConfigRefused(f"set {', '.join(missing)}")
        ca = os.environ.get(OPENBAO_CA_ENV)
        try:
            poll = float(os.environ.get(POLL_ENV) or "5")
        except ValueError:
            raise ConfigRefused(f"{POLL_ENV} is not a number of seconds") from None
        return cls(
            forge_url=os.environ[FORGE_URL_ENV],
            forge_admin_token=_secret_file(os.environ[FORGE_TOKEN_FILE_ENV], FORGE_TOKEN_FILE_ENV),
            openbao_login=_secret_file(os.environ[OPENBAO_LOGIN_FILE_ENV], OPENBAO_LOGIN_FILE_ENV),
            integration_command=os.environ[INTEGRATION_ENV], template_dir=template_dir,
            secrets_dir=Path(os.environ[SECRETS_DIR_ENV]), data_root=Path(os.environ[DATA_ROOT_ENV]),
            poll_interval=poll, openbao_ca=Path(ca) if ca else None)


def _secret_file(path: str, variable: str) -> str:
    """The one-line secret in the file `variable` names; the refusal names the file, never its content."""
    try:
        value = _io.read_text_utf8(Path(path)).strip()
    except OSError as unreadable:
        raise ConfigRefused(f"{variable}: {path} could not be read ({unreadable.strerror})") from None
    if not value or "\n" in value:
        raise ConfigRefused(f"{variable}: {path} must hold one line")
    return value
