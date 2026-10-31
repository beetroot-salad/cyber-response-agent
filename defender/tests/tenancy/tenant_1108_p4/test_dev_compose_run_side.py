"""#1163 the dev compose's credential proxy service: it reads the data root and holds no token.
Reads the compose file's text only (as `test_dev_compose.py` does)."""
from __future__ import annotations

import re

from defender._git import REPO_ROOT
from defender.tests.tenancy.tenant_1108_p4 import test_dev_compose as C

DATA_ROOT = REPO_ROOT / ".defender-data"
#: Environment names that would carry a login to OpenBao or to the proxy's store.
TOKENISH = re.compile(r"TOKEN|SECRET|PASSWORD|ROLE_ID|VAULT|BAO|ROOT", re.IGNORECASE)


def _proxy() -> dict:
    (svc,) = C._credential_proxy_services().values()
    return svc


def _read_only(entry: object) -> bool:
    """Whether one `volumes` entry (short or long syntax) is mounted read-only."""
    if isinstance(entry, dict):
        return bool(entry.get("read_only"))
    parts = str(entry).split(":")
    return len(parts) > 2 and "ro" in parts[2].split(",")


def test_c1_the_proxy_service_mounts_the_data_root_read_only():
    """Every mount of the data root into the proxy service is `:ro`, and there is one. H4, O2."""
    svc = _proxy()
    entries = svc.get("volumes") or []
    mounted = [(e, m) for e, m in zip(entries, C._mounts(svc), strict=True)
               if C._under(C._host_path(m[1]), DATA_ROOT)]
    assert mounted, "the proxy service does not mount the data root"
    writable = [e for e, _ in mounted if not _read_only(e)]
    assert not writable, f"the data root is mounted writable: {writable}"


def test_c2_the_proxy_service_environment_holds_no_token_or_login():
    """No environment name that could carry a login, no value of an OpenBao dev root token, no
    env file; the operator's config path is there. H4, O5."""
    svc = _proxy()
    env = C._environment(svc)
    assert "DEFENDER_CREDENTIAL_PROXY_CONFIG" in env, "positive control: the environment is read"
    assert not [k for k in env if TOKENISH.search(k)], f"token-like names: {sorted(env)}"
    assert not [v for v in env.values() if v.strip().lower() in ("root", "dev-root-token")]
    assert not svc.get("env_file"), "an env file can carry a token the test cannot see"
