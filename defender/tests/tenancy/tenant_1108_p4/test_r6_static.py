"""#1108 P4 round 6 — static pins on files nothing hermetic executes (each was a wrong-but-green
variant): what the dev Forgejo may mount from the issuer's state, what a Docker build context
excludes, and the provisioning script's secret hygiene. Parsing the files as text is the oracle:
the script needs docker and OpenBao to run (`test_live_dev_issuer.py` owns that)."""
from __future__ import annotations

import re

from defender._git import REPO_ROOT
from defender.tests.tenancy.tenant_1108_p4.test_dev_compose import (
    ISSUER_STATE,
    KNOWLEDGE_DATA,
    _host_path,
    _mounts,
    _services,
    _under,
)

SCRIPT = REPO_ROOT / ".devcontainer" / "provision-dev-issuer.sh"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"


def test_r6_forgejo_mounts_no_more_of_the_issuers_state_than_its_ca_certificate():
    """Forgejo (which also runs tenant-supplied repository content) is handed the dev CA
    certificate folder `playground-issuer/trust` and nothing else of the issuer's state: not the
    folder itself, not a parent of it (the seal key, the CA key, storage, recovery keys and the
    client config's secret_id live there)."""
    trust = (ISSUER_STATE / "trust").resolve()
    seen_trust = False
    for name, service in _services().items():
        if name != "forgejo":  # the dev container mounts the whole repository by design
            continue
        for kind, source, target in _mounts(service):
            if kind != "bind":
                continue
            host = _host_path(source)
            exposes_state = _under(host, ISSUER_STATE.resolve()) or _under(ISSUER_STATE.resolve(), host)
            if not exposes_state:
                continue
            assert host == trust, (
                f"service {name} mounts {source} -> {target}: more of the issuer's state than "
                "the CA certificate folder")
            seen_trust = True
    assert seen_trust, "control: some service mounts the CA certificate folder"


def test_r6_the_trust_folder_is_filled_with_the_ca_certificate_only():
    text = SCRIPT.read_text(encoding="utf-8")
    into_trust = re.findall(r"\$STATE/trust/([^\s\"']+)", text)
    assert into_trust, "control: the script writes the trust folder"
    assert set(into_trust) == {"dev-issuer-ca.pem"}, into_trust


def test_r6_the_docker_build_context_excludes_the_forge_data_and_the_issuer_state():
    lines = {line.strip() for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()}
    for folder in (KNOWLEDGE_DATA.name, ISSUER_STATE.name):
        assert f"{folder}/" in lines or folder in lines, f".dockerignore lost {folder}/"


def _function(text: str, name: str) -> str:
    start = text.index(f"\n{name}() {{")
    return text[start:text.index("\n}\n", start)]


def test_r6_provisioning_revokes_the_root_token_last():
    body = _function(SCRIPT.read_text(encoding="utf-8"), "provision")
    revokes = [m.start() for m in re.finditer(r'bao "\$t" token revoke -self', body)]
    assert revokes, "provisioning no longer revokes the root token"
    assert all(body.index(step) < revokes[-1] for step in
               ("write_client_config", "bind_forge", "check_main_protected"))


def test_r6_the_issuer_secret_files_are_created_private():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "umask 077" in _function(text, "prepare")
    config = _function(text, "write_client_config")
    assert config.index('chmod 0600 "$config.tmp"') < config.index('mv "$config.tmp"'), (
        "the client config (secret_id) must be made private before it is moved into place")
    assert 'chmod 0400 "$STATE/seal/unseal"' in text
