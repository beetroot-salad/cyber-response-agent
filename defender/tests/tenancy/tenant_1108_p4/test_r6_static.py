"""#1108 P4: static pins on files nothing hermetic executes (the dev compose file, `.dockerignore`,
the issuer provisioning script), each a wrong-but-green variant. Parsing the files as text is the
oracle: the script needs docker and OpenBao to run."""
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


def test_r6_the_script_makes_files_only_and_holds_no_tenant_credential_step():
    """The `provision` subcommand is retired (#1214: the lifecycle service creates a tenant's
    credentials). It must not come back half-way: no subcommand, no OpenBao root token, no
    AppRole secret_id, no tenant.json binding, no `bao` call from this script."""
    text = SCRIPT.read_text(encoding="utf-8")
    for retired in ("provision()", "bind_forge", "tenant.json", "root_token", "secret-id", "operator init",
                    "write_client_config", "ensure_integration"):
        assert retired not in text, f"the script still holds retired provisioning: {retired}"
    usage = re.search(r'die "usage: [^"]*"', text)
    assert usage, "control: the script prints its usage"
    assert "provision <" not in usage.group(0), usage.group(0)


def test_r6_prepare_creates_its_private_files_private():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "umask 077" in _function(text, "prepare")
    assert 'chmod 0400 "$STATE/seal/unseal"' in text
