"""#1108 P4: the dev compose file and `.gitignore` carry the configuration that lets the issuer
unseal without a human (O12), keeps Forgejo's data on a bind mount (O13), and keeps issuer state
on disk under the repo with deployment facts never in the environment (U4/P-4).

CI-safe configuration checks: they parse `.devcontainer/docker-compose.yml` and ask git what
`.gitignore` ignores; the behaviour is `test_live_dev_issuer.py`'s. Deliberately not pinned (left
to the implementation): where OpenBao's own config lives, the issuer's port, how Forgejo trusts
the dev CA, and the client config file's name.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml  # tests may load YAML raw (tooling/lint/lint_raw_yaml.py excludes tests); a
# compose file may legitimately use `x-` anchors, which `defender._yaml` would refuse.

from defender import _git
from defender._git import REPO_ROOT

COMPOSE = REPO_ROOT / ".devcontainer" / "docker-compose.yml"
COMPOSE_DIR = COMPOSE.parent
KNOWLEDGE_DATA = REPO_ROOT / "playground-knowledge"
ISSUER_STATE = REPO_ROOT / "playground-issuer"
OLD_FORGEJO_VOLUME = "forgejo-data"

_INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}")


# ---------------------------------------------------------------------------------------------
# Small readers of compose's own syntax (not of the policy under test)
# ---------------------------------------------------------------------------------------------

def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _services() -> dict:
    return _compose()["services"]


def _bao() -> dict:
    services = _services()
    assert "openbao" in services, "no `openbao` service in the dev compose file (U1)"
    return services["openbao"]


def _default(value: str) -> str:
    """`value` with every `${VAR:-default}` replaced by its default, as compose resolves it on a
    machine whose `.devcontainer/.env` sets nothing (the team baseline). A `${VAR}` with no
    default resolves to the empty string."""
    return _INTERPOLATION.sub(lambda m: m.group(2) or "", value)


def _environment(service: dict) -> dict[str, str]:
    """A service's `environment`, mapping or `KEY=value` list form."""
    env = service.get("environment") or {}
    if isinstance(env, list):
        return dict(item.split("=", 1) if "=" in item else (item, "") for item in env)
    return {str(k): "" if v is None else str(v) for k, v in env.items()}


def _mounts(service: dict) -> list[tuple[str, str, str]]:
    """`(type, source, target)` of every `volumes` entry, short or long syntax. `type` is
    `bind` for a host path (compose's rule: a source starting `.`, `/` or `~`), else `volume`."""
    out = []
    for entry in service.get("volumes") or []:
        if isinstance(entry, dict):
            source = _default(str(entry.get("source", "")))
            kind = entry.get("type") or ("bind" if source[:1] in "./~" else "volume")
            out.append((kind, source, str(entry.get("target", ""))))
            continue
        parts = _default(str(entry)).split(":")
        if len(parts) == 1:  # an anonymous volume
            out.append(("volume", "", parts[0]))
            continue
        source, target = parts[0], parts[1]
        out.append(("bind" if source[:1] in "./~" else "volume", source, target))
    return out


def _host_path(source: str) -> Path:
    """A bind source as the host path compose resolves (relative to the compose file's folder)."""
    return (COMPOSE_DIR / source).resolve() if not source.startswith("/") else Path(source)


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _version(image: str) -> tuple[int, ...] | None:
    """The `major.minor.patch` an image reference pins at the team baseline, or None."""
    ref = _default(image)
    tag = ref.rsplit(":", 1)[1] if ":" in ref.rsplit("/", 1)[-1] else ""
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    return tuple(int(g) for g in match.groups()) if match else None


def _ignored(paths: list[str]) -> set[str]:
    """Which of `paths` (repo-relative) `.gitignore` ignores, by git's own matcher. `--no-index`
    asks the patterns alone, so a tracked path is judged by them too."""
    out = _git.git(["check-ignore", "--no-index", "--", *paths], cwd=REPO_ROOT, check=False)
    return set(out.splitlines())


# ---------------------------------------------------------------------------------------------
# The issuer service
# ---------------------------------------------------------------------------------------------

def test_compose_has_an_openbao_service_pinned_at_2_4_or_later_O12():
    """The image is pinned to an exact `major.minor.patch` at the team baseline (no `latest`, no
    floating tag). Control: Forgejo's pin reads as a version."""
    assert _version(_services()["forgejo"]["image"]) is not None, "control: the reader parses a pin"
    image = _bao().get("image", "")
    assert "openbao" in _default(image).rsplit(":", 1)[0], f"openbao runs image {image!r}"
    version = _version(image)
    assert version is not None, f"openbao image {image!r} is not pinned to an exact version"
    assert version[:2] >= (2, 4), f"openbao image {image!r} is older than 2.4 (static seal)"


def test_openbao_publishes_no_host_port_O12():
    """The issuer is reachable only on the compose network.
    Positive control on the same field: Forgejo does publish its loopback UI port."""
    assert _services()["forgejo"].get("ports"), "control: forgejo's `ports` is read"
    bao = _bao()
    assert not bao.get("ports"), f"openbao publishes {bao.get('ports')!r} to the host"
    assert bao.get("network_mode") != "host", "openbao shares the host's network"


def test_openbao_state_and_seal_key_live_on_disk_under_playground_issuer_U4():
    """OpenBao's storage, seal key and CA are bound from `<repo>/playground-issuer/`, with no
    named or anonymous volume, so `down -v` cannot destroy them and the operator can back them
    up."""
    mounts = _mounts(_bao())
    binds = [_host_path(src) for kind, src, _ in mounts if kind == "bind"]
    assert any(_under(path, ISSUER_STATE) for path in binds), (
        f"no openbao bind mount under {ISSUER_STATE}: {mounts}")
    volumes = [(src, dst) for kind, src, dst in mounts if kind != "bind"]
    assert not volumes, f"openbao keeps state in docker volumes {volumes}"


def test_openbao_is_not_a_dev_server_and_gets_no_token_by_environment_U4_P4():
    """A real server with file storage and a static seal, not `bao server -dev` (in-memory, root
    token by environment, lost on restart), and no token or seal key handed in by environment.
    An absent `command` is dev mode too: the image's default (Vault's) starts a dev server."""
    bao = _bao()
    command = bao.get("command") or []
    command = command.split() if isinstance(command, str) else [str(c) for c in command]
    assert "server" in command, f"openbao's command {command!r} does not start a server"
    assert not any(c == "-dev" or c.startswith("-dev-") or c.startswith("--dev") for c in command), (
        f"openbao runs as a dev server: {command}")
    env = _environment(bao)
    secretish = [k for k in env if re.search(r"TOKEN|DEV_ROOT|SEAL|SECRET|UNSEAL", k)]
    assert not secretish, f"openbao receives {secretish} through its environment"


# ---------------------------------------------------------------------------------------------
# Forgejo
# ---------------------------------------------------------------------------------------------

def test_forgejo_data_is_bind_mounted_at_playground_knowledge_O13():
    """So `docker compose down -v` and a rebuild cannot delete it (that it survives is the live
    test's)."""
    mounts = _mounts(_services()["forgejo"])
    data = [(kind, src) for kind, src, dst in mounts if dst.rstrip("/") == "/data"]
    assert len(data) == 1, f"forgejo's /data mounts: {data}"
    kind, source = data[0]
    assert kind == "bind", f"forgejo's /data is a {kind} ({source!r}), not a bind mount"
    assert _host_path(source) == KNOWLEDGE_DATA, f"forgejo's /data is {source!r}"


def test_forgejo_uses_no_named_volume_and_down_v_cannot_reach_the_old_one_O13():
    """No Forgejo state stays in a docker volume, and `down -v` (which removes every declared
    named volume that is not `external`) cannot reach the old `forgejo-data` volume: it is
    undeclared or `external: true`."""
    mounts = _mounts(_services()["forgejo"])
    volumes = [(src, dst) for kind, src, dst in mounts if kind != "bind"]
    assert not volumes, f"forgejo still keeps state in docker volumes {volumes}"
    declared = _compose().get("volumes") or {}
    if OLD_FORGEJO_VOLUME in declared:
        old = declared[OLD_FORGEJO_VOLUME]
        why = (f"`{OLD_FORGEJO_VOLUME}` is declared {old!r}: `down -v` would delete the old "
               "data before the operator chose to")
        assert isinstance(old, dict), why
        assert old.get("external") is True, why


def test_forgejo_allows_the_issuer_domain_and_runs_17_or_later_O12():
    """Forgejo gets `FORGEJO__authorized_integration__ALLOWED_DOMAINS` naming the
    issuer's compose-network hostname (the `openbao` service's name, `hostname`,
    `container_name` or a network alias), and runs a Forgejo with Authorized Integrations
    (17+) at the team baseline."""
    forgejo, bao = _services()["forgejo"], _bao()
    version = _version(forgejo["image"])
    assert version is not None, f"forgejo image {forgejo['image']!r} is not pinned"
    assert version[0] >= 17, f"forgejo image {forgejo['image']!r} predates Authorized Integrations"
    env = _environment(forgejo)
    key = "FORGEJO__authorized_integration__ALLOWED_DOMAINS"
    assert key in env, f"forgejo has no {key}"
    allowed = {d.strip().lower() for d in re.split(r"[,\s]+", _default(env[key])) if d.strip()}
    names = {"openbao", str(bao.get("hostname", "")).lower(),
             str(bao.get("container_name", "")).lower()}
    networks = bao.get("networks") or {}
    if isinstance(networks, dict):
        for net in networks.values():
            names.update(a.lower() for a in (net or {}).get("aliases", []) or [])
    names.discard("")
    assert allowed & names, f"{key}={env[key]!r} names none of the issuer's hosts {sorted(names)}"


def test_git_to_forgejo_stays_on_the_compose_network_http_port_3000():
    """Git reaches Forgejo at `http://forgejo:3000` on the compose network: the service keeps
    its name and listens on 3000."""
    forgejo = _services()["forgejo"]
    assert _environment(forgejo).get("FORGEJO__server__HTTP_PORT") == "3000"


# ---------------------------------------------------------------------------------------------
# P-4: deployment facts are file-only, never environment
# ---------------------------------------------------------------------------------------------

_DEPLOYMENT_FACT = re.compile(
    r"BAO|VAULT|OPENBAO|ISSUER|APPROLE|ROLE_ID|SECRET_ID|FORGE_|FORGEJO_TOKEN|AUDIENCE")


def test_the_dev_container_environment_names_no_issuer_or_forge_fact_P4_O8():
    """Issuer and forge facts reach delivery processes by file path only, so the devcontainer's
    compose environment names none. Control: the reader sees the data root it does carry."""
    env = _environment(_services()["devcontainer"])
    assert "DEFENDER_DATA_ROOT" in env, "control: the devcontainer environment is read"
    leaked = sorted(k for k in env if _DEPLOYMENT_FACT.search(k))
    assert not leaked, f"deployment facts in the devcontainer environment: {leaked}"


# ---------------------------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------------------------

# Probe names carry no extension `.gitignore` already ignores (`*.key`, `*.pem`, `*.crt`,
# `*.log`, `.env`), so only a `playground-*` entry can make them ignored.
_KNOWLEDGE_PROBES = [
    "playground-knowledge/gitea/gitea.db",
    "playground-knowledge/git/repositories/tenants/playground.git/HEAD",
]
_ISSUER_PROBES = [
    "playground-issuer/storage/core/_keyring",
    "playground-issuer/seal/unseal",
    "playground-issuer/client/00000000-0000-4000-8000-000000000000/issuer.json",
    "playground-issuer/recovery/keys.json",
]


def test_playground_knowledge_and_playground_issuer_are_gitignored_U2_U4():
    """Forgejo's data and the issuer's seal key, storage, recovery keys and client config can
    never be committed. Control: a sibling name and a tracked source file are not ignored."""
    controls = ["playground-knowledgebase/HEAD", "defender/run.py"]
    ignored = _ignored(_KNOWLEDGE_PROBES + _ISSUER_PROBES + controls)
    assert not ignored & set(controls), f"control paths reported ignored: {ignored & set(controls)}"
    missing = [p for p in _KNOWLEDGE_PROBES + _ISSUER_PROBES if p not in ignored]
    assert not missing, f"not ignored: {missing}"


@pytest.mark.parametrize("name", ["playground-knowledge", "playground-issuer"])
def test_the_bind_mounted_folders_are_not_tracked_U2_U4(name):
    """Nothing under the bind-mounted state folders is tracked in the product repo."""
    tracked = _git.git(["ls-files", "--", name], cwd=REPO_ROOT)
    assert tracked == "", f"tracked under {name}/: {tracked.splitlines()[:5]}"
