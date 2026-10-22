"""#1108 P4 S-F — the dev compose file and `.gitignore` carry the configuration that makes
O12 (issuer unsealed without a human), O13 (Forgejo data on a bind mount) and U4/P-4
(issuer state on disk under the repo, deployment facts never in the environment) possible.

Structural and CI-safe: these parse `.devcontainer/docker-compose.yml` and ask git which paths
`.gitignore` ignores. They pin configuration only. Whether OpenBao actually unseals after a
restart, whether Forgejo's data actually survives `docker compose down -v`, and whether Forgejo
accepts the issuer (P4-C14/C15) are live behaviours: `test_live_dev_issuer.py` owns them.

What is deliberately NOT pinned here (the design leaves it to the implementer; reported):
where OpenBao's own config (file storage, static seal, TLS listener) lives, the issuer's port,
how Forgejo comes to trust the dev CA (mounted bundle vs environment), and the name of the
issuer client config file under `playground-issuer/client/`.
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
# The issuer service (U1, U4; design "Dev issuer and Forgejo")
# ---------------------------------------------------------------------------------------------

def test_compose_has_an_openbao_service_pinned_at_2_4_or_later_O12():
    """O12/U1: the dev compose file runs OpenBao as service `openbao`, its image pinned to an
    exact `major.minor.patch` of at least 2.4 at the team baseline (no `latest`, no floating
    tag). Positive control on the same reader: Forgejo's pin reads as a version."""
    assert _version(_services()["forgejo"]["image"]) is not None, "control: the reader parses a pin"
    image = _bao().get("image", "")
    assert "openbao" in _default(image).rsplit(":", 1)[0], f"openbao runs image {image!r}"
    version = _version(image)
    assert version is not None, f"openbao image {image!r} is not pinned to an exact version"
    assert version[:2] >= (2, 4), f"openbao image {image!r} is older than 2.4 (static seal)"


def test_openbao_publishes_no_host_port_O12():
    """Design: the issuer has no host port; it is reachable only on the compose network.
    Positive control on the same field: Forgejo does publish its loopback UI port."""
    assert _services()["forgejo"].get("ports"), "control: forgejo's `ports` is read"
    bao = _bao()
    assert not bao.get("ports"), f"openbao publishes {bao.get('ports')!r} to the host"
    assert bao.get("network_mode") != "host", "openbao shares the host's network"


def test_openbao_state_and_seal_key_live_on_disk_under_playground_issuer_U4():
    """U4: OpenBao's storage, static seal key and CA are on disk under
    `<repo>/playground-issuer/` (compose `../playground-issuer`), not in a docker volume: so a
    `down -v` cannot destroy them and the operator can see and back them up. At least one bind
    mount has its source there, and openbao uses no named or anonymous volume."""
    mounts = _mounts(_bao())
    binds = [_host_path(src) for kind, src, _ in mounts if kind == "bind"]
    assert any(_under(path, ISSUER_STATE) for path in binds), (
        f"no openbao bind mount under {ISSUER_STATE}: {mounts}")
    volumes = [(src, dst) for kind, src, dst in mounts if kind != "bind"]
    assert not volumes, f"openbao keeps state in docker volumes {volumes}"


def test_openbao_is_not_a_dev_server_and_gets_no_token_by_environment_U4_P4():
    """The design's issuer is a real server with file storage and a static seal, not `bao server
    -dev` (in-memory, root token by environment, lost on restart — which would break O12's
    restart promise). No root/dev token or seal key is handed in through its environment.
    `command` must be given and start a `server`: the image's default command (inherited from
    the Vault image) is a dev server, so an absent `command` is dev mode too."""
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
# Forgejo (U2, O13; design "Dev issuer and Forgejo")
# ---------------------------------------------------------------------------------------------

def test_forgejo_data_is_bind_mounted_at_playground_knowledge_O13():
    """O13/U2: Forgejo's `/data` is the host folder `<repo>/playground-knowledge/` (compose
    `../playground-knowledge`), so `docker compose down -v` and a rebuild cannot delete it.
    (That it survives is live; this pins the mount that makes it possible.)"""
    mounts = _mounts(_services()["forgejo"])
    data = [(kind, src) for kind, src, dst in mounts if dst.rstrip("/") == "/data"]
    assert len(data) == 1, f"forgejo's /data mounts: {data}"
    kind, source = data[0]
    assert kind == "bind", f"forgejo's /data is a {kind} ({source!r}), not a bind mount"
    assert _host_path(source) == KNOWLEDGE_DATA, f"forgejo's /data is {source!r}"


def test_forgejo_uses_no_named_volume_and_down_v_cannot_reach_the_old_one_O13():
    """O13: no Forgejo state stays in a docker volume, and the old `forgejo-data` volume is kept
    until the operator deletes it. `docker compose down -v` removes every named volume the file
    declares (and does not remove an `external` one), so the old volume is either no longer
    declared or declared `external: true` (e.g. for a one-time migration)."""
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
    """Design: Forgejo gets `FORGEJO__authorized_integration__ALLOWED_DOMAINS` naming the
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
    """Design: git to Forgejo stays `http://forgejo:3000` on the compose network in dev — the
    service keeps its name and listens on 3000 inside the network."""
    forgejo = _services()["forgejo"]
    assert _environment(forgejo).get("FORGEJO__server__HTTP_PORT") == "3000"


# ---------------------------------------------------------------------------------------------
# P-4: deployment facts are file-only, never environment
# ---------------------------------------------------------------------------------------------

_DEPLOYMENT_FACT = re.compile(
    r"BAO|VAULT|OPENBAO|ISSUER|APPROLE|ROLE_ID|SECRET_ID|FORGE_|FORGEJO_TOKEN|AUDIENCE")


def test_the_dev_container_environment_names_no_issuer_or_forge_fact_P4_O8():
    """P-4/O8: issuer URL, CA, AppRole `role_id`/`secret_id` and the forge binding reach delivery
    processes by file path only, never through an environment variable. The devcontainer
    service's compose environment names none of them. Positive control: the same reader sees
    the data root it does carry."""
    env = _environment(_services()["devcontainer"])
    assert "DEFENDER_DATA_ROOT" in env, "control: the devcontainer environment is read"
    leaked = sorted(k for k in env if _DEPLOYMENT_FACT.search(k))
    assert not leaked, f"deployment facts in the devcontainer environment: {leaked}"


# ---------------------------------------------------------------------------------------------
# .gitignore (U2, U4)
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
    "playground-issuer/client/issuer.json",
    "playground-issuer/recovery/keys.json",
]


def test_playground_knowledge_and_playground_issuer_are_gitignored_U2_U4():
    """U2/U4: Forgejo's data and the issuer's seal key, storage, recovery keys and client
    config (`secret_id`) can never be committed: git ignores everything below
    `playground-knowledge/` and `playground-issuer/`. Positive control on the same matcher: a
    sibling name and a tracked source file are not ignored."""
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
