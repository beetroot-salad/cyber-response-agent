"""#1108 P4: the dev compose file and `.gitignore` carry the configuration that lets the issuer
unseal without a human (O12), keeps Forgejo's data on a bind mount (O13), and keeps issuer state
on disk under the repo with deployment facts never in the environment (U4/P-4).

CI-safe configuration checks: they parse `.devcontainer/docker-compose.yml` and ask git what
`.gitignore` ignores; the behaviour is `test_live_dev_issuer.py`'s. Deliberately not pinned (left
to the implementation): where OpenBao's own config lives, the issuer's port, how Forgejo trusts
the dev CA, and the client config file's name.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest
import yaml  # tests may load YAML raw (tooling/lint/lint_raw_yaml.py excludes tests); a
# compose file may legitimately use `x-` anchors, which `defender._yaml` would refuse.

from defender import _git
from defender._git import REPO_ROOT
from defender.tests.identity.test_identity_realm_export import THEME, THEME_NAME, stylesheet_references, theme_properties

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
    assert "openbao" in services, "no `openbao` service in the dev compose file"
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


def _credential_proxy_services() -> dict:
    """Services whose command or entrypoint runs the #1163 credential proxy program."""
    def runs_proxy(svc: dict) -> bool:
        words = [str(svc.get(k, "")) for k in ("command", "entrypoint")]
        return any("credential_proxy" in w for w in words)
    return {name: svc for name, svc in _services().items() if runs_proxy(svc)}


def test_the_credential_proxy_is_a_long_lived_compose_service_off_the_docker_socket_H4():
    """#1163 H4: one compose service runs the proxy, on the compose network only, holding no
    docker socket. Control: the devcontainer service does mount the socket (C11)."""
    devcontainer = _services()["devcontainer"]
    assert any("docker.sock" in str(v) for v in devcontainer.get("volumes", [])), "control"
    proxies = _credential_proxy_services()
    assert len(proxies) == 1, f"services running the credential proxy: {sorted(proxies)}"
    (svc,) = proxies.values()
    assert not any("docker.sock" in str(v) for v in svc.get("volumes", [])), svc.get("volumes")
    assert not svc.get("ports"), f"the proxy publishes {svc.get('ports')!r} to the host"
    assert svc.get("network_mode") != "host"


def test_the_credential_proxy_mounts_the_whole_data_root_and_no_tenant_folder_A26():
    """A26: the proxy keeps no tenant list, so compose gives it the data root itself, once,
    and no per-tenant folder under it. Control: the mount is found."""
    data_root = REPO_ROOT / ".defender-data"
    (svc,) = _credential_proxy_services().values()
    hosts = [_host_path(source) for _kind, source, _target in _mounts(svc)]
    mounted = [h for h in hosts if _under(h, data_root)]
    assert data_root in mounted, "control: the data root is mounted whole"
    assert mounted == [data_root], f"mounts below the data root: {mounted}"


# ---------------------------------------------------------------------------------------------
# #1540 F5/PR5: Keycloak's sign-in theme, whole, holding the product's look the app imports
# ---------------------------------------------------------------------------------------------

FRONTEND = REPO_ROOT / "defender" / "frontend"
THEME_IN_KEYCLOAK = f"/opt/keycloak/themes/{THEME_NAME}"
_BUILD_OUTPUTS = {"node_modules", "dist", "dist-builds", "generated"}


def _theme_stylesheet(theme: Path) -> Path:
    """The theme's own stylesheet: the second entry of `styles` (the first is the parent's)."""
    return theme / "login" / "resources" / theme_properties(theme)["styles"].split()[1]


def _files_below(root: Path, skip: Path | None = None) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file() and not (_BUILD_OUTPUTS & set(p.relative_to(root).parts))
            and not (skip and _under(p, skip))]


def theme_looks(theme: Path = THEME) -> list[Path]:
    """The files the theme's own stylesheet references (`url()`, `@import`), resolved: the product's look (the tokens,
    the illustration), each a file of the theme folder."""
    stylesheet = _theme_stylesheet(theme)
    return [(stylesheet.parent / re.split(r"[?#]", ref)[0]).resolve()
            for ref in stylesheet_references(stylesheet.read_text(encoding="utf-8"))]


def twins_of(sources: list[Path], frontend: Path) -> list[tuple[Path, Path]]:
    """(source, twin) for every non-empty file below `frontend` (build outputs aside) that is byte-identical to a source
    and is not that source itself."""
    found = []
    for source in sources:
        content = source.read_bytes()
        found += [(source, other) for other in _files_below(frontend)
                  if other.resolve() != source.resolve() and other.stat().st_size == len(content) and content
                  and other.read_bytes() == content]
    return found


def check_theme_is_mounted_whole_and_holds_its_looks(compose: dict, compose_dir: Path, theme: Path) -> None:
    """F5/PR5, read statically: compose mounts the theme folder at Keycloak's themes dir and mounts nothing into it (the
    folder alone is the theme); every Keycloak bind source exists; each `url()`/`@import` of the theme's stylesheet
    resolves to a non-empty file of the theme folder."""
    keycloak = compose["services"]["keycloak"]
    mounts = [(source, target) for kind, source, target in _mounts(keycloak) if kind == "bind"]
    hosts = {target: (compose_dir / source).resolve() for source, target in mounts}
    missing = [f"{s} -> {t}" for s, t in mounts if not (compose_dir / s).exists()]
    assert not missing, f"mount sources that do not exist: {missing}"
    assert hosts.get(THEME_IN_KEYCLOAK) == theme.resolve(), f"the theme folder is not mounted at {THEME_IN_KEYCLOAK}: {hosts}"
    inside = sorted(t for t in hosts if t.startswith(THEME_IN_KEYCLOAK + "/"))
    assert inside == [], f"PR5: the theme folder is the whole theme; these are mounted into it: {inside}"
    looks = theme_looks(theme)
    assert looks, "control: the theme's stylesheet references its look"
    for look in looks:
        assert _under(look, theme.resolve()), f"{look}: the stylesheet reaches outside the theme"
        assert look.is_file(), f"{look}: referenced by the theme's stylesheet, but absent"
        assert look.stat().st_size, f"{look}: referenced by the theme's stylesheet, but empty"


def test_1540_f5_the_dev_compose_mounts_the_theme_whole_and_it_holds_its_looks():
    """Keycloak gets the theme folder alone, and every file its stylesheet uses is there and not empty. (F5, PR5)"""
    check_theme_is_mounted_whole_and_holds_its_looks(_compose(), COMPOSE_DIR, THEME)


def _good_world(root: Path) -> tuple[dict, Path, Path]:
    """A synthetic repo: `.devcontainer/` (compose dir), and a theme folder holding its stylesheet and two looks."""
    compose_dir = root / ".devcontainer"
    theme = root / "frontend" / "keycloak-theme"
    resources = theme / "login" / "resources"
    (resources / "css").mkdir(parents=True)
    (resources / "img").mkdir()
    compose_dir.mkdir()
    (theme / "login" / "theme.properties").write_text("parent=keycloak.v2\nstyles=css/styles.css css/own.css\n")
    (resources / "css" / "own.css").write_text(
        '/* url(gone.png) */\n@import "tokens.css";\n.a{background:url("../img/art.svg?v=1")} .b{background:url(data:x)}\n')
    (resources / "img" / "art.svg").write_text("<svg>art</svg>")
    (resources / "css" / "tokens.css").write_text(":root{--c:red}")
    compose = {"services": {"keycloak": {"volumes": [f"../frontend/keycloak-theme:{THEME_IN_KEYCLOAK}:ro"]}}}
    return compose, compose_dir, theme


def test_1540_f5_the_theme_check_accepts_a_good_world_and_refuses_each_break(tmp_path):
    """Positive control, then single breaks: no folder mount, a missing source, a file mounted into the theme, a
    dangling reference, an empty look. (F5, PR5)"""
    compose, compose_dir, theme = _good_world(tmp_path)
    check_theme_is_mounted_whole_and_holds_its_looks(compose, compose_dir, theme)
    css = theme / "login" / "resources" / "css" / "own.css"
    tokens = theme / "login" / "resources" / "css" / "tokens.css"
    volumes = compose["services"]["keycloak"]["volumes"]

    def broken(*, volumes_: list[str] | None = None, css_: str | None = None, tokens_: str | None = None) -> None:
        bad = copy.deepcopy(compose)
        bad["services"]["keycloak"]["volumes"] = volumes_ if volumes_ is not None else volumes
        originals = css.read_text(), tokens.read_text()
        if css_ is not None:
            css.write_text(css_)
        if tokens_ is not None:
            tokens.write_text(tokens_)
        try:
            with pytest.raises(AssertionError):
                check_theme_is_mounted_whole_and_holds_its_looks(bad, compose_dir, theme)
        finally:
            css.write_text(originals[0])
            tokens.write_text(originals[1])

    broken(volumes_=[])  # the theme folder is not mounted
    broken(volumes_=[volumes[0].replace(THEME_IN_KEYCLOAK, "/opt/keycloak/themes/other")])
    broken(volumes_=[*volumes, "../gone.svg:/opt/keycloak/data/x.svg:ro"])  # a source that is not there
    (tmp_path / "frontend" / "art.svg").write_text("<svg>art</svg>")
    broken(volumes_=[*volumes, f"../frontend/art.svg:{THEME_IN_KEYCLOAK}/login/resources/img/art.svg:ro"])  # PR5
    broken(css_=css.read_text().replace("tokens.css", "colours.css"))  # a reference nothing provides
    broken(css_=css.read_text().replace("tokens.css", "../../../../art.svg"))  # a reference outside the theme
    broken(tokens_="")  # an empty placeholder where the look should be


def test_1540_pr5_no_file_of_the_frontend_is_a_twin_of_a_look_of_the_theme():
    """Every file the theme's stylesheet uses exists once under `defender/frontend/`: no byte-identical copy of it
    anywhere there, so the app keeps no copy of the illustration or the tokens and imports the theme's. (PR5)"""
    looks = theme_looks()
    assert len(looks) >= 2, f"the illustration and the tokens are the theme's looks: {looks}"
    assert twins_of(looks, FRONTEND) == []


def test_1540_pr5_the_twin_search_finds_a_copy_anywhere_under_the_frontend_and_ignores_the_source_itself(tmp_path):
    """Self-test of the search: a copy in the app's own folders is found, build outputs and the source are not. (PR5)"""
    frontend = tmp_path / "frontend"
    (frontend / "src" / "assets").mkdir(parents=True)
    (frontend / "dist").mkdir()
    (frontend / "dist-builds").mkdir()
    art = frontend / "art.svg"
    art.write_text("<svg>art</svg>")
    (frontend / "other.svg").write_text("<svg>other</svg>")
    assert twins_of([art], frontend) == []
    (frontend / "dist" / "built.svg").write_text("<svg>art</svg>")
    (frontend / "dist-builds" / "built.svg").write_text("<svg>art</svg>")
    assert twins_of([art], frontend) == [], "a build output is not a copy"
    twin = frontend / "src" / "assets" / "again.svg"
    twin.write_text("<svg>art</svg>")
    assert twins_of([art], frontend) == [(art, twin)]


_CUSTOM_PROPERTY = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")


def test_1540_pr5_the_tokens_are_declared_once():
    """No file of the frontend besides the theme's tokens file declares a custom property that file declares (names read
    from it), so no near copy of the look survives. (PR5)"""
    sheets = [look for look in theme_looks() if look.suffix == ".css"]
    assert sheets, "the tokens are a stylesheet the theme's own stylesheet imports"
    names = {name for sheet in sheets for name in _CUSTOM_PROPERTY.findall(sheet.read_text(encoding="utf-8"))}
    assert names, f"control: the tokens declare custom properties: {sheets}"
    declared_again = []
    for other in _files_below(FRONTEND):
        if other.resolve() in sheets:
            continue
        text = other.read_bytes().decode("utf-8", errors="ignore")
        again = sorted(names & set(_CUSTOM_PROPERTY.findall(text)))
        if again:
            declared_again.append(f"{other.relative_to(FRONTEND)}: {again}")
    assert declared_again == [], f"PR5: the tokens are declared again outside their one file: {declared_again}"
