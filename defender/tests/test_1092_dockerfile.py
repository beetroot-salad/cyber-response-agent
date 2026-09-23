"""#1092 — the shape of `defender/box.Dockerfile` (M1, F1, MF4) and the `box` extra (M2).

Static demands over the recipe's TEXT: O8 keys on the digest pin and the pinned uv binary,
O7 on what is copied in (nothing, since #1097) and what installer is taken out, O1 on the
extra and its lock entry, #1097 O4 on the install step: the committed `box-requirements.txt`
bind-mounted into the one `RUN` that also mounts uv, installed hash-checked and unresolved.
What the built image then IS — the installed distributions, the absent installers, the
compiled bytecode — is `test_1092_box_image_live.py`'s, against a real daemon.
"""
from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

from defender.tests._spec1092 import DEFENDER, DOCKERFILE

_FROM_DIGEST = re.compile(r"^FROM\s+python:3\.11-slim@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?\s*$")
#: The one way uv reaches the recipe: lent to the sync's RUN as a bind mount from its pinned
#: image (a version AND a digest), never COPYed into a layer of the image (#1095).
_UV_MOUNT = re.compile(
    r"--mount=type=bind,from=ghcr\.io/astral-sh/uv:(?P<version>[^@,\s]+)(@sha256:[0-9a-f]{64})?,source=/uv,target=/bin/uv\b"
)
_EXPLICIT_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def _instructions(path: Path = DOCKERFILE) -> list[str]:
    """The Dockerfile's instructions, one per entry, line continuations joined and comment
    lines dropped (a `#` inside a RUN's shell text is kept — only whole comment lines go)."""
    assert path.is_file(), f"{path} does not exist"
    joined: list[str] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not pending and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        joined.append((pending + line).strip())
        pending = ""
    if pending:
        joined.append(pending.strip())
    return joined


def _index_of(instructions: list[str], needle: str) -> int:
    hits = [i for i, ins in enumerate(instructions) if needle in ins]
    assert len(hits) == 1, f"expected exactly one instruction containing {needle!r}, got {hits}"
    return hits[0]


def _install_at(instructions: list[str]) -> int:
    """The index of THE install step: the one `RUN` uv is lent to (d12)."""
    hits = [i for i, ins in enumerate(instructions) if ins.startswith("RUN ") and "astral-sh/uv" in ins]
    assert len(hits) == 1, f"expected exactly one RUN mounting uv, got {hits}"
    return hits[0]


def _run_parts(instruction: str) -> tuple[list[dict[str, str]], list[str]]:
    """A `RUN` split into its `--mount=` options (each a `key=value` dict; a bare flag maps to
    "") and the shell words it runs, as `shlex` splits them."""
    assert instruction.startswith("RUN "), instruction
    words = shlex.split(instruction[len("RUN "):])
    mounts: list[dict[str, str]] = []
    while words and words[0].startswith("--"):
        flag = words.pop(0)
        if flag.startswith("--mount="):
            opts = {}
            for part in flag[len("--mount="):].split(","):
                key, _, value = part.partition("=")
                opts[key] = value
            mounts.append(opts)
    return mounts, words


def _requirement_files(command: list[str]) -> list[str]:
    """Every `-r`/`--requirement` argument of the install command, in order."""
    out: list[str] = []
    for i, word in enumerate(command):
        if word in ("-r", "--requirement") and i + 1 < len(command):
            out.append(command[i + 1])
        elif word.startswith("--requirement="):
            out.append(word.split("=", 1)[1])
        elif word.startswith("-r") and len(word) > 2:
            out.append(word[2:])
    return out


def _context_list_mount(mounts: list[dict[str, str]]) -> dict[str, str]:
    """The one mount lending the build context's `box-requirements.txt` to the step — a bind
    with no `from=` (so its source is the context, `defender/` — #1098)."""
    hits = [
        m for m in mounts
        if m.get("type", "bind") == "bind" and "from" not in m
        and m.get("source", m.get("src", "")).lstrip("./") == "box-requirements.txt"
    ]
    assert len(hits) == 1, f"expected one context bind of box-requirements.txt, got {mounts}"
    return hits[0]


# ---- d11 -------------------------------------------------------------------------------------
def test_the_dockerfile_pins_its_base_by_sha256_digest():
    """The Dockerfile's base line is `FROM python:3.11-slim@sha256:<64 hex>`, a digest pin
    and not a floating tag; every `FROM` in the file is digest-pinned."""
    froms = [ins for ins in _instructions() if ins.startswith("FROM ")]
    assert froms, "no FROM instruction"
    assert _FROM_DIGEST.match(froms[0]), froms[0]
    for ins in froms:
        assert "@sha256:" in ins, ins


# ---- d12 (amended by #1095: mounted, never copied) ---------------------------------------------
def test_the_dockerfile_copies_a_version_pinned_uv_binary_and_never_pip_installs():
    """The Dockerfile obtains uv only as a bind MOUNT on the install's `RUN` — `--mount=type=bind,
    from=ghcr.io/astral-sh/uv:<explicit version>@sha256:<digest>,source=/uv,target=/bin/uv`
    (a version and a digest — UVPIN #88), never `latest` — so the binary is on the path of
    that one step and enters no layer: no `COPY --from` of uv anywhere, nothing to remove
    afterwards, and no `pip install` of anything (uv's own `uv pip install` is the install
    step, #1097 — pip the installer never runs).

    # rejected: `COPY --from … /uv /bin/uv` plus a final `RUN rm -f /bin/uv` (the recipe as
    # first written): the copy is a 45 MB layer every daemon stores and `docker save` still
    # yields; the `rm` only masks it in the merged view (#1095 finding 4)."""
    instructions = _instructions()
    uv_sites = [ins for ins in instructions if "astral-sh/uv" in ins]
    assert len(uv_sites) == 1, uv_sites
    assert uv_sites[0].startswith("RUN "), uv_sites[0]
    m = _UV_MOUNT.search(uv_sites[0])
    assert m, uv_sites[0]
    assert _EXPLICIT_VERSION.match(m.group("version")), m.group("version")
    assert "@sha256:" in m.group(0), "the uv mount is not digest-pinned (UVPIN #88)"
    assert "uv pip install" in uv_sites[0], "uv is mounted on some step other than the install"
    for ins in instructions:
        assert not (ins.startswith("COPY ") and "--from=" in ins), f"a binary copied into a layer: {ins}"
        # pip the installer, never uv's pip interface (#1097: `uv pip install` IS the install).
        assert not re.search(r"(?<!\buv )\bpip3?\s+install\b", ins), ins
        assert "get-pip" not in ins, ins


# ---- d13 (#1097: negative; positive control in the same test — the list IS bind-mounted) -----------
def test_the_dockerfile_copies_nothing_from_the_build_context():
    """The Dockerfile has no `COPY` and no `ADD` at all — no manifest, no lock, no source tree,
    no `.env` enters a layer (#1097 M2) — while the install step still reads the build
    context: it bind-mounts `box-requirements.txt` from it (no `from=`) and installs from the
    mount's target, so the recipe is not simply empty of inputs.

    # rejected: `COPY pyproject.toml uv.lock` + `uv sync` (the #1092 recipe): it put two
    # manifests in the image and named the image from files whose edits mostly cannot change
    # it (#1097 O1)."""
    instructions = _instructions()
    assert [ins for ins in instructions if ins.startswith(("COPY ", "ADD "))] == []
    mounts, command = _run_parts(instructions[_install_at(instructions)])
    target = _context_list_mount(mounts).get("target", _context_list_mount(mounts).get("dst"))
    assert target, mounts
    assert _requirement_files(command) == [target], (target, command)
    # No OTHER step reaches into the context either: a second `RUN --mount` of the context
    # (`source=.`) could `cp` the manifests or the source tree into a layer with no COPY at all
    # (#1097 adversary H6). Every bind without `from=`, in every RUN, is the one list mount.
    context_binds = [
        m for ins in instructions if ins.startswith("RUN ")
        for m in _run_parts(ins)[0]
        if m.get("type", "bind") == "bind" and "from" not in m
    ]
    assert context_binds == [_context_list_mount(mounts)], context_binds


# ---- d14 (#1097 O4) -----------------------------------------------------------------------------
def test_the_install_step_installs_exactly_the_mounted_list_hash_checked_unresolved_into_the_system_python():
    """The one `RUN` uv is lent to runs `uv pip install` over exactly one requirement file —
    the target of its bind mount of the context's `box-requirements.txt` — with `--system`
    (bare `python3` on the box's PATH is the interpreter every shim runs; no venv), with
    `--require-hashes` (every download verified against the list's recorded hash), with
    `--no-deps` (nothing outside the list is resolved), with `--strict`, and with
    `UV_COMPILE_BYTECODE=1` set for that step (the box's mount is read-only, so nothing could
    compile `.pyc`s at import time); it no longer runs `uv sync`, and no `ENV` instruction
    leaks an install-time variable into the image (O7-SHAPE #60).

    # rejected: `uv sync --locked --inexact` from copied manifests (the #1092 recipe) — the
    # freshness check `--locked` gave moves to the drift test (#1097 M4); `uv pip install`
    # never prunes, so the base's `packaging` survives the way `--inexact` kept it."""
    instructions = _instructions()
    mounts, command = _run_parts(instructions[_install_at(instructions)])
    joined = " ".join(command)
    assert "uv pip install" in joined, command
    assert "uv sync" not in joined, command
    target = _context_list_mount(mounts).get("target", _context_list_mount(mounts).get("dst"))
    assert target, mounts
    assert _requirement_files(command) == [target], (target, command)
    # The step's WHOLE command, not the presence of each wanted flag: uv takes the last of a
    # flag and its negation, so `--require-hashes … --no-require-hashes` would pass a presence
    # check while installing unverified downloads (#1097 adversary H1). Flag order is free;
    # nothing else may ride along — no negation, no second command, no second list.
    assert command[:4] == ["UV_COMPILE_BYTECODE=1", "uv", "pip", "install"], command
    install_args = command[4:]
    r_at = install_args.index("-r")
    flags = install_args[:r_at] + install_args[r_at + 2:]
    assert install_args[r_at + 1] == target, (target, command)
    assert sorted(flags) == sorted(["--system", "--require-hashes", "--no-deps", "--strict"]), command
    assert not any(ins.startswith("ENV ") for ins in instructions), "an ENV instruction"


# ---- d15 -------------------------------------------------------------------------------------
def test_the_dockerfile_uninstalls_pip_setuptools_and_wheel_after_the_install_and_names_packaging_as_kept():
    """After the install, the Dockerfile uninstalls `pip`, `setuptools` and `wheel` from
    `/usr/local` and names `packaging` as the base package it keeps (`uv pip install` never
    prunes the base's own site-packages — #1097)."""
    instructions = _instructions()
    sync_at = _install_at(instructions)
    uninstall_at = _index_of(instructions, "uninstall")
    uninstall = instructions[uninstall_at]
    for dist in ("pip", "setuptools", "wheel"):
        assert re.search(rf"\b{dist}\b", uninstall), (dist, uninstall)
    assert sync_at < uninstall_at, (sync_at, uninstall_at)
    assert "packaging" in DOCKERFILE.read_text(encoding="utf-8"), "packaging is not named as kept"


# ---- MF4: the ensurepip wheels go too ----------------------------------------------------------
def test_the_dockerfile_removes_ensurepips_bundled_wheels_after_the_install():
    """After the install, the Dockerfile removes `ensurepip/_bundled` — the two wheels the base
    ships that survive the pip/setuptools/wheel uninstall and restore a working offline `pip`
    into the tmpfs (G17) — with an `rm -rf` of a path ending in `ensurepip/_bundled`; the
    `ensurepip` module itself stays."""
    instructions = _instructions()
    sync_at = _install_at(instructions)
    hits = [
        i for i, ins in enumerate(instructions)
        if re.search(r"\brm\b.*-rf?\b.*ensurepip/_bundled\b|\brm\b.*ensurepip/_bundled\b", ins)
    ]
    assert hits, "no instruction removes ensurepip/_bundled"
    assert hits[-1] > sync_at, "the removal precedes the install"
    for ins in instructions:
        if re.search(r"\brm\b", ins) and "ensurepip" in ins:
            targets = re.findall(r"\S*ensurepip\S*", ins)
            assert all(t.rstrip("/").endswith("ensurepip/_bundled") for t in targets), (
                f"the ensurepip module itself is removed: {ins}"
            )


# ---- d16 -------------------------------------------------------------------------------------
def test_the_box_extra_is_exactly_duckdb_and_the_lock_provides_it():
    """`pyproject.toml` declares an optional-dependency extra `box` whose only entry is
    `duckdb`, and `uv.lock` provides that extra (its `defender` package lists
    `optional-dependencies.box = [duckdb]` and `provides-extras` names `box`), so
    `--locked` resolves it instead of erroring.

    # rejected: `--extra runtime` (byte-for-byte the host venv): ships anthropic/openai/mcp/
    # fastmcp into the boundary for no consumer (D1)."""
    pyproject = tomllib.loads((DEFENDER / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"]["optional-dependencies"]
    assert "box" in extras, sorted(extras)
    names = [re.split(r"[<>=!~;\[ ]", entry, maxsplit=1)[0].strip().lower() for entry in extras["box"]]
    assert names == ["duckdb"], extras["box"]

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    defender = [p for p in lock["package"] if p["name"] == "defender"]
    assert len(defender) == 1
    box_extra = defender[0].get("optional-dependencies", {}).get("box")
    assert box_extra is not None, "the lock has no `box` extra — relock (G23)"
    assert [d["name"] for d in box_extra] == ["duckdb"], box_extra
    assert "box" in defender[0]["metadata"]["provides-extras"], defender[0]["metadata"]
