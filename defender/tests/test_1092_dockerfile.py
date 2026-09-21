"""#1092 — the shape of `defender/box.Dockerfile` (M1, F1, MF4) and the `box` extra (M2).

Static demands over the recipe's TEXT: O8 keys on the digest pin and the pinned uv binary,
O7 on what is copied in and what installer is taken out, O1 on the extra and its lock entry.
What the built image then IS — the installed distributions, the absent installers, the
compiled bytecode — is `test_1092_box_image_live.py`'s, against a real daemon.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from defender.tests._spec1092 import DEFENDER, DOCKERFILE

_FROM_DIGEST = re.compile(r"^FROM\s+python:3\.11-slim@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?\s*$")
_UV_COPY = re.compile(
    r"^COPY\s+--from=ghcr\.io/astral-sh/uv:(?P<version>\S+?)(@sha256:[0-9a-f]{64})?\s+/uv\s+/bin/uv\s*$"
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


# ---- d11 -------------------------------------------------------------------------------------
def test_the_dockerfile_pins_its_base_by_sha256_digest():
    """The Dockerfile's base line is `FROM python:3.11-slim@sha256:<64 hex>`, a digest pin
    and not a floating tag; every `FROM` in the file is digest-pinned."""
    froms = [ins for ins in _instructions() if ins.startswith("FROM ")]
    assert froms, "no FROM instruction"
    assert _FROM_DIGEST.match(froms[0]), froms[0]
    for ins in froms:
        assert "@sha256:" in ins, ins


# ---- d12 -------------------------------------------------------------------------------------
def test_the_dockerfile_copies_a_version_pinned_uv_binary_and_never_pip_installs():
    """The Dockerfile obtains uv only by `COPY --from=ghcr.io/astral-sh/uv:<explicit
    version>` (a digest on that COPY too — UVPIN #88), never `latest`, and contains no
    `pip install` of anything."""
    instructions = _instructions()
    uv_copies = [ins for ins in instructions if "astral-sh/uv" in ins]
    assert len(uv_copies) == 1, uv_copies
    m = _UV_COPY.match(uv_copies[0])
    assert m, uv_copies[0]
    assert _EXPLICIT_VERSION.match(m.group("version")), m.group("version")
    assert "@sha256:" in uv_copies[0], "the uv COPY is not digest-pinned (UVPIN #88)"
    for ins in instructions:
        assert not re.search(r"\bpip3?\s+install\b", ins), ins
        assert "get-pip" not in ins, ins


# ---- d13 (negative; positive control: d14 — the two files ARE copied and synced) -----------------
def test_the_dockerfile_copies_exactly_pyproject_and_uv_lock_and_no_code():
    """The Dockerfile's `COPY` instructions from the build context name exactly
    `defender/pyproject.toml` and `defender/uv.lock` — no source tree, no `.env`, nothing
    else — and there is no `ADD`."""
    instructions = _instructions()
    assert not any(ins.startswith("ADD ") for ins in instructions)
    sources: list[str] = []
    for ins in instructions:
        if not ins.startswith("COPY ") or "--from=" in ins:
            continue
        words = [w for w in ins.split()[1:] if not w.startswith("--")]
        assert len(words) >= 2, ins
        sources.extend(words[:-1])
    assert sorted(sources) == ["defender/pyproject.toml", "defender/uv.lock"], sources


# ---- d14 -------------------------------------------------------------------------------------
def test_the_sync_line_targets_usr_local_frozen_no_dev_inexact_compiled_with_the_box_extra():
    """The sync instruction sets `UV_PROJECT_ENVIRONMENT=/usr/local` and
    `UV_COMPILE_BYTECODE=1` and runs `uv sync` with `--frozen`, `--no-dev`, `--inexact` and
    `--extra box`, and the uv binary is removed afterwards (`rm … /bin/uv` after the sync);
    no `ENV` instruction leaks a sync-time variable into the image (O7-SHAPE #60)."""
    instructions = _instructions()
    sync = instructions[_index_of(instructions, "uv sync")]
    for flag in ("--frozen", "--no-dev", "--inexact", "--extra box"):
        assert flag in sync, (flag, sync)
    assert "UV_PROJECT_ENVIRONMENT=/usr/local" in sync, sync
    assert "UV_COMPILE_BYTECODE=1" in sync, sync
    removal = [i for i, ins in enumerate(instructions) if "/bin/uv" in ins and "rm" in ins]
    assert removal, "uv is never removed"
    assert removal[-1] > instructions.index(sync), "uv is not removed after the sync"
    assert not any(ins.startswith("ENV ") for ins in instructions), "an ENV instruction"


# ---- d15 -------------------------------------------------------------------------------------
def test_the_dockerfile_uninstalls_pip_setuptools_and_wheel_after_the_sync_and_names_packaging_as_kept():
    """After the sync and before `/bin/uv` is removed, the Dockerfile uninstalls `pip`,
    `setuptools` and `wheel` from `/usr/local` and names `packaging` as the base package it
    keeps (the reason `--inexact` was chosen)."""
    instructions = _instructions()
    sync_at = _index_of(instructions, "uv sync")
    uninstall_at = _index_of(instructions, "uninstall")
    uninstall = instructions[uninstall_at]
    for dist in ("pip", "setuptools", "wheel"):
        assert re.search(rf"\b{dist}\b", uninstall), (dist, uninstall)
    rm_uv = [i for i, ins in enumerate(instructions) if "/bin/uv" in ins and "rm" in ins]
    assert sync_at < uninstall_at < rm_uv[-1], (sync_at, uninstall_at, rm_uv)
    assert "packaging" in DOCKERFILE.read_text(encoding="utf-8"), "packaging is not named as kept"


# ---- MF4: the ensurepip wheels go too ----------------------------------------------------------
def test_the_dockerfile_removes_ensurepips_bundled_wheels_after_the_sync():
    """After the sync, the Dockerfile removes `ensurepip/_bundled` — the two wheels the base
    ships that survive the pip/setuptools/wheel uninstall and restore a working offline `pip`
    into the tmpfs (G17) — with an `rm -rf` of a path ending in `ensurepip/_bundled`; the
    `ensurepip` module itself stays."""
    instructions = _instructions()
    sync_at = _index_of(instructions, "uv sync")
    hits = [
        i for i, ins in enumerate(instructions)
        if re.search(r"\brm\b.*-rf?\b.*ensurepip/_bundled\b|\brm\b.*ensurepip/_bundled\b", ins)
    ]
    assert hits, "no instruction removes ensurepip/_bundled"
    assert hits[-1] > sync_at, "the removal precedes the sync"
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
    `--frozen` resolves it instead of erroring.

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
