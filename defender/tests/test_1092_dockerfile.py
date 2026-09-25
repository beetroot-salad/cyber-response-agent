"""#1092 — the shape of `defender/box.Dockerfile` (M1, F1, MF4) and the `box` extra (M2).

Static demands over the recipe's TEXT: O8 keys on the digest pin and the pinned uv binary,
O7 on what is copied in and what installer is taken out, O1 on the extra and its lock entry.
#1097 (design amendment) keeps the image synced from the same lock as the host venv,
`--locked`, and pins the sync's whole command and the absence of any context bind, the two
holes round 1's adversary found in a presence-only reading. Amendment 2 (M2″) FENCES that sync
with `--no-install-project --no-default-groups`, so neither the project itself nor a
dependency group — both outside what the image name reads — can enter the image.
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
    """The Dockerfile obtains uv only as a bind MOUNT on the sync's `RUN` — `--mount=type=bind,
    from=ghcr.io/astral-sh/uv:<explicit version>@sha256:<digest>,source=/uv,target=/bin/uv`
    (a version and a digest — UVPIN #88), never `latest` — so the binary is on the path of
    that one step and enters no layer: no `COPY --from` of uv anywhere, nothing to remove
    afterwards, and no `pip install` of anything.

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
    assert "uv sync" in uv_sites[0], "uv is mounted on some step other than the sync"
    for ins in instructions:
        assert not (ins.startswith("COPY ") and "--from=" in ins), f"a binary copied into a layer: {ins}"
        assert not re.search(r"\bpip3?\s+install\b", ins), ins
        assert "get-pip" not in ins, ins


# ---- d13 (negative; positive control: d14 — the two files ARE copied and synced) -----------------
def test_the_dockerfile_copies_exactly_pyproject_and_uv_lock_and_no_code():
    """The Dockerfile's one `COPY` from the build context is exactly `COPY pyproject.toml
    uv.lock ./` (the context is `defender/`, #1098), under a `WORKDIR` set before it and ahead
    of the sync that reads them — no source tree, no `.env`, nothing else — there is no `ADD`,
    and no `RUN` binds the build context: every `--mount` on every `RUN` names a `from=` image
    (the uv mount), so no step can reach past the COPY list and `cp` the context into a layer
    (#1097 adversary H6). The mount parser is not blind: it sees the uv mount on the sync.

    # rejected: bind-mounting an exported package list from the context into a `uv pip
    # install --no-deps` step (#1097 round 1): a second copy of the lock, and an install that
    # trusts the copy's completeness (the design amendment)."""
    instructions = _instructions()
    assert not any(ins.startswith("ADD ") for ins in instructions)
    copies = [
        (i, ins) for i, ins in enumerate(instructions)
        if ins.startswith("COPY ") and "--from=" not in ins
    ]
    assert len(copies) == 1, copies
    copy_at, copy = copies[0]
    assert copy.split()[1:] == ["pyproject.toml", "uv.lock", "./"], copy
    workdirs = [i for i, ins in enumerate(instructions) if ins.startswith("WORKDIR ")]
    assert workdirs, "no WORKDIR: the COPY's `./` is the image root"
    assert workdirs[0] < copy_at, "the COPY lands before any WORKDIR is set"
    assert copy_at < _index_of(instructions, "uv sync"), "the sync precedes the COPY it reads"

    runs = [ins for ins in instructions if ins.startswith("RUN ")]
    mounts = [m for ins in runs for m in _run_parts(ins)[0]]
    assert any("astral-sh/uv" in m.get("from", "") for m in mounts), mounts
    context_binds = [m for m in mounts if m.get("type", "bind") == "bind" and "from" not in m]
    assert context_binds == [], f"a RUN binds the build context: {context_binds}"


# ---- d14 -------------------------------------------------------------------------------------
def test_the_sync_line_targets_usr_local_frozen_no_dev_inexact_compiled_with_the_box_extra():
    """The sync instruction sets `UV_PROJECT_ENVIRONMENT=/usr/local` and
    `UV_COMPILE_BYTECODE=1` and runs `uv sync` with `--locked` (not `--frozen`, which skips
    the lock-freshness check and would install a stale set under a FRESH image name — #1095),
    `--no-dev`, `--inexact`, `--extra box`, and — #1097 amendment 2's fence (M2″) —
    `--no-install-project` and `--no-default-groups`, so neither the project itself nor a
    `default-groups` dependency group (neither of which the image name hashes) can enter the
    image whatever `pyproject.toml` says; no `ENV` instruction leaks a sync-time variable into
    the image (O7-SHAPE #60). (uv itself is mounted onto that step and never removed, because it
    was never added — d12.)

    The step's WHOLE command is pinned, not the presence of each wanted flag: uv takes the last
    of a flag and its negation, so `--locked … --frozen` (or `--no-locked`) passes a presence
    check while skipping the freshness check, and `--exact` prunes the base's `packaging`
    (#1097 adversary H1). Exactly those two assignments (in either order), then `uv sync`, then
    exactly `--locked --no-dev --inexact --extra box --no-install-project --no-default-groups`
    in any order — no negation, no second extra, no `--group`, no second command."""
    fence = ["--locked", "--no-dev", "--inexact", "--no-install-project", "--no-default-groups"]
    instructions = _instructions()
    sync = instructions[_index_of(instructions, "uv sync")]
    for flag in (*fence, "--extra box"):
        assert flag in sync, (flag, sync)
    assert "--frozen" not in sync, sync
    assert "UV_PROJECT_ENVIRONMENT=/usr/local" in sync, sync
    assert "UV_COMPILE_BYTECODE=1" in sync, sync
    assert not any(ins.startswith("ENV ") for ins in instructions), "an ENV instruction"

    _mounts, command = _run_parts(sync)
    assert sorted(command[:2]) == ["UV_COMPILE_BYTECODE=1", "UV_PROJECT_ENVIRONMENT=/usr/local"], command
    assert command[2:4] == ["uv", "sync"], command
    flags = command[4:]
    assert flags.count("--extra") == 1, command
    extra_at = flags.index("--extra")
    assert flags[extra_at + 1] == "box", command
    rest = flags[:extra_at] + flags[extra_at + 2:]
    assert sorted(rest) == sorted(fence), command


# ---- d15 -------------------------------------------------------------------------------------
def test_the_dockerfile_uninstalls_pip_setuptools_and_wheel_after_the_sync_and_names_packaging_as_kept():
    """After the sync, the Dockerfile uninstalls `pip`, `setuptools` and `wheel` from
    `/usr/local` and names `packaging` as the base package it keeps (the reason `--inexact`
    was chosen)."""
    instructions = _instructions()
    sync_at = _index_of(instructions, "uv sync")
    uninstall_at = _index_of(instructions, "uninstall")
    uninstall = instructions[uninstall_at]
    for dist in ("pip", "setuptools", "wheel"):
        assert re.search(rf"\b{dist}\b", uninstall), (dist, uninstall)
    assert sync_at < uninstall_at, (sync_at, uninstall_at)
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


# ---- #1097 round-2 adversary H6: no step beyond the recipe's three ------------------------------
def test_the_recipe_runs_exactly_the_sync_the_installer_uninstall_and_the_ensurepip_removal():
    """The Dockerfile has exactly three `RUN` steps — the `uv sync` (pinned whole by d14), then
    `python3 -m pip uninstall --yes pip setuptools wheel` word for word, then `rm -rf` of
    `ensurepip/_bundled` word for word — so no step can install, copy in, or edit anything
    beyond the lock's closure: an extra `pip --no-cache-dir install …` step, which slips past
    d12's `pip install` pattern, fails here.

    # rejected: widening d12's regex to every pip spelling — a blocklist of install verbs is
    # the shape that missed the option-between-words spelling in the first place."""
    # The WHOLE instruction list, by keyword: a `SHELL` (or `ARG`, `ENV`, `ONBUILD`) line
    # rewrites what every RUN executes while leaving each RUN's text word for word (#1097
    # round-3 adversary H8 — a SHELL injected a .pth into site-packages).
    keywords = [ins.split(None, 1)[0].upper() for ins in _instructions()]
    assert keywords == ["FROM", "WORKDIR", "COPY", "RUN", "RUN", "RUN"], keywords
    runs = [ins for ins in _instructions() if ins.startswith("RUN ")]
    assert len(runs) == 3, runs
    assert "uv sync" in runs[0], runs[0]
    assert shlex.split(runs[1][len("RUN "):]) == [
        "/usr/local/bin/python3", "-m", "pip", "uninstall", "--yes", "pip", "setuptools", "wheel",
    ], runs[1]
    assert shlex.split(runs[2][len("RUN "):]) == [
        "rm", "-rf", "/usr/local/lib/python3.11/ensurepip/_bundled",
    ], runs[2]


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
