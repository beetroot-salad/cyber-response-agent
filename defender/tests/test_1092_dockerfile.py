"""Static shape of defender/box.Dockerfile and the box extra."""
from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

from defender.tests._spec1092 import DEFENDER, DOCKERFILE

_FROM_DIGEST = re.compile(r"^FROM\s+python:3\.11-slim@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?\s*$")


def _instructions(path: Path = DOCKERFILE) -> list[str]:
    """The Dockerfile's instructions, one per entry, line continuations joined and comment
    lines dropped (a `#` inside a RUN's shell text is kept — only whole comment lines go)."""
    assert path.is_file(), f"{path} does not exist"
    joined: list[str] = []
    pending = ""
    # Split on "\n" ONLY, as BuildKit does — `str.splitlines()` also breaks on \x1c, \x0b,
    # \x0c, \x85, U+2028…, which would show a test two lines where BuildKit runs one.
    for raw in path.read_text(encoding="utf-8").split("\n"):
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


def _run_parts(instruction: str) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """A `RUN` split into its `--mount=` options (each a `key=value` dict; a bare option maps
    to ""), every OTHER `--` flag before the command, verbatim (`--network=none`, a `--mount`
    spelled without `=`, …), and the shell words it runs, as `shlex` splits them."""
    assert instruction.startswith("RUN "), instruction
    words = shlex.split(instruction[len("RUN "):])
    mounts: list[dict[str, str]] = []
    flags: list[str] = []
    while words and words[0].startswith("--"):
        flag = words.pop(0)
        if flag.startswith("--mount="):
            opts = {}
            for part in flag[len("--mount="):].split(","):
                key, _, value = part.partition("=")
                opts[key] = value
            mounts.append(opts)
        else:
            flags.append(flag)
    return mounts, flags, words


# ---- d11 -------------------------------------------------------------------------------------
def test_the_dockerfile_pins_its_base_by_sha256_digest():
    """The Dockerfile's base line is `FROM python:3.11-slim@sha256:<64 hex>`, a digest pin
    and not a floating tag; every `FROM` in the file is digest-pinned."""
    froms = [ins for ins in _instructions() if ins.startswith("FROM ")]
    assert froms, "no FROM instruction"
    assert _FROM_DIGEST.match(froms[0]), froms[0]
    for ins in froms:
        assert "@sha256:" in ins, ins


# ---- d13 (negative; positive control: d14 — the two files ARE copied and synced) -----------------
def test_the_dockerfile_copies_exactly_pyproject_and_uv_lock_and_no_code():
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


# ---- d16 -------------------------------------------------------------------------------------
def test_the_box_extra_is_exactly_duckdb_and_pytz_and_the_lock_provides_it():
    pyproject = tomllib.loads((DEFENDER / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"]["optional-dependencies"]
    assert "box" in extras, sorted(extras)
    names = [re.split(r"[<>=!~;\[ ]", entry, maxsplit=1)[0].strip().lower() for entry in extras["box"]]
    assert names == ["duckdb", "libfaketime", "pytz"], extras["box"]

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    defender = [p for p in lock["package"] if p["name"] == "defender"]
    assert len(defender) == 1
    box_extra = defender[0].get("optional-dependencies", {}).get("box")
    assert box_extra is not None, "the lock has no `box` extra — relock (G23)"
    assert [d["name"] for d in box_extra] == ["duckdb", "libfaketime", "pytz"], box_extra
    assert "box" in defender[0]["metadata"]["provides-extras"], defender[0]["metadata"]
