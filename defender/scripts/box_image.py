#!/usr/bin/env python3
"""Name and build the owned box image (#1092, M3 revised).

STDLIB-ONLY: this script runs on a bare CI runner `python3` (`box-dood`'s runner has no uv
and no venv) and on a developer's devcontainer `python3`. It never `import defender...` — it
loads `runtime/box/_image.py` BY FILE PATH, the same door the running package uses only once
pydantic is on `BoxSpec`'s closure (an ordinary package import would then pull pydantic in,
which this script cannot assume is installed).

    python3 defender/scripts/box_image.py tag     # print the image name for THIS tree
    python3 defender/scripts/box_image.py build   # `docker build` it, tagged with that name
    python3 defender/scripts/box_image.py export  # regenerate `box-requirements.txt` (needs uv)

`export` is the one subcommand that needs `uv` — a developer's, after a relock; `tag` and
`build` never run it, so the bare runner never needs it (#1097).
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

#: This script's own tree: `defender/scripts/box_image.py` -> `defender/`.
_DEFENDER_DIR = Path(__file__).resolve().parent.parent

#: The image's package list, beside the recipe that installs it (#1097).
EXPORT_FILE = "box-requirements.txt"

#: The core dependencies plus the `box` extra, as the lock resolves them: exact pins, markers
#: kept, every artifact hash. `--locked` refuses a `pyproject.toml` the lock no longer
#: satisfies (the #1095 guarantee, moved here from the build now that the build reads no
#: manifest); `--no-emit-project` leaves out `defender` itself, a virtual project with nothing
#: to install; no header and no annotations, so the list's bytes — and with them the image
#: name — move only when the pins or their hashes do.
_EXPORT_ARGV: tuple[str, ...] = (
    "uv", "export", "--locked", "--no-dev", "--extra", "box", "--no-emit-project",
    "--no-header", "--no-annotate",
)


class ExportError(RuntimeError):
    """`uv export` ran and refused — carries uv's own reason (a stale lock, most often)."""


def export_requirements(defender_dir: Path) -> str:
    """@owns box-requirements.txt — the text of the box image's package list for the tree at
    `defender_dir`, freshly exported from its `uv.lock`. The ONE place the export command is
    spelled: the `export` subcommand writes this text, and the drift test compares the
    committed file against it. Raises `ExportError` if uv refuses, `OSError` if there is no uv
    to run; never writes anything itself."""
    proc = subprocess.run(  # noqa: S603 — a fixed argv
        list(_EXPORT_ARGV), cwd=defender_dir, capture_output=True, text=True, encoding="utf-8",
    )
    if proc.returncode != 0:
        raise ExportError(f"uv export failed: {proc.stderr.strip()}")
    return proc.stdout


def _load_image_module() -> ModuleType:
    path = _DEFENDER_DIR / "runtime" / "box" / "_image.py"
    spec = importlib.util.spec_from_file_location("_box_image_recipe", path)
    if spec is None or spec.loader is None:  # pragma: no cover — importlib contract
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tag(image: ModuleType) -> str:
    return str(image.image_tag(_DEFENDER_DIR))


def _cmd_tag(image: ModuleType) -> int:
    print(_tag(image))
    return 0


def _cmd_build(image: ModuleType) -> int:
    tag = _tag(image)
    dockerfile = _DEFENDER_DIR / "box.Dockerfile"
    argv = [
        "docker", "build",
        "-f", str(dockerfile),
        "-t", tag,
        # The context is `defender/`, not the repo root: the recipe reads only the package list
        # from it, so no root `.dockerignore` has to keep enumerating large local directories
        # (#1098).
        str(_DEFENDER_DIR),
    ]
    # This is the ONE place the recipe is built, so the builder it needs is pinned here: the
    # recipe's `RUN --mount` (uv and the package list lent to the install step, never a layer) is BuildKit syntax,
    # which the legacy builder rejects. Docker >= 23 defaults to BuildKit; the variable makes
    # an older daemon's CLI use it too instead of failing on the first `--mount`.
    env = dict(os.environ, DOCKER_BUILDKIT="1")
    try:
        proc = subprocess.run(argv, env=env)  # noqa: S603 — the whole point of this command
    except OSError as e:
        # No `docker` on PATH (or one that cannot be exec'd): this CLI's own one line and
        # exit 1, the same surface as every other failure of the build, not a traceback.
        print(f"box_image.py: could not run docker: {e}", file=sys.stderr)
        return 1
    return proc.returncode


def _cmd_export() -> int:
    try:
        text = export_requirements(_DEFENDER_DIR)
    except OSError as e:
        print(f"box_image.py: could not run uv: {e}", file=sys.stderr)
        return 1
    except ExportError as e:
        print(f"box_image.py: {e}", file=sys.stderr)
        return 1
    # Written only after a successful export, so a refusal leaves the committed list as it was.
    # A developer's host-side command on a tracked file, never run by or for a box (the box
    # mounts this tree read-only); this stdlib-only script cannot import `defender._io`.
    (_DEFENDER_DIR / EXPORT_FILE).write_text(text, encoding="utf-8")  # lint-unguarded-tree-write: ok — host-only, see above
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="box_image.py")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("tag")
    sub.add_parser("build")
    sub.add_parser("export")
    args = parser.parse_args(argv)
    if args.command == "export":
        # Needs no image module: the list is an input to the name, not derived from it.
        return _cmd_export()

    try:
        image = _load_image_module()
    except Exception as e:  # noqa: BLE001 — anything importlib raises is this script's fault
        print(f"box_image.py: {e}", file=sys.stderr)
        return 1
    try:
        if args.command == "tag":
            return _cmd_tag(image)
        return _cmd_build(image)
    except image.ImageInputError as e:
        # The tree's fault, in the resolver's own words — the class is the loaded module's,
        # so no name-matching stands between the raise and this arm.
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
