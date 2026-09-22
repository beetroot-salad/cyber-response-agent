#!/usr/bin/env python3
"""Name and build the owned box image (#1092, M3 revised).

STDLIB-ONLY: this script runs on a bare CI runner `python3` (`box-dood`'s runner has no uv
and no venv) and on a developer's devcontainer `python3`. It never `import defender...` — it
loads `runtime/box/_image.py` BY FILE PATH, the same door the running package uses only once
pydantic is on `BoxSpec`'s closure (an ordinary package import would then pull pydantic in,
which this script cannot assume is installed).

    python3 defender/scripts/box_image.py tag    # print the image name for THIS tree
    python3 defender/scripts/box_image.py build  # `docker build` it, tagged with that name
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

#: This script's own tree: `defender/scripts/box_image.py` -> `defender/` -> the tree root.
_DEFENDER_DIR = Path(__file__).resolve().parent.parent
_TREE_ROOT = _DEFENDER_DIR.parent


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
        str(_TREE_ROOT),
    ]
    # This is the ONE place the recipe is built, so the builder it needs is pinned here: the
    # recipe's `RUN --mount` (uv lent to the sync step, never a layer) is BuildKit syntax,
    # which the legacy builder rejects. Docker >= 23 defaults to BuildKit; the variable makes
    # an older daemon's CLI use it too instead of failing on the first `--mount`.
    env = dict(os.environ, DOCKER_BUILDKIT="1")
    proc = subprocess.run(argv, env=env)  # noqa: S603 — the whole point of this command
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="box_image.py")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("tag")
    sub.add_parser("build")
    args = parser.parse_args(argv)

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
