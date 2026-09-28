#!/usr/bin/env python3
"""Name and build the owned box image.

Stdlib-only, python3 >= 3.11 (`tomllib`): it runs on a bare CI runner `python3` with no uv or
venv, and on a devcontainer `python3`. It never imports `defender...`; it loads
`runtime/box/_image.py` by file path, since a package import would pull in pydantic.

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

#: This script's own tree: `defender/scripts/box_image.py` -> `defender/`.
_DEFENDER_DIR = Path(__file__).resolve().parent.parent


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
        # The context is `defender/`, not the repo root: the recipe copies only two files, so
        # no root `.dockerignore` has to exclude large local directories.
        str(_DEFENDER_DIR),
    ]
    # The recipe's `RUN --mount` needs BuildKit; Docker >= 23 defaults to it, and this makes an
    # older CLI use it too.
    env = dict(os.environ, DOCKER_BUILDKIT="1")
    try:
        proc = subprocess.run(argv, env=env)  # noqa: S603 — running docker is this command's job
    except OSError as e:
        # No usable `docker`: one line and exit 1, like any other build failure.
        print(f"box_image.py: could not run docker: {e}", file=sys.stderr)
        return 1
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
        # The tree's fault, in the resolver's own words; the exception class comes from the
        # loaded module itself.
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":  # lint-log-setup: ok — stdlib-only: it builds the image before any defender environment exists, and imports nothing from the package
    sys.exit(main())
