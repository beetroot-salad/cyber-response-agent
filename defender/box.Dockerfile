# The owned box image (#1092). Build context is `defender/` — `scripts/box_image.py build`
# invokes `docker build` that way — not the repo root, so the repo root's `.dockerignore` does
# not apply and needs no entry for this build: the recipe reads one file from the context, the
# package list, and nothing outside `defender/` is ever walked (#1098).
#
# BuildKit recipe: the install step below LENDS itself uv and the package list with
# `RUN --mount` — the legacy builder has no `--mount`, so `scripts/box_image.py build` sets
# DOCKER_BUILDKIT=1 for every build.
#
# Base digest pin (O8): a base CVE update is this repo's to make, by hand, in this line —
# recorded here rather than left to a floating tag that could change what "the same commit"
# builds on different days.
FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9

# Nothing is COPYed: no source tree, no `.env`, no manifest, no lock (O7).
#
# The package list (`box-requirements.txt`, #1097) is `uv export` of the core dependencies
# plus the `box` extra from `uv.lock` — regenerate it with `scripts/box_image.py export` after
# a relock; a test fails CI while it disagrees with the lock. It is MOUNTED into the install
# step, like uv, so it never lands in a layer. The image's name is a hash over this file and
# the list (`runtime/box/_image.py`), so an edit to either names a new image, and an edit to
# neither manifest that leaves the list alone (lint config, the dev/runtime extras) does not.
#
# uv is mounted from its pinned image (a version AND a digest — O8), never COPYed into a
# layer: the binary is on the path of the install and of nothing else, so no installer ever
# enters the image and none has to be removed (O7). Never `pip install uv`, which would ship
# an installer and an unpinned resolver.
#
# `--system`: installs into the SYSTEM site-packages (bare `python3` on the box's fixed PATH
# is what every granted shim and the entrypoint runs — see `_docker._BOX_PATH` — there is no
# venv to activate inside the box). `--require-hashes`: every download must match a hash the
# lock recorded. `--no-deps`: the list is already the whole closure — nothing is resolved
# beyond it. `--strict`: fails if the installed set is left inconsistent. `uv pip install`
# never prunes, so the base image's own `packaging` survives. `UV_COMPILE_BYTECODE=1`:
# compiles `.pyc`s at build time — the box's mount is read-only, so nothing could compile them
# at import time inside a run.
RUN --mount=type=bind,from=ghcr.io/astral-sh/uv:0.8.14@sha256:f3660c56d5b08d6c516360981bedc439f499b9bf37f46a216018da3777a74011,source=/uv,target=/bin/uv \
    --mount=type=bind,source=box-requirements.txt,target=/tmp/box-requirements.txt \
    UV_COMPILE_BYTECODE=1 \
    uv pip install --system --require-hashes --no-deps --strict -r /tmp/box-requirements.txt

# No installer stays reachable inside the sandbox (O7): pip/setuptools/wheel are the base's
# own (the install above never prunes, so they are still here), `packaging` is the one base
# package kept.
RUN /usr/local/bin/python3 -m pip uninstall --yes pip setuptools wheel

# `ensurepip`'s bundled wheels (MF4) go too — otherwise `python3 -m ensurepip` rebuilds a
# working `pip` from them even with the site-packages copy gone; the `ensurepip` module
# itself (stdlib) stays.
RUN rm -rf /usr/local/lib/python3.11/ensurepip/_bundled
