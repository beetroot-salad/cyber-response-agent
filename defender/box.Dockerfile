# The owned box image (#1092). Build context is the REPO ROOT (see `.dockerignore` there),
# not `defender/` — `scripts/box_image.py build` invokes `docker build` that way so this file
# can COPY only the two files it needs without a build-context reach outside the repo.
#
# Base digest pin (O8): a base CVE update is this repo's to make, by hand, in this line —
# recorded here rather than left to a floating tag that could change what "the same commit"
# builds on different days.
FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9

# uv, as a pinned BINARY copy — never `pip install uv`, which would ship an installer and an
# unpinned resolver into the image (O7, O8).
COPY --from=ghcr.io/astral-sh/uv:0.8.14@sha256:f3660c56d5b08d6c516360981bedc439f499b9bf37f46a216018da3777a74011 /uv /bin/uv

# Only the two files the sync needs — no source tree, no `.env`, nothing else (O7).
COPY defender/pyproject.toml defender/uv.lock defender/

WORKDIR /defender

# UV_PROJECT_ENVIRONMENT points the sync at the SYSTEM site-packages (bare `python3` on the
# box's fixed PATH is what every granted shim and the entrypoint runs — see `_docker._BOX_PATH`
# — there is no venv to activate inside the box). `--inexact`: a plain sync PRUNES the base
# image's own site-packages (it removed `packaging`, which the sync then has to re-add by
# name below) — inexact keeps what the base already carries. `--frozen`: never rewrites
# `uv.lock`, a build over a divergent lockfile fails loudly instead of silently relocking.
# `--no-dev`: the box needs the `box` extra, never the dev toolchain. `UV_COMPILE_BYTECODE=1`:
# compiles `.pyc`s at build time — the box's mount is read-only, so nothing could compile them
# at import time inside a run.
RUN UV_PROJECT_ENVIRONMENT=/usr/local UV_COMPILE_BYTECODE=1 \
    uv sync --frozen --no-dev --inexact --extra box

# No installer stays reachable inside the sandbox (O7): pip/setuptools/wheel are the sync's
# own by-product (the base ships them; `--inexact` above keeps them installed until here),
# `packaging` is the one base package `--inexact` exists to keep.
RUN /usr/local/bin/python3 -m pip uninstall --yes pip setuptools wheel

# `ensurepip`'s bundled wheels (MF4) go too — otherwise `python3 -m ensurepip` rebuilds a
# working `pip` from them even with the site-packages copy gone; the `ensurepip` module
# itself (stdlib) stays.
RUN rm -rf /usr/local/lib/python3.11/ensurepip/_bundled

# The uv binary itself is the last thing removed — nothing after this needs it.
RUN rm -f /bin/uv
