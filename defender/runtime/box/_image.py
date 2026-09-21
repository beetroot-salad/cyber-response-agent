"""The owned box image's NAME, derived from the tree it is built from (#1092, M3 revised).

STDLIB-ONLY, and no package-relative import: this module is loaded two ways — the normal
package door (`defender.runtime.box`, now free to pull pydantic — #1092 O2) and BY FILE PATH
from `defender/scripts/box_image.py`, which runs on a bare CI runner `python3` with no uv and
no venv on it. A relative import would make the second door unusable.

The name is a pure function of three files under the tree: `box.Dockerfile`, `uv.lock`,
`pyproject.toml`, read in that order (the order also decides which file a "cannot read" fault
names first). Nothing here reads any file at import time — only `image_tag` touches disk, and
only when called.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

#: Bumped whenever the RECIPE (the meaning of the three input files, not their bytes) changes
#: in a way the hash alone would not capture — e.g. the resolver starts reading a fourth file.
#: Prefixes every name, so a mounted tree's own (possibly foreign) `_image.py` can never be
#: mistaken for the running package's (MF3).
RECIPE_VERSION = "v1"

#: The three files the image name is a function of, IN THE ORDER the resolver reads them.
HASH_INPUTS: tuple[str, ...] = ("box.Dockerfile", "uv.lock", "pyproject.toml")


class ImageInputError(Exception):
    """One of `HASH_INPUTS` could not be read under `tree` — missing, a directory in its
    place, or any other `OSError`. Carries enough to build an operator-facing message without
    importing anything outside the stdlib."""

    def __init__(self, tree: Path, name: str, reason: BaseException) -> None:
        self.tree = tree
        self.name = name
        self.reason = reason
        super().__init__(f"{tree}: cannot read {name}: {reason}")


def image_tag(tree: Path) -> str:
    """`defender-box:<RECIPE_VERSION>-<12 hex>` — the digest over the bytes of `HASH_INPUTS`
    under `tree`, in order. Raises `ImageInputError` naming the FIRST file that cannot be
    read; never partially hashes a tree it could not fully read."""
    tree = Path(tree)
    digest = hashlib.sha256()
    for name in HASH_INPUTS:
        path = tree / name
        try:
            data = path.read_bytes()
        except OSError as e:
            raise ImageInputError(tree, name, e) from e
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return f"defender-box:{RECIPE_VERSION}-{digest.hexdigest()[:12]}"
