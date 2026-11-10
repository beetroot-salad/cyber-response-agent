"""Paths the helper takes from the tenant's folder (#1170 H10): judged without following links at the moment of use.

Every path the helper derives under `<data root>/<T>/` (a box's bind sources, what it removes, what it hands a
publish) must be a chain of real folders from the tenant's folder down, each component looked at with `lstat`: a link
anywhere on the way, a `..`, or a path outside `<T>/` is refused and nothing is created. The race between this check
and docker's bind is accepted (H10); binding from a parent the job cannot rename would close it."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from defender.job_socket import Refused


def confined(tenant_root: Path, path: Path, *, must_exist: bool = True) -> Path:
    """`path`, once every component from `tenant_root` down to it is a real folder (no link followed); a component
    that does not exist yet passes only when `must_exist` is false (the rest is then the helper's to make)."""
    tenant_root, path = Path(tenant_root), Path(path)
    try:
        rel = path.relative_to(tenant_root)
    except ValueError:
        raise Refused(f"{path} is not inside the tenant's folder", "confinement") from None
    if any(part in ("..", ".", "") for part in rel.parts):
        raise Refused(f"{path} climbs out of the tenant's folder", "confinement")
    current = tenant_root
    for step in (None, *rel.parts):
        if step is not None:
            current = current / step
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            if must_exist:
                raise Refused(f"{current} is absent", "confinement") from None
            return path
        except OSError as unreadable:
            raise Refused(f"{current} cannot be looked at: {unreadable.strerror}", "confinement") from None
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise Refused(f"{current} is a link or not a folder: the helper follows nothing out of the tenant's "
                          "folder", "confinement")
    return path
