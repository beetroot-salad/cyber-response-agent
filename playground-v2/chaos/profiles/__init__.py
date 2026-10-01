"""Chaos profiles: committed YAML, static fault descriptions.

The load side only; `chaos.mutations.resolve_mutations` turns a profile (with
a seed and the live inventory) into what actually gets pushed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Profile:
    id: str
    description: str
    mode: str
    seed: int
    params: dict[str, Any] = field(default_factory=dict)
    cover: str = ""


def load_profile(profile_id: str, *, profiles_dir: Path) -> Profile:
    path = Path(profiles_dir) / f"{profile_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"no chaos profile {profile_id!r} at {path}")
    raw = yaml.safe_load(path.read_text()) or {}
    return Profile(
        id=raw.get("id", profile_id),
        description=raw.get("description", ""),
        mode=raw["mode"],
        seed=int(raw.get("seed", 0)),
        params=raw.get("params") or {},
        cover=raw.get("cover", ""),
    )


def list_profiles(*, profiles_dir: Path) -> list[str]:
    profiles_dir = Path(profiles_dir)
    if not profiles_dir.is_dir():
        return []
    return sorted(p.stem for p in profiles_dir.glob("*.yaml"))
