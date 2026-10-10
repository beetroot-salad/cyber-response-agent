"""The episodes root and the episode id (#1105 PR 2, D-ep: moved from the launcher).

`episodes_root(data_root)` is the one reader of `DEFENDER_EPISODES_BASE`, with its refusals;
`refuse_bad_episode_id` is the id rule; `episode_dir(data_root, episode_id)` composes where an
episode lives from the two, refusing (`EpisodeRefused`) before anything under the root is read.
An episode is opened or claimed by id as `Episode.open(episode_dir(data_root, episode_id))` /
`Episode.create(..., exclusive=True)` (`_episode_handle`, which re-exports these names).

Kept apart from both episode owners on purpose: the handle (`_episode_handle`) does no I/O but
through the folder it holds (#1133 D6'), and the layout owner (`_episode_paths`) spells names and
does not resolve the root (#1077 D1).
"""
from __future__ import annotations

import os
from pathlib import Path

from defender._git import REPO_ROOT
from defender._run_id import episode_id_fault

#: Where episodes live. No default: deriving it from the runs base would put `episodes/` inside
#: the tree corpus walkers descend and inside the checkout provenance is stamped from.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"


class EpisodeRefused(ValueError):
    """The episode owner refused an episode id or the configured episodes root, before anything
    under the root was read. The message is operator-ready; each door adds its own prefix."""


def episodes_root(data_root: Path) -> Path:
    """The configured root every episode directory is a child of, resolved.

    Must be outside the data root (every tenant's tree lives there, so walkers indexing a
    tenant's runs or episodes would count it) and outside the checkout (or an untracked episode
    dir makes every sibling's provenance stamp dirty, so no family can complete). Being
    configured also keeps it independent of the data root. `data_root` is the one the request's
    tenant was (or is about to be) accepted under.
    """
    raw = os.environ.get(EPISODES_BASE_ENV)
    if not raw:
        raise EpisodeRefused(
            f"{EPISODES_BASE_ENV} is not set — an episode's directory is a CONFIGURED "
            "location, and there is deliberately no default: derived from the data root it "
            "would be walked by every consumer that indexes a tenant's runs, and derived from "
            "the checkout it would dirty the tree every sibling stamps itself against. Name a "
            "directory outside both")
    # Resolved even when it does not exist yet (every first launch): an unresolved relative path
    # has `.parents == (Path("."),)`, so neither refusal below would fire.
    root = Path(raw)
    candidate = root.resolve()
    data_root = Path(data_root).resolve()
    for forbidden, why in (
        (data_root, "the data root — every tenant's tree lives there, so an episode inside it "
                    "would be indexed as a tenant's own runs or episodes"),
        (REPO_ROOT, "the checkout — an untracked directory there is what a sibling's own "
                    "provenance stamp reports as a dirty tree"),
    ):
        forbidden = Path(forbidden).resolve()
        if candidate == forbidden or forbidden in candidate.parents:
            raise EpisodeRefused(f"{EPISODES_BASE_ENV}={root} resolves inside {why}")
    # A base containing the data root (its parent, say) is refused too; one containing the
    # checkout is not.
    if candidate in data_root.parents:
        raise EpisodeRefused(
            f"{EPISODES_BASE_ENV}={root} contains the data root {data_root} — keep "
            "episodes and tenants' trees apart")
    # The resolved path the refusals judged: paths built from it reach child processes, which
    # would re-resolve a relative one against their own cwd.
    return candidate


def refuse_bad_episode_id(episode_id: object) -> str:  # lint-dup: ok — one rule, two error classes: `_family` raises `FamilyError` for a manifest; the episode owner raises `EpisodeRefused` before any path is built (both state the rule once, in `_run_id.episode_id_fault`)
    """`episode_id`, when it can name a directory of its own under the episodes root — a run id
    with room left for a sibling (`_run_id.episode_id_fault`, the one statement of the rule) —
    else `EpisodeRefused`, before any path is built from it."""
    if type(episode_id) is not str:
        raise EpisodeRefused(f"an episode id must be text, not {type(episode_id).__name__}")
    if (why := episode_id_fault(episode_id)) is not None:
        raise EpisodeRefused(f"episode id {episode_id!r} is not usable: {why} — it names a "
                             "directory and half of every sibling's run id")
    return episode_id


def episode_dir(data_root: Path, episode_id: str) -> Path:
    """Where episode `episode_id` lives: one path component under the configured episodes root.
    The id is judged first, since a separator in it would put the episode outside the root or
    onto another's. Asking for it reads nothing under the root."""
    episode_id = refuse_bad_episode_id(episode_id)
    return episodes_root(data_root) / episode_id
