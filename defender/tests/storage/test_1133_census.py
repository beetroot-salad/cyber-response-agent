"""The Episode handle's constructors are exactly its two doors.

The source-reading census this file used to hold (episode I/O in the migrated modules, the handle's
I/O, path-taking parameters, the path makers, the doors) is `tooling/lint/lint_episode_paths.py`.
What stays here needs the live class, which a lint cannot import."""
from __future__ import annotations

import importlib
import inspect


def test_o5_the_episodes_only_constructors_are_its_two_doors():
    handle_mod = importlib.import_module("defender.records._episode_handle")
    episode = handle_mod.Episode
    constructors = {
        n for n in dir(episode) if not n.startswith("_")
        and isinstance(inspect.getattr_static(episode, n), (classmethod, staticmethod))}
    assert constructors == {"open", "create"}, (
        f"the Episode's public class/static methods are {sorted(constructors)}, not exactly "
        "the doors open and create")
    functions = {n for n, v in vars(handle_mod).items() if not n.startswith("_")
                 and inspect.isfunction(v) and v.__module__ == handle_mod.__name__}
    assert functions == set(), (
        f"_episode_handle defines public functions {sorted(functions)}: a door outside "
        "Episode.open / Episode.create")
