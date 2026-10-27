"""`{system} -> declared verbs` off one tree: the verbs `knowledge._scaffold_rules.check_template`
checks a template against, shared by `connect`'s scaffold check and the lead-authoring lane's
commit gate.

It lives here, not beside the rules, because it reads the verb registry and `knowledge` sits
below `systems` in the import order (#1323). Failures raise the rules' own `ScaffoldRuleError`.
"""
from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

from defender._paths import adapters_under
from defender.kit.verbs import Verb
from defender.knowledge._scaffold_rules import ScaffoldRuleError
from defender.systems.verb_grant import DENY_ALL
from defender.systems.verbs import ModuleVerbRegistry, RegistryError, read_roster


class VerbResolver:
    """`{system} -> declared verbs`, resolved off one tree and cached per system.

    Takes a `defender_dir` because the commit gate runs in the main checkout but checks a drain
    worktree; adapters load by resolved path, so the verdict is about the worktree's code.
    Importing them is safe because the lane's scope check already refuses agent edits outside
    `defender/skills/**.md`. Uses `DENY_ALL` because this asks what a system declares, not what
    a role may call.
    """

    def __init__(self, defender_dir: Path) -> None:
        self._adapters_dir = adapters_under(Path(defender_dir))
        # An unlistable adapters dir fails here as "could not check", never as an empty roster.
        try:
            self._registry = ModuleVerbRegistry(read_roster(self._adapters_dir), DENY_ALL)
        except RegistryError as e:
            raise ScaffoldRuleError(str(e)) from e
        self._cache: dict[str, Mapping[str, Verb]] = {}

    def is_system(self, system: str) -> bool:
        """Does `system` name an adapter in this tree — cold, no import?

        `defender/skills/` also holds authored surfaces that are not systems (some are agent
        system prompts, e.g. `gather/SKILL.md`), so the lead author's write gate asks this too.
        """
        # The roster is fixed at construction, which callers do after the writes being checked.
        return system in self._registry.systems()

    def verbs(self, system: str) -> Mapping[str, Verb]:
        # Failures are not cached, so they are re-raised rather than remembered as empty.
        if system not in self._cache:
            self._cache[system] = self._resolve(system)
        return self._cache[system]

    def _resolve(self, system: str) -> Mapping[str, Verb]:
        # Membership first: a `KeyError` from the adapter's own import would otherwise be
        # indistinguishable from `verbs()`'s "no adapter" `KeyError`.
        if not self.is_system(system):
            raise ScaffoldRuleError(
                f"no adapter for system {system!r} under {self._adapters_dir}"
            )
        try:
            verbs = self._registry.verbs(system)
        except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            # Interrupts and cancellation are not a broken adapter; without this the blanket
            # clause below would make a corpus sweep un-interruptible.
            raise
        except BaseException as exc:  # noqa: BLE001 — a module that will not import is a broken adapter
            raise ScaffoldRuleError(
                f"adapter for system {system!r} failed to import: {type(exc).__name__}: {exc}"
            ) from exc
        if not verbs:
            raise ScaffoldRuleError(
                f"adapter for system {system!r} declares no verbs (empty or missing VERBS)"
            )
        return verbs


__all__ = ["VerbResolver"]
