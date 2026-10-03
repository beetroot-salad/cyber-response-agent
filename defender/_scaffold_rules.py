"""Well-formedness invariants for a system's authored surface (query templates, `SKILL.md`),
as data — shared by `connect`'s scaffold check and the lead-authoring lane's commit gate.

Nothing here prints or exits: callers decide what a `Finding` means. Messages carry no path;
each caller prefixes the locator it has.

The allowed param surface is `model_facing_params`, not `declared_params`: template
placeholders and `params:` are bound by a model, so a `@verb(wrapper_only=…)` param must be
refused here rather than at `validate_params` after the run is spent. `body_substitutions:`
may not name such a param either, since it exempts a `${name}` from checking.
"""
from __future__ import annotations

import asyncio
import errno
import os
import re
from collections.abc import Mapping
from pathlib import Path, PurePath

from defender._corpus import QueryTemplate
from defender._frontmatter import parse_frontmatter_or_none
from defender._io import Bound, RecordRead, bind
from defender._model import model
from defender._paths import adapters_under
from defender.runtime.verb_grant import DENY_ALL
from defender.runtime.verbs import (
    ModuleVerbRegistry,
    RegistryError,
    Verb,
    engine_of,
    model_facing_params,
    read_roster,
    wrapper_only_params,
)

#: The checked placeholder grammar, as `SCHEMA.md` documents it. The bare `{name}` form
#: `lead_render` also substitutes is not checked: query-language bodies carry braces of their
#: own (e.g. ES|QL `GROK "%{IP:src}"`).
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}")


def placeholders(text: str) -> set[str]:
    """Every `${name}` the checked grammar finds in `text` — exported so writers classify
    against the same grammar the checker applies.
    """
    return set(_PLACEHOLDER_RE.findall(text))


@model(frozen=True)
class Finding:
    """One violated invariant. `code` is the stable machine name (tests bind to it); `message`
    names the offending symbol but never the file."""

    code: str
    message: str


class ScaffoldRuleError(Exception):
    """A rule could not be evaluated (an adapter that will not import, a system with none).
    Distinct from a finding: the checker could not tell, which callers must not treat as a pass."""


def _id_findings(t: QueryTemplate) -> list[Finding]:
    """The `id: {system}.{template-id}` invariant `SCHEMA.md` states.

    A template's system comes from its directory, but consumers route on the id's prefix, so a
    mismatch sends rows to the wrong system and mints a sibling draft.
    """
    prefix = t.id.split(".", 1)[0] if "." in t.id else ""
    if prefix == t.system:
        return []
    return [
        Finding(
            "id-system-mismatch",
            f"`id: {t.id}` does not name the system it is filed under — `SCHEMA.md` spells an "
            f"id `{{system}}.{{template-id}}`, so this file's id must start with {t.system!r}",
        )
    ]


def _covers_findings(t: QueryTemplate) -> list[Finding]:
    """`covers:` entries must be `{system}.{segment}` for the system the file sits under.

    `synthesize_drafts` trusts `covers:`, so an entry naming another system silently stops that
    system's draft from ever being minted. The shape check also catches YAML-coerced entries
    (`covers: on` → `"True"`) and bare names no `resolve_query_id` could emit.
    """
    bad = [c for c in t.covers if c.split(".", 1)[0] != t.system or "." not in c]
    if not bad:
        return []
    return [
        Finding(
            "covers-system-mismatch",
            f"`covers:` names {sorted(bad)}, which are not identities of {t.system!r} — an "
            f"entry is a `query_id` this file answers, so it is spelled "
            f"`{t.system}.{{name}}`; an entry naming another system silently stops that "
            "system's drafts from ever being minted again",
        )
    ]


def check_template(t: QueryTemplate, verbs: Mapping[str, Verb]) -> list[Finding]:
    """Every well-formedness finding against one template, given its system's declared verbs."""
    out = _id_findings(t) + _covers_findings(t)
    if not t.verb:
        return out + [
            Finding(
                "no-verb",
                "declares no `verb:` — the placeholder rule is per-VERB, so a template that "
                "names none is undecidable rather than exempt",
            )
        ]
    fn = verbs.get(t.verb)
    if fn is None:
        return out + [
            Finding(
                "unknown-verb",
                f"verb {t.verb!r} is not a declared verb of {t.system} "
                f"(declared: {sorted(verbs)})",
            )
        ]

    allowed = set(model_facing_params(fn))
    out += [
        Finding(
            "undeclared-param",
            f"`params:` names {name!r}, which {t.system}.{t.verb} does not declare as a "
            f"model-bindable param (declared: {sorted(allowed)})",
        )
        for name in sorted(set(t.params) - allowed)
    ]

    # `body_substitutions:` exempts a name from the placeholder rule, so it must not readmit a
    # `wrapper_only` param that `model_facing_params` keeps out.
    reserved = wrapper_only_params(fn)
    out.extend(
        Finding(
            "reserved-body-substitution",
            f"`body_substitutions:` names {name!r}, which {t.system}.{t.verb} reserves to a "
            f"first-party wrapper — no model may bind it, from a template or anywhere else",
        )
        for name in sorted(set(t.body_substitutions) & reserved)
    )

    # Every consumer degrades silently without a `## Query` (typically a promote that kept the
    # draft's `## Executed query` heading), so non-drafts must carry one.
    if t.status != "draft" and not t.query.strip():
        out.append(
            Finding(
                "empty-query",
                "carries no `## Query` — a template's query is its INTERFACE, and a file "
                "without one binds to a dispatch that renders nothing (a draft records under "
                "`## Executed query`; promoting it means writing the wide `## Query` yourself)",
            )
        )

    if engine_of(fn) != "none":
        # An engine verb's body is query language, so its `${…}` are body text, not params.
        return out

    undeclared = sorted(
        placeholders(t.query) - allowed - (set(t.body_substitutions) - reserved)
    )
    out.extend(
        Finding(
            "undeclared-placeholder",
            f"${{{name}}} is neither a declared param of {t.verb} nor a marked "
            f"body_substitution",
        )
        for name in undeclared
    )
    return out


def check_system_skill(
    source: Bound | Path, system: str, name: str | PurePath | None = None,
) -> list[Finding]:
    """The per-system `SKILL.md` frontmatter identity. (`execution.md` shape is authoring advice,
    left to `connect` as a warning.)

    `check_system_skill(view, system, name)`: `name` read through the `Bound` `view` — the drain
    passes its held `skills/` mount's view (#1134 A4). `check_system_skill(path, system)`: today's
    form, `path.name` read under `bind(path.parent)`, so it roots wherever it points and drain
    code never uses it (N-h). Either way a link or any non-plain entry is refused, never
    followed."""
    if isinstance(source, Bound):
        if name is None:
            raise ValueError("check_system_skill(view, system, name): a Bound needs the name")
        rec, spelled = source.read(name), str(name)
    else:
        if name is not None:
            raise ValueError("check_system_skill(path, system): a Path names its own file")
        path = Path(source)
        with bind(path.parent) as view:
            rec, spelled = view.read(path.name), str(path)
    if rec.text is None:
        # Its own finding: "frontmatter name is not …" would point at a line that may be fine.
        reason = _unreadable_reason(rec, spelled)
        return [Finding("skill-unreadable", f"could not be read ({reason})")]
    front = parse_frontmatter_or_none(rec.text)
    if front is not None and front.get("name") == f"defender-{system}":
        return []
    return [
        Finding(
            "skill-name",
            f"frontmatter name is not 'defender-{system}'",
        )
    ]


def _unreadable_reason(rec: RecordRead, spelled: str) -> str:
    """Why `rec` holds no text: the view's refusal, or, for a file that is not there, today's
    `FileNotFoundError` words for `spelled`."""
    if rec.reason is not None:
        return rec.reason
    return str(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), spelled))


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


__all__ = [
    "Finding",
    "ScaffoldRuleError",
    "VerbResolver",
    "check_system_skill",
    "check_template",
    "placeholders",
]
