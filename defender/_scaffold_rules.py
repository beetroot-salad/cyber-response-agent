"""The invariants that say a system's authored surface is well-formed — as DATA, for every lane
that writes it (#901).

These lived in `skills/connect/validate_scaffold.py`, which is run by a maintainer at scaffold
time. `connect` stopped being the only writer: the lead-authoring lane mints `_draft/` templates
(`learning/leads/draft_synthesis.py`) and promotes them into the established catalog and into
`skills/{system}/SKILL.md` continuously, post-merge, and its commit gate is path-shaped — it
never opened a file. The checks below are the half of `validate_scaffold` that is about AUTHORED
CONTENT rather than about an adapter, which is why they are the half that transfers: both lanes
write templates and `SKILL.md`; only `connect` writes adapters.

Two properties make this callable from a commit gate as well as from a CLI:

- **findings, not output.** Nothing here prints, and nothing raises `SystemExit`. A caller decides
  what a finding means — a `FAIL` row in `connect`'s report, a `LeadAuthorError` that refuses a
  commit, an assertion in CI.
- **no path in the message.** Each caller prefixes the locator it actually has (a file name for
  `connect`, a repo-relative path for the loop's commit gate), so neither has to strip the
  other's.

The allowed param surface is `model_facing_params`, not `declared_params`: a template's
`${placeholder}` and its `params:` list are both things a MODEL binds at dispatch, so a param
`@verb(wrapper_only=…)` reserves to a first-party wrapper is not bindable from a template. Under
`declared_params` such a template would pass here and then be refused at `validate_params` with
the run already spent.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from defender._corpus import QueryTemplate
from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_text_soft
from defender.runtime.verb_grant import DENY_ALL
from defender.runtime.verbs import (
    ModuleVerbRegistry,
    Verb,
    engine_of,
    model_facing_params,
)

#: The one checked placeholder grammar, and the only one `SCHEMA.md` documents. `lead_render`
#: additionally substitutes a bare `{name}` when it renders a handoff for display; that form is
#: deliberately NOT checked here, because a query LANGUAGE body carries braces of its own (an
#: ES|QL `GROK "%{IP:src}"` pattern is the shipped case) and checking it would make the corpus's
#: own syntax a source of false refusals.
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}")


@dataclass(frozen=True)
class Finding:
    """One violated invariant. `code` is the stable machine name (tests bind to it); `message` is
    the operator-facing sentence, naming the offending symbol but never the file."""

    code: str
    message: str


class ScaffoldRuleError(Exception):
    """A rule could not be EVALUATED — an adapter that will not import, a system with none. Not a
    finding: a finding says the authored file is wrong, this says the checker could not tell, and
    a caller that treats the two alike re-opens the hole this module closes."""


def check_template(t: QueryTemplate, verbs: Mapping[str, Verb]) -> list[Finding]:
    """Every well-formedness finding against one template, given its system's declared verbs."""
    if not t.verb:
        return [
            Finding(
                "no-verb",
                "declares no `verb:` — the placeholder rule is per-VERB, so a template that "
                "names none is undecidable rather than exempt",
            )
        ]
    fn = verbs.get(t.verb)
    if fn is None:
        return [
            Finding(
                "unknown-verb",
                f"verb {t.verb!r} is not a declared verb of {t.system} "
                f"(declared: {sorted(verbs)})",
            )
        ]

    allowed = set(model_facing_params(fn))
    out = [
        Finding(
            "undeclared-param",
            f"`params:` names {name!r}, which {t.system}.{t.verb} does not declare as a "
            f"model-bindable param (declared: {sorted(allowed)})",
        )
        for name in sorted(set(t.params) - allowed)
    ]

    if engine_of(fn) != "none":
        # An engine verb's body IS the query language, so its `${…}` are body text, not params —
        # the rule is per-VERB (`adapter.md`). Counting these as satisfied reported coverage the
        # check did not have: a system whose whole catalog is engine verbs had every template
        # skipped and every template claimed (#885).
        return out

    undeclared = sorted(set(_PLACEHOLDER_RE.findall(t.query)) - allowed - set(t.body_substitutions))
    out.extend(
        Finding(
            "undeclared-placeholder",
            f"${{{name}}} is neither a declared param of {t.verb} nor a marked "
            f"body_substitution",
        )
        for name in undeclared
    )
    return out


def check_system_skill(skill_md: Path, system: str) -> list[Finding]:
    """The per-system `SKILL.md` frontmatter identity. The `execution.md` shape stays a
    `connect`-local WARN and is not here: it is authoring advice, not an invariant, and the
    pitfalls curator writes that file under a rule of its own."""
    text, _reason = read_text_soft(skill_md)
    front = parse_frontmatter_or_none(text) if text is not None else None
    if front is not None and front.get("name") == f"defender-{system}":
        return []
    return [
        Finding(
            "skill-name",
            f"frontmatter name is not 'defender-{system}'",
        )
    ]


class VerbResolver:
    """`{system} -> declared verbs`, resolved off ONE tree and cached per system.

    Takes a `defender_dir` rather than reading a module global, because the callers that matter
    are not in the tree they check: the loop's commit gate runs in the main checkout and gates a
    drain WORKTREE. `_load_adapter_module` caches on the resolved absolute path, so a resolver
    built on the worktree's adapters dir gets the worktree's adapters and not the running
    process's — which is the property that makes the gate's verdict a statement about the commit
    it is about to make.

    Importing those adapters is safe at that seam for a reason worth stating: the lane's scope
    check has already refused the commit if the agent touched anything outside
    `defender/skills/**.md`, so an adapter reachable here is first-party checked-in code, never
    agent-written.

    `DENY_ALL` is deliberate. This asks what a system DECLARES, which is a different question
    from what a role may call — `verbs()` is grant-independent by construction (a grant decides
    at `decide()`), and passing a real role's grant here would silently scope a
    well-formedness check to one role's authorization.
    """

    def __init__(self, defender_dir: Path) -> None:
        self._adapters_dir = Path(defender_dir) / "scripts" / "adapters"
        self._registry = ModuleVerbRegistry(self._adapters_dir, DENY_ALL)
        self._cache: dict[str, Mapping[str, Verb]] = {}

    def verbs(self, system: str) -> Mapping[str, Verb]:
        # Cached per SYSTEM because the gate asks once per changed path and a batch routinely
        # touches several templates of one system; a failure is deliberately NOT cached, so it
        # is re-raised (and re-reported) rather than remembered as an empty roster.
        if system not in self._cache:
            self._cache[system] = self._resolve(system)
        return self._cache[system]

    def _resolve(self, system: str) -> Mapping[str, Verb]:
        try:
            verbs = self._registry.verbs(system)
        except KeyError:
            raise ScaffoldRuleError(
                f"no adapter for system {system!r} under {self._adapters_dir}"
            ) from None
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
]
