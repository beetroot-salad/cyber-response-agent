"""The invariants that say a system's authored surface is well-formed — as DATA, for every lane
that writes it.

Two lanes write it: `connect`'s maintainer-run scaffold check, and the lead-authoring lane,
which mints `_draft/` templates (`learning/leads/draft_synthesis.py`) and promotes them into
the established catalog and into `skills/{system}/SKILL.md` continuously, post-merge. These
checks are about AUTHORED CONTENT rather than about an adapter, which is why they cover both
lanes; only `connect` writes adapters.

Two properties make this callable from a commit gate as well as from a CLI:

- **findings, not output.** Nothing here prints, and nothing raises `SystemExit`. A caller decides
  what a finding means — a `FAIL` row in `connect`'s report, a `LeadAuthorError` that refuses a
  commit, an assertion in CI.
- **no path in the message.** Each caller prefixes the locator it actually has (a file name for
  `connect`, a repo-relative path for the loop's commit gate), so neither has to strip the
  other's.

The allowed param surface is `model_facing_params`, not `declared_params`: a template's
`${placeholder}` and its `params:` list are both things a MODEL binds at dispatch, so a param
`@verb(wrapper_only=…)` reserves to a first-party wrapper is not bindable from a template.
Under `declared_params` such a template would pass here and then be refused at
`validate_params` with the run already spent. `body_substitutions:` is held to the same set
from the other side: it is the one key that tells this checker *not* to classify a `${name}`,
so a reserved name spelled there would put the surface one frontmatter line from optional.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from defender._corpus import QueryTemplate
from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_text_soft
from defender._paths import adapters_under
from defender.runtime.verb_grant import DENY_ALL
from defender.runtime.verbs import (
    ModuleVerbRegistry,
    Verb,
    engine_of,
    model_facing_params,
    wrapper_only_params,
)

#: The one checked placeholder grammar, and the only one `SCHEMA.md` documents. `lead_render`
#: additionally substitutes a bare `{name}` when it renders a handoff for display; that form is
#: deliberately NOT checked here, because a query LANGUAGE body carries braces of its own (an
#: ES|QL `GROK "%{IP:src}"` pattern is the shipped case) and checking it would make the corpus's
#: own syntax a source of false refusals.
_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}")


def placeholders(text: str) -> set[str]:
    """Every `${name}` the CHECKED grammar finds in `text`.

    THE reader of `_PLACEHOLDER_RE`, exported so any writer deciding which `${name}`s of a body
    it must declare classifies against the same grammar the checker will apply, rather than a
    second copy of it.
    """
    return set(_PLACEHOLDER_RE.findall(text))


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


def _id_findings(t: QueryTemplate) -> list[Finding]:
    """The `id: {system}.{template-id}` invariant `SCHEMA.md` states.

    A template's system is derived from WHERE IT SITS, while every consumer of the corpus
    routes on the id's prefix (`query_id` is `{system}.{kebab-name}`, and `lead_neighbors` keys
    `by_id` on it) — so a file filed under one system's directory while calling itself
    `{other}.x` sends the row to the wrong system and mints a sibling draft besides.

    Both WRITERS are already held to this from their own side (the minter by
    `_draft_candidate_segments`, the loop's commit gate by `lead_author._skills_path_rule`).
    Checked here for every READER that takes a template as data with no repo-relative path to
    key on: `connect`'s scaffold sweep and the corpus-wide CI check.
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

    Checked for the same reason `id:` is, and with more at stake. A `covers:` entry asserts
    that this file ANSWERS that identity, and `synthesize_drafts` believes it: an entry naming
    another system's identity means that system never gets that draft again — permanently,
    silently, from one copy-pasted line. It also weakens the lead lane's transfer rule, since
    any entry on any established template can discharge a departed draft's attribution.

    The shape matters as much as the prefix. `covers:` rides `_declared_names`, whose scalar
    and numeric branches are deliberately tolerant (a YAML `on` becomes the string `True`), so
    without this an unquoted `covers: on` claims the identity `"True"` and a bare
    `covers: probe` claims one no `resolve_query_id` could emit — neither matches any row, and
    both read as provenance.
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

    # A `body_substitutions:` entry is an UNCHECKED escape from the placeholder rule, so a name
    # a model may not bind must not be spellable there either: `body_substitutions:
    # [require_closed]` would otherwise readmit exactly the `@verb(wrapper_only=…)` param the
    # `model_facing_params` surface above keeps out, and the refusal would land at
    # `validate_params` with the gather turn already spent.
    reserved = wrapper_only_params(fn)
    out.extend(
        Finding(
            "reserved-body-substitution",
            f"`body_substitutions:` names {name!r}, which {t.system}.{t.verb} reserves to a "
            f"first-party wrapper — no model may bind it, from a template or anywhere else",
        )
        for name in sorted(set(t.body_substitutions) & reserved)
    )

    # A template that is not a draft must carry a `## Query`. The rule is here rather than left
    # to a consumer because every consumer degrades SILENTLY without one: `lead_render` renders
    # the empty string, `lead_neighbors` scores an empty token set, and the placeholder rule
    # below is vacuous. The reachable way to write one is a promote that copies a draft and
    # keeps its `## Executed query` heading.
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
        # An engine verb's body IS the query language, so its `${…}` are body text, not params
        # — the rule is per-VERB (`adapter.md`). Counting these as satisfied would report
        # coverage the check does not have.
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


def check_system_skill(skill_md: Path, system: str) -> list[Finding]:
    """The per-system `SKILL.md` frontmatter identity. The `execution.md` shape stays a
    `connect`-local WARN and is not here: it is authoring advice, not an invariant, and the
    pitfalls curator writes that file under a rule of its own."""
    text, reason = read_text_soft(skill_md)
    if text is None:
        # Its OWN finding, not the identity one: `read_text_soft` answers `None` for a file that
        # is unreadable or undecodable as much as for one that is absent, and reporting either as
        # "frontmatter name is not …" sends the reader to a line that may be perfectly correct.
        return [Finding("skill-unreadable", f"could not be read ({reason})")]
    front = parse_frontmatter_or_none(text)
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
    built on the worktree's adapters dir gets the worktree's adapters, not the running
    process's — which makes the gate's verdict a statement about the commit it is about to make.

    Importing those adapters is safe at that seam: the lane's scope check has already refused
    the commit if the agent touched anything outside `defender/skills/**.md`, so an adapter
    reachable here is first-party checked-in code, never agent-written.

    `DENY_ALL` is deliberate. This asks what a system DECLARES, not what a role may call —
    `verbs()` is grant-independent by construction, and passing a real role's grant would
    silently scope a well-formedness check to one role's authorization.
    """

    def __init__(self, defender_dir: Path) -> None:
        self._adapters_dir = adapters_under(Path(defender_dir))
        self._registry = ModuleVerbRegistry(self._adapters_dir, DENY_ALL)
        self._cache: dict[str, Mapping[str, Verb]] = {}

    def is_system(self, system: str) -> bool:
        """Does `system` name an adapter in this tree at all — COLD, no import.

        The membership question, which is not `verbs()`'s "what does it declare":
        `defender/skills/` holds authored surfaces that are not systems of record, and a
        per-SYSTEM rule asked about one of those answers about the wrong thing. WHICH
        directories those are is deliberately not listed here — every copy of that roster is
        one a newly authored directory falsifies; `tests/test_hardening_772._AUTHORED_SURFACES`
        holds the shipped set and asserts it against the tree.

        Two of those surfaces are agent system prompts — `gather/SKILL.md` is the gather
        subagent's whole `instructions=` and `invlang/SKILL.md` is inlined into MAIN's ORIENT
        message — which is why the lead author's WRITE gate consumes this answer too, not only
        its commit gate.
        """
        return system in self._systems()

    def _systems(self) -> frozenset[str]:
        # Not memoized: the callers that matter check a handful of paths against a tree that is
        # being written, and a glob of one directory is cheaper than a stale answer about it.
        return frozenset(self._registry.systems())

    def verbs(self, system: str) -> Mapping[str, Verb]:
        # Cached per SYSTEM because the gate asks once per changed path and a batch routinely
        # touches several templates of one system; a failure is deliberately NOT cached, so it
        # is re-raised (and re-reported) rather than remembered as an empty roster.
        if system not in self._cache:
            self._cache[system] = self._resolve(system)
        return self._cache[system]

    def _resolve(self, system: str) -> Mapping[str, Verb]:
        # The membership question FIRST, so the two verdicts stay distinguishable. `verbs()`
        # raises `KeyError(system)` when it finds no adapter file — but a `KeyError` from the
        # adapter's own import (a module-scope `os.environ["…"]`) is indistinguishable from it
        # at the `except`, and reports a file that EXISTS as missing. Asked ahead of the
        # import, "is there an adapter" has one answer.
        if not self.is_system(system):
            raise ScaffoldRuleError(
                f"no adapter for system {system!r} under {self._adapters_dir}"
            )
        try:
            verbs = self._registry.verbs(system)
        except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            # Ahead of the blanket clause below. An interrupt is the operator and a
            # cancellation is the event loop, not a broken adapter; `CancelledError` is a
            # `BaseException`, so leaving it to the clause below would swallow a cancel into a
            # finding about whichever adapter happened to be importing, making a corpus sweep
            # un-interruptible.
            #
            # NOT imported from `query_tool`, though it names the same interrupts: `_RERAISE`
            # there also carries `BudgetKill` and the pydantic-ai `CONTROL_FLOW_EXCEPTIONS`,
            # and this plain-data rule layer has neither dependency nor a budget to be killed
            # by.
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
