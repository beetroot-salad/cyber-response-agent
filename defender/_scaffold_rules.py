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
the run already spent. `body_substitutions:` is held to the same set from the other side: it is
the one key that tells this checker *not* to classify a `${name}`, so a reserved name spelled
there would put the surface one frontmatter line from optional.
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

    THE reader of `_PLACEHOLDER_RE`, exported so a writer classifies against the same grammar
    the checker will apply rather than a second copy of it — the lead lane's minter has to
    decide, at mint time, which `${name}`s of a body it must declare as `body_substitutions:`,
    and a near-miss of this pattern there mints drafts the corpus-wide sweep then refuses
    (#901: one rule, three callers, not three copies).
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

    Checked HERE because this is the seam that finally reads a template as data: a template's
    system is derived from WHERE IT SITS, while every consumer of the corpus routes on the id's
    prefix (`query_id` is `{system}.{kebab-name}`, and `lead_neighbors` keys `by_id` on it), so a
    file filed under one system's directory while calling itself `{other}.x` sends the row to
    the wrong system and mints a sibling draft besides.

    The two WRITERS are each already held to this from their own side — the minter by
    `_draft_candidate_segments`'s `system != row_system`, and the loop's commit gate by
    `lead_author._skills_path_rule`'s RF2 clause (`_frontmatter_id` vs `_membership_segment`),
    which covers a promotion. What was held to nothing is every READER that takes a template as
    data without a repo-relative path to key on: `connect`'s scaffold-time sweep and the
    corpus-wide CI check both parse the file and neither compared its id to its directory, so a
    hand-authored mismatch shipped unremarked until some consumer routed on it.
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


def check_template(t: QueryTemplate, verbs: Mapping[str, Verb]) -> list[Finding]:
    """Every well-formedness finding against one template, given its system's declared verbs."""
    out = _id_findings(t)
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
    # `model_facing_params` surface above exists to keep out, and the refusal would land at
    # `validate_params` with the gather turn already spent (#900).
    reserved = wrapper_only_params(fn)
    out.extend(
        Finding(
            "reserved-body-substitution",
            f"`body_substitutions:` names {name!r}, which {t.system}.{t.verb} reserves to a "
            f"first-party wrapper — no model may bind it, from a template or anywhere else",
        )
        for name in sorted(set(t.body_substitutions) & reserved)
    )

    if engine_of(fn) != "none":
        # An engine verb's body IS the query language, so its `${…}` are body text, not params —
        # the rule is per-VERB (`adapter.md`). Counting these as satisfied reported coverage the
        # check did not have: a system whose whole catalog is engine verbs had every template
        # skipped and every template claimed (#885).
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
        self._adapters_dir = adapters_under(Path(defender_dir))
        self._registry = ModuleVerbRegistry(self._adapters_dir, DENY_ALL)
        self._cache: dict[str, Mapping[str, Verb]] = {}

    def is_system(self, system: str) -> bool:
        """Does `system` name an adapter in this tree at all — COLD, no import.

        The membership question, which is not the same as `verbs()`'s "what does it declare":
        `defender/skills/` holds authored surfaces that are not systems of record, and a
        per-SYSTEM rule asked about one of those answers about the wrong thing.

        WHICH directories those are is deliberately not listed here. Every copy of that roster
        is one a newly authored directory falsifies, and the copy this docstring used to carry
        was already stale by a name (it omitted `judge`) while three more copies of it lived in
        the lead lane. `tests/test_hardening_772._AUTHORED_SURFACES` holds the shipped set and
        asserts it against the tree, so there is one roster and it cannot drift quietly.

        Two of the surfaces it names are agent system prompts — `gather/SKILL.md` is the gather
        subagent's whole `instructions=` and `invlang/SKILL.md` is inlined into MAIN's ORIENT
        message — which is why the lead author's WRITE gate consumes this answer too, not only
        its commit gate (#772).
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
        # raises `KeyError(system)` when it finds no adapter file — but a `KeyError` raised by
        # the adapter's own import (a module-scope `os.environ["…"]` is the shipped shape of it)
        # is indistinguishable from that one at the `except`, and swallowing it there reported a
        # file that EXISTS as missing, sending an operator to look for a path that is right where
        # it should be. Asked ahead of the import, "is there an adapter" has one answer.
        if not self.is_system(system):
            raise ScaffoldRuleError(
                f"no adapter for system {system!r} under {self._adapters_dir}"
            )
        try:
            verbs = self._registry.verbs(system)
        except (KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            # Ahead of the blanket clause below. An interrupt is the operator and a
            # cancellation is the event loop, not a broken adapter, and reporting either as one
            # makes a corpus sweep un-interruptible — `CancelledError` is a `BaseException`
            # since 3.8, so leaving it to the clause below would swallow a cancel into a
            # finding about whichever adapter happened to be importing.
            #
            # NOT imported from `query_tool`, though it names the same interrupts: `_RERAISE`
            # there is those unioned with `BudgetKill` and `CONTROL_FLOW_EXCEPTIONS` (the
            # pydantic-ai signals), and this module is the plain-data rule layer — it has no
            # pydantic-ai dependency and no budget to be killed by. Same three interrupts, the
            # subset that means anything here.
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
