#!/usr/bin/env python3

from __future__ import annotations

import functools
import inspect
import os
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.knowledge import iter_query_templates  # noqa: E402
from defender.knowledge import KnowledgePaths  # noqa: E402
from defender._io import read_text_soft  # noqa: E402
from defender._paths import adapters_under, process_defender_dir  # noqa: E402
from defender.systems import (  # noqa: E402
    ScaffoldRuleError,
    VerbResolver,
    check_system_skill,
    check_template,
)
from defender.kit.settings import PART_FILES, Part  # noqa: E402
from defender.systems.catalog import Catalog  # noqa: E402
from defender.systems.record_judgement import judge_system  # noqa: E402
from defender.systems.system_folder import read_folder  # noqa: E402
from defender.systems.system_status import (  # noqa: E402
    ReasonScope,
    cause_text,
    judge_adapter,
)
from defender.systems.verbs import (  # noqa: E402
    ADAPTER_SUFFIX,
    VerbContext,
    fresh_adapter_module,
    is_platform_served,
    RESERVED_REASON,
    read_roster,
)
from defender.kit.verbs import COMMENT_ACTION, VerbContext as AdapterContext, engine_of  # noqa: E402

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
_GLYPH = {PASS: "✓", WARN: "!", FAIL: "✗"}

# The parameter kinds that bind POSITIONALLY. Legal for the leading ctx (`query_tool`
# passes it positionally), disqualifying for every param after it.
_POSITIONAL_KINDS = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)


def _is_ctx(param: inspect.Parameter) -> bool:
    """Is the leading param annotated `VerbContext`? The kind alone is not enough: in
    `def get_host(host: str)` the tool would bind the ctx object into `host`. Accepts the
    class, the string annotation, and qualified spellings."""
    ann = param.annotation
    if ann is AdapterContext or ann is VerbContext:
        return True
    return isinstance(ann, str) and ann.rpartition(".")[2] == "VerbContext"



class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str]] = []

    def add(self, status: str, message: str) -> None:
        self.rows.append((status, message))

    def render_and_exit(self) -> None:
        for status, message in self.rows:
            print(f"  [{_GLYPH[status]}] {message}")
        fails = sum(1 for s, _ in self.rows if s == FAIL)
        warns = sum(1 for s, _ in self.rows if s == WARN)
        print(f"\n{len(self.rows)} checks: "
              f"{len(self.rows) - fails - warns} pass, {warns} warn, {fails} fail")
        raise SystemExit(1 if fails else 0)


def check_registry(report: Report, defender: Path, system: str):
    """Resolve `system`'s verbs through `VerbResolver`, the shared resolution rule (which
    already tells an adapter's own import errors from a missing adapter and lets interrupts
    through).
    """
    adapter = defender / "integrations" / f"{system.replace('-', '_')}{ADAPTER_SUFFIX}"
    if is_platform_served(system):
        # The platform serves this name itself (#1390); an adapter file claiming it is refused.
        report.add(FAIL, f"adapter module {adapter.name}: system {system!r} is {RESERVED_REASON}")
        return None
    try:
        verbs = VerbResolver(defender).verbs(system)
    except ScaffoldRuleError as exc:
        report.add(FAIL, f"adapter module {adapter.name}: {exc}")
        return None
    report.add(PASS, f"adapter {adapter.name} imports; VERBS declares {len(verbs)} verb(s)")
    if not verbs and _exports_comment_action(defender, system):
        report.add(PASS, f"VERBS is empty and the adapter exports `{COMMENT_ACTION}`: a "
                         "comment-only adapter offers the agent nothing, so no health-check")
    elif "health-check" in verbs:
        report.add(PASS, "VERBS declares a health-check verb")
    else:
        report.add(FAIL, f"VERBS declares no health-check verb (has {sorted(verbs)})")
    check_signatures(report, verbs)
    check_settings_declared(report, defender, system)
    return verbs


def _exports_comment_action(defender: Path, system: str) -> bool:
    """Does `system`'s adapter export the host's comment action (#1359)?"""
    adapters = adapters_under(defender)
    try:
        module = fresh_adapter_module(read_roster(adapters), system)
    except Exception:  # noqa: BLE001 — the resolver above already reported an adapter that will not import
        return False
    return callable(getattr(module, COMMENT_ACTION, None))


def check_settings_declared(report: Report, defender: Path, system: str) -> None:
    """The adapter declares its settings check, `check_settings(tenant)` (#1256): judged by the
    run's own judgement of an adapter (`system_status.judge_adapter`) — the one a run start makes
    of every granted system — with no run record to check over, so it stops at the declaration.
    An adapter declaring none, or a non-callable one, is down as broken in every run."""
    adapters = adapters_under(defender)
    cause = judge_adapter(
        functools.partial(fresh_adapter_module, read_roster(adapters), system), tenant=None,
        scope=ReasonScope(defender_dir=defender, adapters_root=adapters))
    if cause is None:
        report.add(PASS, "adapter declares its settings check (`check_settings`)")
    else:
        report.add(FAIL, f"settings check: {cause_text(cause)}")


def check_signatures(report: Report, verbs) -> None:
    """Every verb must be dispatchable as ``fn(ctx, **params)``, the call shape `query_tool`
    makes. `declared_params` sees only keyword-only params, so a positional param can never
    be bound by the model.

    Mirrors the checks CI's verbs-registry test applies to shipped adapters, so
    this gate is no weaker than CI."""
    broken: list[str] = []
    for name in sorted(verbs):
        fn = verbs[name]
        try:
            params = list(inspect.signature(fn).parameters.values())
        except (TypeError, ValueError):
            broken.append(f"{name}: signature is unreadable, so the tool cannot bind it")
            continue
        if not params or params[0].kind not in _POSITIONAL_KINDS:
            broken.append(f"{name}: takes no leading VerbContext parameter")
            continue
        if not _is_ctx(params[0]):
            broken.append(
                f"{name}: leading param `{params[0].name}` is not annotated `VerbContext` — "
                f"the tool passes the ctx positionally, so an unannotated leading param is "
                f"either the carriage undeclared or a model param the ctx will overwrite"
            )
            continue
        positional = [p.name for p in params[1:] if p.kind in _POSITIONAL_KINDS]
        if positional:
            broken.append(
                f"{name}: param(s) {positional} are positional — the model can only bind "
                f"keyword-only params, so spell them `*, {positional[0]}: <type>`"
            )
            continue
        var_kw = [p.name for p in params if p.kind is inspect.Parameter.VAR_KEYWORD]
        if var_kw:
            broken.append(
                f"{name}: **{var_kw[0]} widens what the function accepts without widening "
                f"what `declared_params` reports, so the validator's roster is not the "
                f"body's — spell every model param out"
            )
            continue
        unannotated = [
            p.name for p in params[1:]
            if p.kind is inspect.Parameter.KEYWORD_ONLY
            and p.annotation is inspect.Parameter.empty
        ]
        if unannotated:
            broken.append(
                f"{name}: param(s) {unannotated} carry no annotation — `validate_params` "
                f"has no type to enforce, so a quoted \"20\" reaches the body as a str"
            )
    if broken:
        for b in broken:
            report.add(FAIL, f"verb signature: {b}")
    else:
        report.add(PASS, f"{len(verbs)} verb(s) are dispatchable as fn(ctx, **params)")


class HandoffLocator:
    """How a fault names a part of connect's handoff folder (#1366 DC6): the file itself, so the operator fixes it
    before handing it to `tenant.py set-system`. The sentence is the store's; only the locator differs."""

    def __init__(self, folder: Path) -> None:
        self._folder = Path(folder)

    def system(self, system: str) -> str:
        return f"{self._folder}/"

    def part(self, system: str, part: Part) -> str:
        return str(self._folder / PART_FILES[part])

    def case(self) -> str:
        return str(self._folder / "case-record.yaml")


def check_handoff(report: Report, defender: Path, system: str, folder: Path) -> None:
    """Connect's handoff (#1366 O11): the folder holding `system`'s `config.env` and `access.yaml`, the input of
    `tenant.py set-system`, judged by the record store's own judgement (K1: the adapter's settings check over a record
    built from it, its access declaration parsed) with no tenant and no database. Each fault is the store's sentence,
    naming the file. A catalog adapter connect produces is merged and deployed before the operator applies it."""
    locator = HandoffLocator(folder)
    read = read_folder(folder, system, locator=locator)
    try:
        catalog = Catalog.of_checkout(defender)
    except Exception as e:  # noqa: BLE001 — an unreadable adapters tree is this row's failure, reported
        report.add(FAIL, f"handoff not judged: the adapters could not be listed ({type(e).__name__})")
        return
    faults = [*read.faults, *judge_system(system, settings=read.settings, access=read.access, locator=locator,
                                          catalog=catalog)]
    for fault in faults:
        report.add(FAIL, fault)
    if not faults:
        report.add(PASS, f"the handoff's config.env and access.yaml are a record the store accepts for {system}")


def check_skill(report: Report, staged: Path, system: str) -> None:
    """The per-system skill of the staged tenant half (`staged`, an agent root's shape)."""
    skill_dir = KnowledgePaths(staged).system_skill_dir(system)
    skill = skill_dir / "SKILL.md"
    if not skill.exists():
        report.add(FAIL, f"per-system skill skills/{system}/SKILL.md is missing")
        return
    text, _reason = read_text_soft(skill)
    findings = check_system_skill(skill, system)
    if findings:
        for f in findings:
            report.add(FAIL, f"skills/{system}/SKILL.md {f.message}")
    else:
        report.add(PASS, f"skills/{system}/SKILL.md has frontmatter name: defender-{system}")

    execution = skill_dir / "execution.md"
    has_inline = text is not None and "## Execution" in text
    if execution.exists():
        report.add(PASS, f"skills/{system}/execution.md exists")
    elif has_inline:
        # Inline puts the transport in the file the orchestrator reads to route, and gather
        # then hits a missing execution.md.
        report.add(WARN, "SKILL.md embeds ## Execution inline — split it into execution.md "
                         "(docs/system-skill-shape.md)")
    else:
        report.add(WARN, "no execution.md and no inline ## Execution section")


def check_templates(report: Report, staged: Path, system: str, verbs) -> None:
    """Every template of `system` in the staged tenant half, drafts included, since `_draft/`
    is where the lead-authoring lane writes. The rules are `_scaffold_rules`, shared with the
    loop's commit gate.
    """
    qdir = KnowledgePaths(staged).catalog_dir / system
    templates = [t for t in iter_query_templates(qdir.parent) if t.system == system]
    if not templates:
        report.add(WARN, f"no seed query templates under skills/gather/queries/{system}/ (they grow post-merge)")
        return
    verbs = verbs or {}
    failures: list[str] = []
    exempt = 0
    for t in templates:
        findings = check_template(t, verbs)
        failures.extend(f"{t.path.name}: {f.message}" for f in findings)
        fn = verbs.get(t.verb)
        if fn is not None and engine_of(fn) != "none":
            exempt += 1
    if failures:
        for f in failures:
            report.add(FAIL, f"template invariant: {f}")
    else:
        checked = len(templates) - exempt
        drafts = sum(1 for t in templates if "_draft" in t.path.parts)
        report.add(PASS, f"{len(templates)} template(s) name a declared verb and declare only "
                         f"real params ({drafts} draft(s) included); {checked} param-only "
                         f"template(s) satisfy the placeholder<->param invariant"
                         + (f" ({exempt} engine-verb template(s) exempt)" if exempt else ""))


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(prog=Path(sys.argv[0]).name)
    ap.add_argument("system")
    ap.add_argument(
        "--handoff", type=Path, default=None,
        help="the folder connect hands the operator: the system's config.env and access.yaml, which "
             "`tenant.py set-system` stores as the system's record; judged as the store judges it")
    ap.add_argument(
        "--staged", type=Path, default=None,
        help="the staged tenant half, laid out as the tenant's agent/ "
             "(skills/<system>/, skills/gather/queries/<system>/); without it the skill and "
             "template checks fail as unchecked")
    args = ap.parse_args()
    system = args.system
    defender = process_defender_dir()
    os.environ.setdefault("DEFENDER_DIR", str(defender))

    print(f"validate_scaffold: {system}\n")
    report = Report()
    verbs = check_registry(report, defender, system)
    # The handoff is judged with no tenant and no database: it is not a tenant's yet (#1366 O11).
    if args.handoff is None:
        report.add(WARN, "the handoff (config.env, access.yaml) not checked — give the folder with --handoff <dir>")
    else:
        check_handoff(report, defender, system, args.handoff.resolve())
    # The tenant half (system skill, seed queries) is judged where connect staged it, for
    # `tenant.py propose`; the adapter checks above read the code tree (#1108 P4 flow 6).
    if args.staged is None:
        report.add(FAIL, f"skills/{system}/ and its seed templates not checked — give the "
                         "staged tenant half with --staged <dir>")
    else:
        staged = args.staged.resolve()
        check_skill(report, staged, system)
        check_templates(report, staged, system, verbs)
    report.render_and_exit()


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    main()
