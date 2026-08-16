#!/usr/bin/env python3

from __future__ import annotations

import inspect
import os
import re
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._corpus import iter_query_templates  # noqa: E402
from defender._io import read_text_soft  # noqa: E402
from defender._scaffold_rules import (  # noqa: E402
    ScaffoldRuleError,
    VerbResolver,
    check_system_skill,
    check_template,
)
from defender.runtime.verbs import (  # noqa: E402
    ADAPTER_SUFFIX,
    VerbContext,
    engine_of,
)

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
_GLYPH = {PASS: "✓", WARN: "!", FAIL: "✗"}

# The parameter kinds that bind POSITIONALLY. Legal for the leading ctx (`query_tool`
# passes it positionally), disqualifying for every param after it.
_POSITIONAL_KINDS = (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)


def _is_ctx(param: inspect.Parameter) -> bool:
    """The leading param is the harness carriage, not a model-supplied value. Checking the
    KIND alone is not enough: `def get_host(host: str)` also has a leading positional param,
    so a verb that dropped its ctx entirely reads as well-formed and the tool then binds a
    `VerbContext` OBJECT into `host` — a silently wrong request instead of a caught error.
    Adapters carry `from __future__ import annotations`, so the annotation arrives as the
    STRING `"VerbContext"`; one without it hands over the class. Accept both, and any
    qualified spelling (`verbs.VerbContext`)."""
    ann = param.annotation
    if ann is VerbContext:
        return True
    return isinstance(ann, str) and ann.rpartition(".")[2] == "VerbContext"

_SECRET_KEYS = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)$", re.I)
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_HIGH_ENTROPY = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")



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


def _defender_dir() -> Path:
    env = os.environ.get("DEFENDER_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[2]


def check_registry(report: Report, defender: Path, system: str):
    """Resolve `system`'s verbs through `VerbResolver` — THE resolution rule, not a second
    copy of it (#901).

    This used to spell the same three verdicts inline (`KeyError` -> missing, any other
    `BaseException` -> failed to import, empty -> declares no verbs), and it carried the same
    two defects the resolver has since had fixed: a `KeyError` raised by the ADAPTER'S OWN
    import is indistinguishable from the registry's "no such adapter" one at that `except`, so
    a file that exists was reported as missing; and the blanket clause swallowed an interrupt
    or a cancellation into "broken adapter", making a scaffold sweep un-interruptible. Both
    now live in one place, with one caller here and one at the loop's commit gate.
    """
    adapter = defender / "scripts" / "adapters" / f"{system.replace('-', '_')}{ADAPTER_SUFFIX}"
    try:
        verbs = VerbResolver(defender).verbs(system)
    except ScaffoldRuleError as exc:
        report.add(FAIL, f"adapter module {adapter.name}: {exc}")
        return None
    report.add(PASS, f"adapter {adapter.name} imports; VERBS declares {len(verbs)} verb(s)")
    if "health-check" in verbs:
        report.add(PASS, "VERBS declares a health-check verb")
    else:
        report.add(FAIL, f"VERBS declares no health-check verb (has {sorted(verbs)})")
    check_signatures(report, verbs)
    return verbs


def check_signatures(report: Report, verbs) -> None:
    """Every verb must be dispatchable as ``fn(ctx, **params)`` — the ONE call shape
    `query_tool` makes (`fn(vctx, **params)`), with the model's params bound by keyword.

    A verb that takes its params positionally is not merely non-idiomatic, it is
    unusable: `declared_params` collects KEYWORD_ONLY parameters only, so a
    positional-or-keyword param is invisible to `validate_params` and the model can
    never bind it. Every call is then refused at the boundary as an unknown param, and
    the one shape that survives (`params={}`) raises TypeError on the missing positional
    inside the tool. The checklist advertised this check from the day `check_registry`
    was written and it was never here (#885).

    The four sub-checks are the four ways that call shape breaks, and they are the SAME
    four `test_verbs_registry_declares_surface` pins over the shipped adapters — a gate a
    scaffold author is told to clear before going further must not be weaker than the CI
    test that greets them afterwards."""
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


def check_config(report: Report, defender: Path, system: str) -> None:
    path = defender / "knowledge" / "environment" / "systems" / system / "config.env"
    if not path.exists():
        report.add(WARN, f"no config.env at {path.relative_to(defender)} (fine only if the adapter needs none)")
        return
    secrets_found = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if not val:
            continue
        if key.endswith("_ENV"):
            if not _ENV_NAME.match(val):
                report.add(FAIL, f"config.env: {key}={val!r} should name an env var, not hold a value")
                secrets_found = True
        elif _SECRET_KEYS.search(key):
            report.add(FAIL, f"config.env: {key} holds a value inline — reference a secret via {key}_ENV instead")
            secrets_found = True
        elif _HIGH_ENTROPY.match(val):
            report.add(WARN, f"config.env: {key} looks high-entropy — confirm it isn't a secret")
    if not secrets_found:
        report.add(PASS, "config.env carries no inline secrets")


def check_skill(report: Report, defender: Path, system: str) -> None:
    skill = defender / "skills" / system / "SKILL.md"
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

    execution = defender / "skills" / system / "execution.md"
    has_inline = text is not None and "## Execution" in text
    if execution.exists():
        report.add(PASS, f"skills/{system}/execution.md exists")
    elif has_inline:
        # Was a PASS. The inline shape is what the four stubs used, and it put each one's
        # `docker exec … curl` transport in the file the orchestrator reads to route (#261) —
        # while leaving gather to discover the missing sibling with a Read that 404s.
        report.add(WARN, "SKILL.md embeds ## Execution inline — split it into execution.md "
                         "(docs/system-skill-shape.md)")
    else:
        report.add(WARN, "no execution.md and no inline ## Execution section")


def check_templates(report: Report, defender: Path, system: str, verbs) -> None:
    """Every template of `system`, DRAFTS INCLUDED.

    The `_draft/` exclusion that used to sit here is the whole of #901: it excluded exactly the
    directory the lead-authoring lane mints into, so the one lane that writes this tree
    continuously was the one lane no content check could reach. The rule itself now lives in
    `_scaffold_rules`, which the loop's commit gate calls too — the checker and the writer meet
    because they read the same function, not because two copies were kept in step.
    """
    qdir = defender / "skills" / "gather" / "queries" / system
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
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <system>", file=sys.stderr)
        raise SystemExit(2)
    system = sys.argv[1]
    defender = _defender_dir()
    os.environ.setdefault("DEFENDER_DIR", str(defender))

    print(f"validate_scaffold: {system}\n")
    report = Report()
    verbs = check_registry(report, defender, system)
    check_config(report, defender, system)
    check_skill(report, defender, system)
    check_templates(report, defender, system, verbs)
    report.render_and_exit()


if __name__ == "__main__":
    main()
