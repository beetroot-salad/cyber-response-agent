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
from defender._io import TEXT_READ_ERRORS, read_plain, read_text_soft  # noqa: E402
from defender._paths import process_defender_dir  # noqa: E402
from defender._scaffold_rules import (  # noqa: E402
    ScaffoldRuleError,
    VerbResolver,
    check_system_skill,
    check_template,
)
from defender.runtime.tenant_settings import (  # noqa: E402
    DOCKER_EXEC,
    SECRET_REF_SUFFIX,
    is_blank,
    is_secret_name,
    parse_env,
    system_prefix,
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

_RETIRED_ENV_SUFFIX = re.compile(r"_ENV$", re.I)
_SECRET_KEYS = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API[_-]?KEY)$", re.I)
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


def check_registry(report: Report, defender: Path, system: str):
    """Resolve `system`'s verbs through `VerbResolver` — THE resolution rule, not a second copy
    of it. Spelling the verdicts inline invites two defects the resolver already handles: a
    `KeyError` raised by the ADAPTER'S OWN import is indistinguishable from the registry's "no
    such adapter" one, and a blanket `except BaseException` swallows an interrupt into "broken
    adapter", making a scaffold sweep un-interruptible.
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

    A verb that takes its params positionally is not merely non-idiomatic, it is unusable:
    `declared_params` collects KEYWORD_ONLY parameters only, so a positional-or-keyword param
    is invisible to `validate_params` and the model can never bind it. Every call is then
    refused at the boundary as an unknown param, and the one shape that survives (`params={}`)
    raises TypeError on the missing positional inside the tool.

    The four sub-checks are the four ways that call shape breaks, and they are the SAME four
    `test_verbs_registry_declares_surface` pins over the shipped adapters — a gate a scaffold
    author clears before going further must not be weaker than the CI test that greets them
    afterwards."""
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


def _why_unreadable(error: Exception) -> str:
    """A short cause for a file that could not be read — never its content."""
    if isinstance(error, UnicodeDecodeError):
        return "is not valid UTF-8"
    return (error.strerror if isinstance(error, OSError) else None) or type(error).__name__


def _secret_entries(report: Report, settings_dir: Path) -> dict[str, str] | None:
    """The tenant's `secrets.env` entries, or `None` after a FAIL row saying it could not be read.

    A missing file is an empty one (each declared reference then FAILs as having no entry). A
    file that is not a plain regular file (a directory, a FIFO — never opened blocking), is not
    UTF-8, or cannot be read is one FAIL and no further verdict about the references: a PASS for
    what could not be read would be a lie. Parsed by the platform's own `parse_env`, the one
    parser, so the validator and the run agree on every quoting rule. A VALUE is never put in a
    row."""
    path = settings_dir / "secrets.env"
    try:
        text = read_plain(path)
    except FileNotFoundError:
        return {}
    except TEXT_READ_ERRORS as e:
        report.add(FAIL, f"secrets.env could not be read ({_why_unreadable(e)}) — the references "
                         "in config.env cannot be checked against it")
        return None
    return parse_env(text)


def _check_access_method(report: Report, entries: dict[str, str], prefix: str) -> None:
    """`<PREFIX>_TRANSPORT` is `docker-exec` and `<PREFIX>_DOCKER_CONTEXT` is set: both required,
    neither defaulted."""
    transport, context = f"{prefix}_TRANSPORT", f"{prefix}_DOCKER_CONTEXT"
    if is_blank(entries.get(transport, "")):
        report.add(FAIL, f"config.env: {transport} is not set — name the access method "
                         f"({DOCKER_EXEC}); there is no default")
    elif entries[transport] != DOCKER_EXEC:
        report.add(FAIL, f"config.env: {transport}={entries[transport]!r} is not an implemented "
                         f"access method (only {DOCKER_EXEC})")
    if is_blank(entries.get(context, "")):
        report.add(FAIL, f"config.env: {context} is not set — name the docker context the "
                         "system is reached over; there is no default")


def _check_reference(report: Report, key: str, val: str) -> bool:
    """One `*_SECRET_REF` key: spelled all-uppercase, non-blank, name-shaped. Whether it is a
    reference worth looking up in `secrets.env`. Names the key only — what a malformed reference
    holds may be the secret itself."""
    if key != key.upper():
        report.add(FAIL, f"config.env: {key} is a mis-spelled reference — spell it {key.upper()}")
    elif is_blank(val):
        report.add(FAIL, f"config.env: {key} is blank — name the secrets.env entry it refers to")
    elif not is_secret_name(val):
        report.add(FAIL, f"config.env: {key} must name a secrets.env entry (letters, digits and "
                         "underscore, not starting with a digit), not hold a value")
    else:
        return True
    return False


def _check_values(report: Report, entries: dict[str, str]) -> list[tuple[str, str]]:
    """Every key's value, judged: the references (returned, for the `secrets.env` lookup), the
    inline secrets (FAIL) and the high-entropy values (WARN). The retired `<KEY>_ENV` convention
    gets no treatment of its own — a leftover is judged by the secret name it carries."""
    inline_secret = False
    references: list[tuple[str, str]] = []
    for key, val in entries.items():
        if key.upper().endswith(SECRET_REF_SUFFIX):
            if _check_reference(report, key, val):
                references.append((key, val))
        elif is_blank(val):
            continue
        elif _SECRET_KEYS.search(_RETIRED_ENV_SUFFIX.sub("", key)):
            stem = _RETIRED_ENV_SUFFIX.sub("", key)
            report.add(FAIL, f"config.env: {key} holds a value inline — reference a secret via "
                             f"{stem}{SECRET_REF_SUFFIX} instead, with the value in the tenant's "
                             "secrets.env")
            inline_secret = True
        elif _HIGH_ENTROPY.match(val):
            report.add(WARN, f"config.env: {key} looks high-entropy — confirm it isn't a secret")
    if not inline_secret:
        report.add(PASS, "config.env carries no inline secrets")
    return references


def check_config(report: Report, settings_dir: Path, system: str) -> None:
    """`system`'s `config.env` in the connected tenant's `settings/` folder (#1106), and its
    references into the tenant's `secrets.env` (#1107).

    Checked: the access method (`<PREFIX>_TRANSPORT=docker-exec` and `<PREFIX>_DOCKER_CONTEXT`,
    both required, no default); that no key holds a secret inline; and that every
    `<KEY>_SECRET_REF` is spelled all-uppercase, holds a name-shaped, non-blank value, and names an
    entry of `secrets.env` that exists and is non-blank. The report names keys and entry NAMES,
    never a value from either file — and never the string a malformed reference holds, which may
    be the secret itself."""
    path = settings_dir / "systems" / system / "config.env"
    if not path.exists():
        report.add(WARN, f"no config.env at {path} (fine only if the adapter needs none)")
        return
    try:
        entries = parse_env(read_plain(path))
    except TEXT_READ_ERRORS as e:
        report.add(FAIL, f"config.env could not be read ({_why_unreadable(e)})")
        return
    _check_access_method(report, entries, system_prefix(system))
    references = _check_values(report, entries)
    if not references:
        return
    held = _secret_entries(report, settings_dir)
    if held is None:
        return
    missing = [(key, name) for key, name in references if is_blank(held.get(name, ""))]
    for key, name in missing:
        report.add(FAIL, f"config.env: {key} refers to {name}, which has no non-blank entry in "
                         "the tenant's secrets.env")
    if not missing:
        report.add(PASS, f"{len(references)} secret reference(s) name non-blank entries of the "
                         "tenant's secrets.env")


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
        # Not a PASS: the inline shape puts the system's `docker exec … curl` transport in the
        # file the orchestrator reads to route, and leaves gather to discover the missing
        # sibling with a Read that 404s.
        report.add(WARN, "SKILL.md embeds ## Execution inline — split it into execution.md "
                         "(docs/system-skill-shape.md)")
    else:
        report.add(WARN, "no execution.md and no inline ## Execution section")


def check_templates(report: Report, defender: Path, system: str, verbs) -> None:
    """Every template of `system`, DRAFTS INCLUDED.

    Drafts are NOT excluded: `_draft/` is exactly the directory the lead-authoring lane mints
    into, so excluding it leaves the one lane that writes this tree continuously unchecked. The
    rule lives in `_scaffold_rules`, which the loop's commit gate calls too — the checker and
    the writer meet because they read the same function.
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
    import argparse

    from defender._tenants import TenantDirError, add_tenant_arguments, entry_tenant

    ap = argparse.ArgumentParser(prog=Path(sys.argv[0]).name)
    ap.add_argument("system")
    add_tenant_arguments(ap, reads="holds the connected system's config.env")
    args = ap.parse_args()
    system = args.system
    defender = process_defender_dir()
    os.environ.setdefault("DEFENDER_DIR", str(defender))

    print(f"validate_scaffold: {system}\n")
    report = Report()
    verbs = check_registry(report, defender, system)
    # An unresolvable tenant WARNs rather than exits: the config check is advisory (an absent
    # config.env only warns), and the scaffold's other checks still run.
    try:
        settings_dir = entry_tenant(defender, args.tenants_root, args.tenant).settings
    except TenantDirError as refusal:
        report.add(WARN, f"config.env not checked — the tenant's settings folder could not be "
                         f"resolved: {refusal}")
    else:
        check_config(report, settings_dir, system)
    check_skill(report, defender, system)
    check_templates(report, defender, system, verbs)
    report.render_and_exit()


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    main()
