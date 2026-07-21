"""Executable spec for #620 — the AUTHORING CONTRACT half (slice 3).

Spec graph: ``defender/tests/spec_graph_620-consumers-connect.yaml``. Each test realizes one
demand of that graph and is named after the demand id (the id is repeated in the docstring).

These tests assert over STATIC file/corpus CONTENT — the query-template corpus, ``SCHEMA.md``,
the three ``execution.md`` files, the ``connect`` skill + its examples, the always-injected
gather prompt, the pitfalls-curator prompt, the oracle prompt, and the design docs that teach
authoring against the #611/#617 migration.

**RED BY CONSTRUCTION.** Every import here resolves against HEAD (only existing corpus machinery
is imported), but the *assertions* describe the POST-migration content. Today the templates still
fence bare argv, ``SCHEMA.md`` still names the deleted ``shell/SQL-shaped`` category, the connect
skill still teaches ``AdapterArgumentParser``/the shim, and the docs still cite the dead CLI
contract — so these tests are RED against current file content and go GREEN once
write-code-from-spec edits the files. That is the correct red.

Several assertions pin an *intended post-migration shape* the spec fixes but does not spell out
byte-for-byte (the exact frontmatter keys the corpus gains, the exact wording a re-homed doc
adopts). Those are flagged in-line with ``ASSUMED POST-MIGRATION SHAPE`` so the reviewer can
reconcile them against the spec / the shipped code.
"""
from __future__ import annotations

import importlib.util
import inspect
import py_compile
import re
import sys
from pathlib import Path

from defender import _corpus
from defender._frontmatter import parse_frontmatter
from defender.learning.leads import lead_neighbors as ln
from defender.runtime import circuit_breaker

_DEFENDER = Path(__file__).resolve().parents[1]
_ROOT = _DEFENDER.parent
_QUERIES = _DEFENDER / "skills" / "gather" / "queries"
_SCHEMA = _QUERIES / "SCHEMA.md"
_CONNECT = _DEFENDER / "skills" / "connect"
_EXAMPLES = _CONNECT / "examples"
_DOCS = _DEFENDER / "docs"
_HANDBOOK = _DEFENDER / "skills" / "handbook" / "content"

_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}")



def _established():
    """Every ESTABLISHED template (outside ``_draft/``), as ``_corpus.QueryTemplate``."""
    return [
        t for t in _corpus.iter_query_templates(_QUERIES)
        if "_draft" not in t.path.parts
    ]


def _fm_and_query(path: Path) -> tuple[dict, str]:
    """``(frontmatter, ## Query body)`` for a template file."""
    fm, body = parse_frontmatter(path.read_text(encoding="utf-8"))
    return fm, _corpus.section_bodies(body).get("Query", "")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


_ARGV_TEMPLATES = [
    _QUERIES / "change-mgmt" / "active-changes.md",
    _QUERIES / "change-mgmt" / "get-change.md",
    _QUERIES / "change-mgmt" / "list-changes.md",
    _QUERIES / "cmdb" / "host-trust-edges.md",
    _QUERIES / "cmdb" / "hostname-by-ip.md",
    _QUERIES / "identity" / "user-authorization.md",
]
_POINTER_TEMPLATES = [
    _QUERIES / "cmdb" / "list-all-hosts.md",
    _QUERIES / "identity" / "access-check.md",
    _QUERIES / "identity" / "user-profile.md",
    _QUERIES / "host-state" / "authorized-keys.md",
    _QUERIES / "host-state" / "package-list.md",
    _QUERIES / "host-state" / "user-account.md",
]
_NON_QUERY_TODAY = _ARGV_TEMPLATES + _POINTER_TEMPLATES



def test_every_established_query_is_a_query():
    """demand: every_established_query_is_a_query.

    Every established template's ## Query body must be a query or a structured call — not a
    bare argv fragment (the 6 change-mgmt/cmdb/identity ones), not a ``# See … SKILL.md``
    pointer comment (the 6 cmdb/host-state/identity ones), and sshd-auth-event-by-id.md stops
    teaching ``arg0`` by name and the ``exit=2`` claim.
    """
    for t in _established():
        q = t.query
        assert q.strip(), f"{t.path}: empty ## Query (positive control — every template has one)"

        assert not re.search(r"See\b.*SKILL\.md", q), \
            f"{t.path}: ## Query is a `See … SKILL.md` pointer, not a query"

        assert not re.search(r"--[a-z]", q), \
            f"{t.path}: ## Query still carries a CLI --flag argv fragment"

        non_comment = [ln_ for ln_ in q.splitlines()
                       if ln_.strip() and not ln_.strip().startswith(("#", "```", "~~~"))]
        assert non_comment, f"{t.path}: ## Query has no non-comment content — a pointer stub"

        assert t.status
    for path in _NON_QUERY_TODAY:
        fm, _q = _fm_and_query(path)
        assert fm.get("verb"), (
            f"{path}: a non-query ## Query must be reshaped into a verb-declaring structured "
            f"call — the template declares no `verb:` (ASSUMED post-migration frontmatter key)"
        )

    sshd_by_id = _read(_QUERIES / "elastic" / "sshd-auth-event-by-id.md")
    assert "arg0" not in sshd_by_id, "sshd-auth-event-by-id.md still names the dead `arg0` param"
    assert "exit=2" not in sshd_by_id, "sshd-auth-event-by-id.md still claims exit=2 for a param mistake"


def test_draft_arg0_raw_templates_are_dropped():
    """demand: draft_arg0_raw_templates_are_dropped.

    The 33 ``_draft/`` templates carrying the dead ``bound params`` marker (an ``arg0`` positional
    plus ``raw: True``) are DROPPED, not migrated. The drop must leave lead_neighbors' catalog
    walk + IDF coherent — no import error, no zero-corpus divide.
    """
    offenders = [
        t.path for t in _corpus.iter_query_templates(_QUERIES)
        if "'raw': True" in t.body or "'arg0'" in t.body
    ]
    assert offenders == [], (
        f"{len(offenders)} template(s) still carry the dropped `arg0`/`raw: True` bound-params "
        f"marker (should be deleted): {[str(p) for p in offenders[:5]]}"
    )

    catalog = ln.load_catalog(_QUERIES)
    assert catalog, "load_catalog returned nothing after the drop (catalog walk broke)"
    idf = ln.build_idf(ln._all_query_variants(catalog))
    assert idf, "build_idf produced an empty IDF over the post-drop corpus"


def test_placeholder_is_a_declared_param_or_marked_body_substitution():
    """demand: placeholder_is_a_declared_param_or_marked_body_substitution.

    The corpus invariant must FAIL a template whose ``${placeholder}`` is neither a declared
    param of the template's verb NOR explicitly marked a query-body substitution. The rule is
    VERB-dependent (``${start}`` is a param of elastic.query but body text in esql), so the
    corpus must FIRST gain a per-template verb / body-substitution declaration — enforcing it
    keyed on the SYSTEM repeats the ``_is_esql`` mistake.

    ASSUMED POST-MIGRATION SHAPE: the corpus declares, per template, a ``verb:`` key, a
    ``params:`` list (declared-param members), and a ``body_substitutions:`` list (the
    in-body-text placeholders). The check classifies each ``${x}`` into
    declared-param / body-substitution / neither and fails on ``neither`` (or on no verb).
    """

    def violations(fm: dict, query_body: str) -> set[str]:
        placeholders = set(_PLACEHOLDER_RE.findall(query_body))
        if not fm.get("verb"):
            return placeholders
        params = fm.get("params") or []
        names: set[str] = set()
        if isinstance(params, list):
            for p in params:
                if isinstance(p, str):
                    names.add(p)
                elif isinstance(p, dict):
                    names.update(str(k) for k in p)
        elif isinstance(params, dict):
            names.update(str(k) for k in params)
        subs = fm.get("body_substitutions") or []
        sub_names = {str(s) for s in subs} if isinstance(subs, (list, tuple)) else set()
        return {p for p in placeholders if p not in names and p not in sub_names}

    def passes(text: str) -> bool:
        fm, body = parse_frontmatter(text)
        q = _corpus.section_bodies(body).get("Query", "")
        return bool(fm.get("verb")) and not violations(fm, q)

    good = (
        "---\nid: cmdb.get-host-demo\nstatus: established\n"
        "verb: get-host\nparams: [host]\n---\n\n"
        "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${host}\n```\n"
    )
    bad_undeclared = (
        "---\nid: cmdb.get-host-demo\nstatus: established\n"
        "verb: get-host\nparams: [host]\n---\n\n"
        "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${mystery}\n```\n"
    )
    bad_no_verb = (
        "---\nid: cmdb.get-host-demo\nstatus: established\n---\n\n"
        "## Query\n\n```\nget-host ${host}\n```\n"
    )
    assert passes(good), "a verb-declaring template with every placeholder declared must pass"
    assert not passes(bad_undeclared), "an undeclared ${placeholder} must FAIL the invariant"
    assert not passes(bad_no_verb), "a template that declares no verb is undecidable -> FAIL"

    failing = [t.path for t in _established() if not passes(_read(t.path))]
    assert failing == [], (
        f"{len(failing)} established template(s) fail the placeholder<->param invariant "
        f"(the corpus has not yet gained per-template verb / body-substitution declarations): "
        f"{[str(p) for p in failing[:5]]}"
    )


def test_body_substitution_distinguishable_and_schema_documents_it():
    """demand: body_substitution_distinguishable_and_schema_documents_it.

    A body substitution is distinguishable from a param binding in the corpus, and SCHEMA.md
    documents it. SCHEMA.md's ``engine:`` heuristic (naming the deleted ``shell/SQL-shaped
    systems`` category), its "one CLI invocation" template definition, and its ``` ```bash ```
    fence sanction are corrected; the untagged-KQL-fence gap is documented; and ``filter_keys``
    is REMOVED from the 2 templates carrying it.
    """
    carriers = [t.path for t in _corpus.iter_query_templates(_QUERIES)
                if "filter_keys" in _read(t.path)]
    assert carriers == [], f"filter_keys still present in: {[str(p) for p in carriers]}"

    schema = _read(_SCHEMA)
    assert "shell/SQL-shaped" not in schema, \
        "SCHEMA.md still names the deleted 'shell/SQL-shaped systems' engine category"
    assert "one CLI invocation" not in schema, \
        "SCHEMA.md still defines a template as 'one CLI invocation'"
    assert "```bash" not in schema, "SCHEMA.md still sanctions a ```bash query fence"

    low = schema.lower()
    assert "```query" in schema, "SCHEMA.md does not document the structured ```query render"
    assert "kql" in low, "SCHEMA.md does not document the (untagged) KQL fence"
    assert "body substitution" in low or "body-substitution" in low, \
        "SCHEMA.md does not document the body-substitution vs param distinction"


def test_lead_neighbors_scores_the_new_param_only_fence():
    """demand: lead_neighbors_scores_the_new_param_only_fence.

    A param-only template's new structured ## Query fence produces a non-degenerate token
    variant in ``lead_neighbors._query_variants``, and the scorer still discriminates
    same-measurement siblings. ``PLUMBING_TOKENS`` drops ``start``/``end``/``limit``, which are
    real params of elastic.query/alerts — the migration must not silently collapse that signal.
    """
    fence_a = "```query\nverb: get-host\nparams:\n  host: web-1\n```"
    fence_b = "```query\nverb: list-hosts\nparams:\n  role: bastion\n```"

    var_a = ln._query_variants(fence_a)
    tokens_a = frozenset().union(*var_a) if var_a else frozenset()
    var_b = ln._query_variants(fence_b)
    tokens_b = frozenset().union(*var_b) if var_b else frozenset()

    assert tokens_a - ln.PLUMBING_TOKENS, "structured param-only fence tokenized to only plumbing"
    assert "get-host" in tokens_a, f"structured fence lost its verb token: {sorted(tokens_a)}"
    assert "web-1" in tokens_a, f"structured fence lost its value token: {sorted(tokens_a)}"
    assert tokens_a != tokens_b, "two distinct param-only measurements collapsed to one variant"

    assert "start" not in ln.PLUMBING_TOKENS, "start is a real param — must not be dropped as plumbing"
    assert "end" not in ln.PLUMBING_TOKENS, "end is a real param — must not be dropped as plumbing"
    assert "limit" not in ln.PLUMBING_TOKENS, "limit is a real param — must not be dropped as plumbing"



def test_pitfalls_prompt_names_reachable_sections_and_failures():
    """demand: pitfalls_prompt_names_reachable_sections_and_failures.

    ``lead_pitfalls.md`` aims the curator at ``## Verbs`` (not the ``## CLI`` heading #617
    renamed), names reachable failure classes (an exit-64 param error, not "a wrong CLI flag"
    and not the shell-newline pitfall — nothing shells out), and the non-existent ``siem``
    system is gone.
    """
    prompt = _read(_DEFENDER / "learning" / "leads" / "lead_pitfalls.md")

    assert "## CLI" not in prompt, "lead_pitfalls.md still points the curator at a ## CLI heading"
    assert "## Verbs" in prompt, "lead_pitfalls.md must aim the curator at the ## Verbs surface"
    assert "wrong CLI flag" not in prompt, "lead_pitfalls.md still names an unreachable 'wrong CLI flag'"
    assert "ends the shell command" not in prompt, \
        "lead_pitfalls.md still teaches the unreachable shell-newline pitfall (nothing shells out)"
    assert not re.search(r"\bsiem\b", prompt), "lead_pitfalls.md still uses the non-existent 'siem' system"
    assert "64" in prompt, "lead_pitfalls.md must name the exit-64 param-error failure class"


def test_pitfalls_keeps_exit_64_and_reshapes_examples():
    """demand: pitfalls_keeps_exit_64_and_reshapes_examples.

    An exit-64 (agent-fixable) row STAYS in the pitfalls queue — a wrong param name is exactly
    the agent-fixable signal the lane exists for — and the prompt's exemplars are reshaped from
    CLI flags to param errors.
    """
    assert circuit_breaker.error_class_for_exit(64) == "agent-fixable"
    assert circuit_breaker.error_class_for_exit(2) == "infra"

    prompt = _read(_DEFENDER / "learning" / "leads" / "lead_pitfalls.md")
    assert "`index=windows`" not in prompt, \
        "lead_pitfalls.md still exemplifies a CLI index-flag mistake instead of a param error"
    assert "`index:windows`" not in prompt, \
        "lead_pitfalls.md still exemplifies a CLI index-flag mistake instead of a param error"
    assert "shell command" not in prompt, \
        "lead_pitfalls.md still exemplifies a shell-command mistake (nothing shells out)"
    assert re.search(r"param", prompt), "lead_pitfalls.md exemplars do not name a param mistake"


def test_execution_md_documents_exit_64_and_index_off_flags():
    """demand: execution_md_documents_exit_64_and_index_off_flags.

    Each ``execution.md`` ``## Exit codes`` documents 64 (the code a model's own param mistake
    now produces). ``elastic/execution.md`` ``## Index-pattern selection`` is off the ``--index``
    CLI-flag surface, consistent with its own 'no command, no --help' ## Verbs opening.
    """
    for system in ("elastic", "cmdb", "identity"):
        text = _read(_DEFENDER / "skills" / system / "execution.md")
        sections = _corpus.section_bodies(text)
        exit_codes = sections.get("Exit codes", "")
        assert exit_codes.strip(), f"{system}/execution.md has no ## Exit codes section"
        assert "64" in exit_codes, f"{system}/execution.md ## Exit codes does not document 64"

    elastic = _read(_DEFENDER / "skills" / "elastic" / "execution.md")
    idx = _corpus.section_bodies(elastic).get("Index-pattern selection", "")
    assert idx.strip(), "elastic/execution.md lost its ## Index-pattern selection section"
    assert "--index" not in idx, \
        "elastic/execution.md ## Index-pattern selection still teaches the --index CLI flag"
    assert "logs-system.auth-*" in idx, \
        "elastic/execution.md ## Index-pattern selection no longer lists the index patterns"



def test_gather_prompt_does_not_hardcode_esql_for_every_system():
    """demand: gather_prompt_does_not_hardcode_esql_for_every_system.

    ``skills/gather/SKILL.md`` — loaded whole for EVERY gather dispatch regardless of system —
    does not present ``verb='esql'`` / the esql call as THE universal query shape: neither its
    worked example nor its ORIENT line teaches a cmdb dispatch an esql call it cannot make.
    """
    skill = _read(_DEFENDER / "skills" / "gather" / "SKILL.md")

    assert "the query language is **ES|QL**" not in skill, \
        "gather/SKILL.md ORIENT still tells every dispatch the query language is ES|QL"
    assert not re.search(r'query\(system="<system>",\s*verb="esql"', skill), \
        "gather/SKILL.md worked example hardcodes verb=\"esql\" for a generic system=\"<system>\""


def test_gather_prompt_positive_control():
    """demand: gather_prompt_positive_control.

    Positive control: the gather prompt still teaches the real ``query()`` call shape
    (system/verb/params) — the esql-generalisation is removed, not the query-tool guidance.
    """
    skill = _read(_DEFENDER / "skills" / "gather" / "SKILL.md")
    assert "query(system=" in skill, "gather/SKILL.md dropped the query() call shape entirely"
    assert re.search(r"\bverb=", skill), "gather/SKILL.md no longer names the verb param"
    assert re.search(r"\bparams=", skill), "gather/SKILL.md no longer names the params arg"



def _connect_skill_text() -> str:
    parts = []
    for name in ("SKILL.md", "adapter.md", "checklist.md", "decisions.md"):
        p = _CONNECT / name
        if p.exists():
            parts.append(_read(p))
    return "\n".join(parts)


def test_connect_teaches_the_registry_contract_not_the_shim():
    """demand: connect_teaches_the_registry_contract_not_the_shim.

    ``connect/`` stops teaching the shim / --help alignment-loop / ``resolve_auth`` / ``die()``
    / ``EXIT_*`` contract (which contradicts ``bin/README.md:48`` "do NOT drop a shim"), AND
    teaches the replacement: a module is importable + ``VERBS`` declares its verbs, examples
    compiling against ``faults.py`` / ``VerbContext`` / a returning health-check. A pure
    negative would pass on an empty skill — the replacement must be PRESENT too.
    """
    text = _connect_skill_text()

    assert "AdapterArgumentParser" not in text, "connect/ still teaches AdapterArgumentParser"
    assert "EXIT_USAGE" not in text, "connect/ still teaches the EXIT_* / die() adapter contract"
    assert "resolve_auth" not in text, "connect/ still routes credentials through _adapter.resolve_auth"
    assert not re.search(r"[Rr]egister the shim", text), "connect/ still tells the author to register a shim"

    assert "VERBS" in text, "connect/ does not teach the VERBS registry contract"
    assert "faults" in text, "connect/ does not point authors at the faults.py taxonomy"


def _load_example(name: str):
    """Load a connect example module by path, with examples/ and the worktree root on sys.path
    so both the current (`from _adapter import …`) and the migrated (`from defender…`) import
    forms resolve."""
    for p in (str(_EXAMPLES), str(_ROOT)):
        if p not in sys.path:
            sys.path.insert(0, p)
    path = _EXAMPLES / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_connect_example_{name}", path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_connect_examples_compile_against_the_live_tree():
    """demand: connect_examples_compile_against_the_live_tree.

    ``connect/examples/`` modules import/compile against the current tree and instantiate the
    LIVE shape (a ``VERBS`` mapping, ``VerbContext``, ``faults.py``, a health-check that RETURNS
    a dict) — not ``AdapterArgumentParser`` / ``build_parser`` / ``main()`` / ``die()`` /
    ``EXIT_*`` / a bash shim, none of which any shipped adapter imports.
    """
    for py in sorted(_EXAMPLES.glob("*.py")):
        py_compile.compile(str(py), doraise=True)

    example_adapter = _load_example("example_adapter")

    assert isinstance(getattr(example_adapter, "VERBS", None), dict), \
        "example_adapter.py exposes no VERBS mapping"
    assert example_adapter.VERBS, "example_adapter.py exposes an empty VERBS mapping"
    assert "health-check" in example_adapter.VERBS, "example_adapter.py VERBS declares no health-check"
    src = inspect.getsource(example_adapter)
    assert "VerbContext" in src, "example_adapter.py does not reference VerbContext"
    assert "faults" in src, "example_adapter.py does not use the faults.py taxonomy"

    hc = example_adapter.VERBS["health-check"]
    hc_src = inspect.getsource(hc)
    assert re.search(r"\breturn\b", hc_src), "example_adapter health-check does not return a value"
    assert "print(" not in hc_src, \
        "example_adapter health-check still prints instead of returning a dict"
    assert "SystemExit" not in hc_src, \
        "example_adapter health-check still raises SystemExit instead of returning a dict"

    for name in ("example_adapter", "_adapter"):
        if not (_EXAMPLES / f"{name}.py").exists():
            continue
        mod = _load_example(name)
        for dead in ("AdapterArgumentParser", "build_parser", "main", "die", "resolve_auth",
                     "EXIT_USAGE"):
            assert not hasattr(mod, dead), f"examples/{name}.py still defines the dead symbol {dead!r}"



def test_dead_contract_docs_rehomed():
    """demand: dead_contract_docs_rehomed.

    ``scripts/adapters/README.md``, ``docs/system-skill-shape.md``,
    ``docs/state-surface-adapters.md``, ``docs/lead-author-failure-pitfalls.md:70`` (mis-cites
    ``examples/_adapter.py`` as the exit taxonomy — it is ``faults.py``), and the handbook name
    the query-tool/VERBS contract and NOT the dead shim/AdapterArgumentParser/
    ``print(json.dumps(payload))``/register-the-shim one — the new-contract text is PRESENT, not
    merely the old absent. (lint_stale_refs cannot gate this, so these assertions ARE the gate.)

    ASSUMED POST-MIGRATION SHAPE: each doc names the query-tool / ``VERBS`` / ``faults.py``
    contract (any of the listed ``live`` tokens present); the exact wording is the author's.
    """
    cases = [
        (_DEFENDER / "scripts" / "adapters" / "README.md",
         ["AdapterArgumentParser", "print(json.dumps(payload))"],
         ["VERBS", "query tool"]),
        (_DOCS / "system-skill-shape.md",
         ["Adapter CLI invocation pattern", "Flag conventions"],
         ["VERBS", "query tool", "verb"]),
        (_DOCS / "state-surface-adapters.md",
         ["one subcommand per query verb", "must be authoritative"],
         ["VERBS", "query tool"]),
        (_DOCS / "lead-author-failure-pitfalls.md",
         ["examples/_adapter.py"],
         ["faults.py"]),
        (_HANDBOOK / "runtime-loop.md",
         ["runs the system CLIs"],
         ["query tool", "VERBS"]),
        (_HANDBOOK / "knowledge-and-skills.md",
         ["how its CLI is dispatched"],
         ["query tool", "VERBS", "verbs are dispatched"]),
    ]
    for path, dead, live in cases:
        text = _read(path)
        for token in dead:
            assert token not in text, f"{path.name}: still carries dead-contract text {token!r}"
        assert any(tok in text for tok in live), \
            f"{path.name}: names no replacement contract (expected one of {live})"



def test_oracle_prompt_teaches_a_runnable_call():
    """demand: oracle_prompt_teaches_a_runnable_call.

    ``pipeline/oracle/prompt.md`` stops teaching ``params:{kql:'…'}`` on a fictitious 'sentinel'
    system (``kql`` is a param of no verb — rejected exit 64); its example is a call the real
    registry accepts.
    """
    prompt = _read(_DEFENDER / "learning" / "pipeline" / "oracle" / "prompt.md")

    assert not re.search(r"\bkql\b", prompt), "oracle prompt still teaches a `kql` param (no verb has one)"
    assert not re.search(r"\bsentinel\b", prompt), "oracle prompt still uses the fictitious 'sentinel' system"
    assert "native_query" in prompt, \
        "oracle prompt's example does not use a real registry param (e.g. native_query)"
