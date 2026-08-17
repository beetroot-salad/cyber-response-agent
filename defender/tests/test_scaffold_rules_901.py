"""#901 — the scaffold invariants as one rule, over every lane that writes `defender/skills/`.

The invariants lived in `skills/connect/validate_scaffold.py`, run by a maintainer at scaffold
time, and `check_templates` selected `"_draft" not in t.path.parts` — the exact directory the
lead-authoring lane mints into. The checker and the writer could not meet, so a lead-authored
template whose `${placeholder}` is not a param its verb declares was refused by nothing.

What is pinned here, and why each one is a control rather than a restatement:

- the RULE, `_scaffold_rules.check_template`, findings-per-defect, including the two the fold
  closed on the way past (a `params:` entry the verb does not declare, and a placeholder naming
  a `@verb(wrapper_only=…)` param no model may bind);
- the SCOPE, over the shipped corpus WITH drafts. The pre-existing sweeps
  (`test_620_consumers.py::test_validate_scaffold_green_on_all_seven_via_registry_probe`) are
  green-tree checks: they pass today and would pass unchanged against a fix that enforced
  nothing new, so a corpus assertion alone does not discriminate. The negative controls that do
  live at each lane's own seam — `test_lead_author.py` for the commit gate,
  `test_lead_author_synth.py` for the minter;
- the RESOLVER, which must answer about the tree it was handed and not the one this process
  imported from — the property the loop's gate depends on, since it runs from the main checkout
  and gates a drain worktree.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _scaffold_rules
from defender._corpus import iter_query_templates, read_query_template
from defender.runtime.verbs import engine_for, engine_of

_DEFENDER = Path(__file__).resolve().parents[1]
_CATALOG = _DEFENDER / "skills" / "gather" / "queries"
_ADAPTERS = _DEFENDER / "scripts" / "adapters"
_ALL_SEVEN = (
    "elastic", "identity", "cmdb", "ticket", "change-mgmt", "threat-intel", "host-state",
)


@pytest.fixture(scope="module")
def resolver() -> _scaffold_rules.VerbResolver:
    return _scaffold_rules.VerbResolver(_DEFENDER)


def _codes(text: str, system: str, tmp_path: Path, resolver) -> list[str]:
    """`check_template`'s finding codes for `text` filed under `system/`.

    Written to disk and read back through `read_query_template` on purpose: the system a
    template belongs to is derived from its LOCATION, and a test that constructs the
    `QueryTemplate` by hand would be checking a shape the corpus never produces.
    """
    d = tmp_path / system
    d.mkdir(parents=True, exist_ok=True)
    path = d / "probe.md"
    path.write_text(text, encoding="utf-8")
    template, reason = read_query_template(path)
    assert template is not None, reason
    return [f.code for f in _scaffold_rules.check_template(template, resolver.verbs(system))]


_GOOD = (
    "---\nid: cmdb.probe\nstatus: established\nverb: get-host\nparams: [host]\n---\n\n"
    "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${host}\n```\n"
)


def test_a_well_formed_template_has_no_findings(tmp_path, resolver):
    assert _codes(_GOOD, "cmdb", tmp_path, resolver) == []


def test_a_template_declaring_no_verb_is_undecidable_not_exempt(tmp_path, resolver):
    """The rule is per-VERB — the engine exemption, the param roster and the body-substitution
    classification all key on it — so a template that names none cannot be checked at all. It
    fails; it does not pass by default. This is the shape `validate_scaffold` used to paper over
    with two prose fallbacks (a `verb:` line inside the fence, then the first non-fence token),
    both of which resolved a verb the corpus never declared."""
    text = _GOOD.replace("verb: get-host\nparams: [host]\n---", "---", 1)
    assert _codes(text, "cmdb", tmp_path, resolver) == ["no-verb"]


def test_a_template_naming_a_verb_the_system_does_not_declare_is_refused(tmp_path, resolver):
    assert _codes(_GOOD.replace("verb: get-host", "verb: get-hosts", 1), "cmdb", tmp_path,
                  resolver) == ["unknown-verb"]


def test_an_undeclared_placeholder_is_refused(tmp_path, resolver):
    assert _codes(_GOOD.replace("${host}", "${mystery}", 1), "cmdb", tmp_path,
                  resolver) == ["undeclared-placeholder"]


def test_a_marked_body_substitution_is_allowed(tmp_path, resolver):
    text = _GOOD.replace(
        "params: [host]", "params: [host]\nbody_substitutions: [mystery]", 1
    ).replace("${host}", "${mystery}", 1)
    assert _codes(text, "cmdb", tmp_path, resolver) == []


def test_a_params_entry_the_verb_does_not_declare_is_refused(tmp_path, resolver):
    """`SCHEMA.md` says `params:` IS the verb's declared params. Nothing checked that until
    #901: `validate_scaffold` read the signature and ignored `params:`, while the authoring
    contract's copy read `params:` and never met the signature, so a template could declare a
    param the adapter had renamed away and both enforcement copies would agree it was fine."""
    text = _GOOD.replace("params: [host]", "params: [host, hostname]", 1)
    assert _codes(text, "cmdb", tmp_path, resolver) == ["undeclared-param"]


def test_an_engine_verbs_body_placeholders_are_body_text_not_params(tmp_path, resolver):
    """An engine verb's `## Query` IS the query language, so its `${…}` are body text. Keyed on
    the VERB (`engine_of`), never the system — a system whose whole catalog is engine verbs had
    every template skipped and every template claimed (#885)."""
    text = (
        "---\nid: elastic.probe\nstatus: established\nverb: esql\nparams: []\n---\n\n"
        "## Query\n\n```esql\nFROM logs-* | WHERE host == \"${anything}\"\n```\n"
    )
    assert _codes(text, "elastic", tmp_path, resolver) == []


def test_a_wrapper_only_param_is_not_bindable_from_a_template(tmp_path, resolver):
    """`ticket.get-ticket` declares `require_closed` and reserves it to the first-party wrapper
    (`@verb(wrapper_only=…)`, #900). A template's `${placeholder}` is a MODEL binding, so the
    allowed surface here is `model_facing_params` — under `declared_params` this template would
    pass the check and then be refused at `validate_params` with the gather turn already spent.
    """
    text = (
        "---\nid: ticket.probe\nstatus: established\nverb: get-ticket\n"
        "params: [key]\n---\n\n"
        "## Query\n\n```query\nverb: get-ticket\nparams:\n  key: ${key}\n"
        "  require_closed: ${require_closed}\n```\n"
    )
    assert _codes(text, "ticket", tmp_path, resolver) == ["undeclared-placeholder"]
    declared = text.replace("params: [key]", "params: [key, require_closed]", 1)
    assert _codes(declared, "ticket", tmp_path, resolver) == [
        "undeclared-param", "undeclared-placeholder",
    ]


def test_a_wrapper_only_param_cannot_be_smuggled_in_as_a_body_substitution(tmp_path, resolver):
    """`body_substitutions:` is an UNCHECKED escape from the placeholder rule — it names what
    the checker must not classify — so the reserved set has to be refused there too. Otherwise
    the `model_facing_params` surface above is one frontmatter line from being optional, and
    the refusal lands back at `validate_params` with the gather turn spent (#900)."""
    text = (
        "---\nid: ticket.probe\nstatus: established\nverb: get-ticket\n"
        "params: [key]\nbody_substitutions: [require_closed]\n---\n\n"
        "## Query\n\n```query\nverb: get-ticket\nparams:\n  key: ${key}\n"
        "  require_closed: ${require_closed}\n```\n"
    )
    assert _codes(text, "ticket", tmp_path, resolver) == [
        "reserved-body-substitution", "undeclared-placeholder",
    ]


def test_a_params_mapping_is_read_as_a_declaration_not_as_nothing(tmp_path, resolver):
    """YAML gives "a list of names" more than one spelling, and `params:` carrying a per-param
    note is the one a template author reaches for. Read as nothing, the entries the verb does
    not declare go unreported — for THIS rule an unread declaration is an unenforced one, not a
    conservative one."""
    text = _GOOD.replace(
        "params: [host]", "params:\n  host: the hostname\n  hostname: the other one", 1)
    assert _codes(text, "cmdb", tmp_path, resolver) == ["undeclared-param"]
    listed = _GOOD.replace("params: [host]", "params:\n  - host: the hostname", 1)
    assert _codes(listed, "cmdb", tmp_path, resolver) == []


def test_a_yaml_boolean_param_entry_is_read_the_same_in_every_spelling(tmp_path, resolver):
    """`params: [on]` is a BOOLEAN to YAML, not the name the author typed — and the reader has
    to answer about it the same way in all three spellings, because it is one declaration.

    It did not. The sequence branch excluded `bool`, so the entry was dropped and went
    unreported, while the mapping branches stringified the same value and reported it. That is
    the split `_declared_names`' own docstring rules out for this rule: an unread declaration is
    an unenforced one, so a template carrying an unquoted `on` / `yes` / `no` passed a sweep
    that used to refuse it. `'True'` is not a name either — reporting it is what tells the
    author their `on` was coerced, instead of the declaration silently going unchecked.
    """
    for spelling in (
        "params: [on]", "params: on", "params:\n  on: a note", "params:\n  - on: a note",
    ):
        text = _GOOD.replace("params: [host]", spelling, 1)
        assert _codes(text, "cmdb", tmp_path, resolver) == ["undeclared-param"], spelling


def test_a_bare_scalar_declaration_is_the_one_entry_spelling_not_nothing(tmp_path, resolver):
    """`body_substitutions: window` is a one-entry list to everyone but YAML, which hands it
    over as a plain string. Read as nothing, the ESCAPE the author wrote is unread and the
    `${window}` it covers is refused as undeclared — a refusal naming a name the file declares,
    and on the lead lane's promote it discards the whole batch. (For `params:` the same scalar
    fails the other way, unenforced rather than over-refused; both are the shape going unread.)

    A `str` is also ITERABLE, which is why it is answered ahead of the sequence branch: read as
    a sequence it would declare one name per character.
    """
    body = "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${host}-${window}\n```\n"
    listed = (
        "---\nid: cmdb.probe\nstatus: established\nverb: get-host\n"
        "params: [host]\nbody_substitutions: [window]\n---\n\n" + body
    )
    scalar = listed.replace("body_substitutions: [window]", "body_substitutions: window", 1)
    assert _codes(listed, "cmdb", tmp_path, resolver) == []
    assert _codes(scalar, "cmdb", tmp_path, resolver) == []


def test_covers_reads_every_spelling_and_is_not_a_placeholder_declaration(tmp_path, resolver):
    """`covers:` rides `_declared_names` for its SHAPE tolerance, not its name semantics.

    What it carries are `query_id`s, so the tolerance is what matters and the classification is
    not: it must never join `params:`/`body_substitutions:` in excusing a `${name}`. A template
    that covered `cmdb.probe` and left `${probe}` undeclared would otherwise pass — a
    frontmatter key that quietly widened the placeholder rule.
    """
    from defender._corpus import parse_query_template

    def _covers(line: str):
        text = f"---\nid: cmdb.probe\nstatus: established\nverb: get-host\n{line}---\n"
        template, reason = parse_query_template(text, tmp_path / "cmdb" / "probe.md")
        assert template is not None, reason
        return template.covers

    assert _covers("covers: [cmdb.a, cmdb.b]\n") == ("cmdb.a", "cmdb.b")
    # The one-entry spelling a hand-editing author reaches for — and a `str` is iterable, so
    # read as a sequence it would yield one entry per character.
    assert _covers("covers: cmdb.a\n") == ("cmdb.a",)
    assert _covers("") == ()

    # …and the half the docstring promises: covering an identity does not declare a name.
    smuggled = (
        "---\nid: cmdb.probe\nstatus: established\nverb: get-host\nparams: [host]\n"
        "covers: [probe]\n---\n\n"
        "## Query\n\n```query\nverb: get-host\nparams:\n  host: ${host}-${probe}\n```\n"
    )
    assert _codes(smuggled, "cmdb", tmp_path, resolver) == ["undeclared-placeholder"]


def test_every_shipped_template_including_drafts_satisfies_the_rule(resolver):
    """The scope half. `validate_scaffold` excluded `_draft/`; this does not, which is the only
    reason the lead lane's output is inside any check at all."""
    offenders = []
    drafts = 0
    for t in iter_query_templates(_CATALOG):
        drafts += "_draft" in t.path.parts
        offenders += [
            f"{t.path.relative_to(_DEFENDER)}: {f.code} — {f.message}"
            for f in _scaffold_rules.check_template(t, resolver.verbs(t.system))
        ]
    assert offenders == [], offenders
    assert drafts, (
        "the corpus carries no `_draft/` template, so this sweep cannot show that drafts are in "
        "scope — the assertion above would hold identically under the excluded-drafts rule"
    )


def test_every_shipped_system_skill_carries_its_frontmatter_identity():
    for system in _ALL_SEVEN:
        skill = _DEFENDER / "skills" / system / "SKILL.md"
        assert _scaffold_rules.check_system_skill(skill, system) == [], system


def test_a_skill_md_whose_frontmatter_names_another_system_is_refused(tmp_path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: defender-elastic\n---\n# body\n")
    assert [f.code for f in _scaffold_rules.check_system_skill(skill, "cmdb")] == ["skill-name"]


def test_the_resolver_answers_about_the_tree_it_was_handed(tmp_path):
    """The property the loop's commit gate stands on: the drain runs it from the main checkout
    against a `lead-author/<id>` worktree, so a resolver that answered from the running
    process's own adapters would be grading a different tree than the one being committed.
    `_load_adapter_module` caches on the resolved absolute path, which is what keeps the two
    apart — this pins that the roster follows the directory, not the import."""
    adapters = tmp_path / "scripts" / "adapters"
    adapters.mkdir(parents=True)
    (adapters / "cmdb_adapter.py").write_text(
        "from __future__ import annotations\n"
        "from defender.runtime.verbs import VerbContext, verb\n"
        "@verb()\n"
        "def only_here(ctx: VerbContext, *, x: str = '') -> dict:\n    return {}\n"
        "VERBS = {'only-here': only_here}\n"
    )
    other = _scaffold_rules.VerbResolver(tmp_path)
    assert sorted(other.verbs("cmdb")) == ["only-here"]
    assert "get-host" in _scaffold_rules.VerbResolver(_DEFENDER).verbs("cmdb")


def test_an_unresolvable_system_raises_rather_than_reporting_a_clean_template(tmp_path):
    """`ScaffoldRuleError`, not an empty verb mapping. "Could not check" rendered as "nothing
    wrong" is the #901 defect itself, and a caller that cannot tell the two apart re-opens it."""
    resolver = _scaffold_rules.VerbResolver(tmp_path)
    with pytest.raises(_scaffold_rules.ScaffoldRuleError):
        resolver.verbs("nosuchsystem")


def test_the_engine_declaration_table_agrees_with_every_decorator():
    """Two sources answer "is this verb an engine verb": the `@verb(engine=…)` attribute the
    rule reads (`engine_of`), and the static `_ENGINE_DECL` table keyed by `(system, verb)` that
    the offline lanes read (`engine_for`) where no registry is in hand. They agree today; a
    silent disagreement would exempt a template from the placeholder rule in one lane and
    enforce it in the other, which is the drift class this issue is about."""
    resolver = _scaffold_rules.VerbResolver(_DEFENDER)
    for system in _ALL_SEVEN:
        for name, fn in resolver.verbs(system).items():
            assert engine_of(fn) == engine_for(system, name), f"{system}.{name}"
    assert _ADAPTERS.is_dir()
