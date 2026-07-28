"""#632 part 5 — the grant-derived roster, and the surfaces the model actually reads.

One test per demand of `spec_graph_632-verb-authorization.yaml`, named by its
`discharged_by`. RED against `d01001e6` by construction.

D6 as the design doc still words it is REFUTED, not narrowed (g10): `descriptor_catalog`
emits one line per SYSTEM and names no verbs at all, so the roster the gather model works
from is hand-written skill prose it Reads — and all four grant-withheld verbs are
advertised there today with copy-paste call examples, one file actively instructing the
model to use one. `05-early-resolutions.md` R-A2 replaces that sentence: the roster becomes
grant-derived, and the correspondence is a DEMAND the spec pins rather than an assumption
it leans on. Roster content is therefore load-bearing, not cosmetic — the narrowing is what
bounds the accepted cost of denying a legitimate verb ("not there yet for this role", never
"the model tried and was refused").

§7 R8 bounds the reach: the demand is scoped to an ENUMERATED set of build-time artifacts —
the generated roster, the per-system skill and execution prose, and committed templates
including drafts reachable by search. Two residuals are recorded out loud rather than
inherited silently, because an unenforceable clause reads as coverage:

* RS1 — the learning loop writes lessons into a corpus later injected into a prompt,
  LLM-written, so a withheld verb can appear in what the model reads months after this
  ships, in a file this change's diff never touches. Handed to the deferred estate-write
  work, which already owns that stored-injection channel.
* RS2 — the artifacts that DEFINE the verb surface sit inside the model's read scope; a
  system's adapter names its own verbs, so read literally the demand is unsatisfiable and
  the enumeration is what makes it testable.

§7 R9 settles the generator: from the grant as data with no adapter code executed, the
generated section overwritten in place with the build FAILING if surrounding prose still
names a withheld verb, no roster at all on generation failure, a committed artifact with a
regenerate-and-compare check, and a system with no granted verbs omitted entirely.

THE ROSTER AND ITS AUDIT DECIDE ON PAIRS, which is a decision about what the roster renders
rather than a way of writing the assertions. A verb name does not name an authorization: one
name is withheld on one system and granted on another (`cmdb.list-roles` to nobody,
`identity.list-roles` to gather), so a screen comparing bare names against a flat roster
string forbids a verb the same grant requires — no rendering satisfies both halves. Each
granted verb is therefore rendered as its qualified `{system}.{verb}` call id, the id form
the queries table already keys on, under its own system's section; `roster_pairs` reads them
back, and every "IS advertised" assertion goes through it too, so a roster that renders
nothing parseable fails loudly instead of passing its negatives vacuously.

WHAT THE AUDIT CAN SEE IS A SEPARATE QUESTION FROM WHAT THE GRANT DECIDES, and conflating the
two is how the correspondence demand stopped reaching its own counter-examples. The committed
prose names verbs in more than one form, and two of the four sites this demand exists to
correct are bare names — a query table of bare subcommands in the owning system's own file,
and, sharpest, one system's prose telling the model to use another system's withheld verb by
name alone. The audit therefore reads three forms with three attributions (the helper module's
docstring carries the rule), and it is asserted against the real tree in both directions: the
committed prose must report zero offenders, and the audit must demonstrably reach the files
that name a verb only in bare form. Without that second half, "zero offenders" is a claim
about the instrument, not about the tree.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.hooks.inject_system_skill_description import descriptor_catalog  # noqa: E402
from defender.runtime.driver import GATHER_DEF  # noqa: E402
from defender.runtime.verb_roster import (  # noqa: E402
    RosterError,
    audit_read_surfaces,
    generate_roster,
    load_roster,
    model_read_surfaces,
    roster_path,
)
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DENIED,
    DONE,
    GRANTED,
    GRANTED_COLLIDING_PAIR,
    UNDECLARED,
    WITHHELD_COLLIDING_PAIR,
    WITHHELD_FROM_GATHER,
    bare_only_surfaces,
    declared_verbs_everywhere,
    grant_of,
    recording_table,
    roster_pairs,
    run_gather,
    ScopedFakeVerbs,
)
from defender.tests.e2e._replay_harness import DEFENDER, Turn, VerbRecorder  # noqa: E402

pytestmark = pytest.mark.e2e

ADAPTER_SRC = (
    "def look(ctx, *, name: str) -> dict:\n    return {'name': name}\n"
    "def peek(ctx, *, name: str) -> dict:\n    return {'name': name}\n"
    "VERBS = {'look': look, 'peek': peek}\n"
)
# beta alone declares a third verb, granted to nobody. It is what makes a bare mention of it
# in ALPHA's file un-attributable by directory: the naming system does not declare the name,
# and the system that does withholds it — the shipped `cmdb` file naming the identity stub's
# `list-authorized-hosts`, reproduced locally.
BETA_ONLY_VERB = "sniff"
BETA_ADAPTER_SRC = ADAPTER_SRC.replace(
    "VERBS = {'look': look, 'peek': peek}",
    f"def {BETA_ONLY_VERB}(ctx, *, name: str) -> dict:\n    return {{'name': name}}\n"
    f"VERBS = {{'look': look, 'peek': peek, '{BETA_ONLY_VERB}': {BETA_ONLY_VERB}}}",
)


def _tree(root: Path, systems=("alpha", "beta")) -> Path:
    """A minimal defender tree: one adapter and one described SKILL.md per system, plus the
    committed-template directory the search surface is enumerated over."""
    (root / "scripts" / "adapters").mkdir(parents=True)
    (root / "skills" / "gather" / "queries").mkdir(parents=True)
    for system in systems:
        (root / "scripts" / "adapters" / f"{system}_adapter.py").write_text(
            BETA_ADAPTER_SRC if system == "beta" else ADAPTER_SRC, encoding="utf-8")
        d = root / "skills" / system
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.md").write_text(
            f"---\nname: {system}\ndescription: the {system} system of record\n---\n\nbody\n",
            encoding="utf-8")
        (d / "execution.md").write_text(f"# {system}\n\nhow to drive {system}.\n", encoding="utf-8")
    return root




def test_the_advertised_catalog_names_only_granted_verbs(tmp_path: Path):
    """The model-facing verb_roster names only the verbs the role's verb_grant enumerates,
    so an ungranted verb is never advertised and never produces a confusing denial. The
    roster is generated FROM THE GRANT AS DATA with no adapter code executed (§7 R9), which
    is what makes generation a data transform rather than a code-executing step at run
    start — the import-isolation fault cannot occur under this shape.

    Its counter-examples exist TODAY and must fail before the change lands: four withheld
    verbs advertised in committed skill and execution prose with copy-paste call lines, one
    of them as an instruction to use it.

    The demand is a WIRING, so the second half drives the consumer that R-A2's `mode: remove`
    edge leaves depending on it: the gather leg reads the roster through the real read tool
    under the real permission gate, and what comes back names the shipped grant's verbs and
    none it withholds. Asserting on the generated string alone would check a shape and
    credit a wiring — the roster could be correct and unreachable, or reachable and never
    read, with every assertion green.

    EVERY assertion here is on a `(system, verb)` PAIR, and that is a decision about what the
    roster must render, not a test convenience. Authorization is a property of the pair — the
    grant is enumerated as pairs and the registry decides on pairs — and one verb name is
    withheld on one system while granted on another. A roster that renders bare verb names
    cannot be screened at all: `list-roles` is required (identity grants it to gather) and
    forbidden (cmdb's is granted to nobody) in the same string. So the roster renders each
    granted verb as its qualified `{system}.{verb}` call id under its system's section, and
    the local grant below withholds `peek` on alpha while GRANTING it on beta, so a
    name-keyed generator fails here rather than only against the shipped grant."""
    tree = _tree(tmp_path / "tree")
    grant = grant_of("gather", (("alpha", "look"), ("beta", "peek")))

    roster = generate_roster(grant, defender_dir=tree)
    advertised = roster_pairs(roster)

    assert ("alpha", "look") in advertised
    assert ("beta", "peek") in advertised
    assert "alpha" in roster
    assert "beta" in roster
    assert ("alpha", "peek") not in advertised, \
        "alpha advertises `peek` — granted on beta, withheld here: the roster keys on the name"
    assert ("beta", "look") not in advertised, \
        "beta advertises `look` — granted on alpha, withheld here: the roster keys on the name"

    (tree / "scripts" / "adapters" / "alpha_adapter.py").write_text(
        "raise RuntimeError('an adapter must never be imported to build the roster')\n",
        encoding="utf-8")
    assert generate_roster(grant, defender_dir=tree) == roster, \
        "roster generation executed adapter code"

    # The wiring: the gather leg reads the COMMITTED roster for its own role, in a real run,
    # through the real read tool — the substitute for the withdrawn hand-authored prose.
    rec = VerbRecorder()
    verbs = ScopedFakeVerbs(recording_table(rec, {"elastic": ("query",)}),
                            grant_of("gather", (("elastic", "query"),)))
    r = run_gather(
        tmp_path / "run", verbs=verbs, run_id="d18-wired",
        turns=[Turn(tool_calls=[("read_file", {"path": str(roster_path(DEFENDER, "gather"))})]),
               DONE],
    )
    # The DELTA past the first request is exactly what the read added: the ambient gather
    # prompt cannot satisfy these assertions, and a prompt that happens to name a withheld
    # verb cannot fail them for the roster.
    assert r.gather.seen[-1].startswith(r.gather.seen[0]), \
        "the flattened history is not append-only — the delta is not the read's own result"
    delivered = roster_pairs(r.gather.seen[-1][len(r.gather.seen[0]):])

    assert ("ticket", "list-tickets") in delivered, \
        "the gather leg could not read its roster at all — the withdrawn prose has no substitute"
    assert GRANTED_COLLIDING_PAIR in delivered, (
        f"the roster withholds {'.'.join(GRANTED_COLLIDING_PAIR)}, which gather's grant names — "
        f"the generator dropped it because {'.'.join(WITHHELD_COLLIDING_PAIR)} is withheld"
    )
    advertised_but_withheld = sorted(set(WITHHELD_FROM_GATHER) & delivered)
    assert not advertised_but_withheld, \
        f"the roster the gather leg read advertises withheld pairs: {advertised_but_withheld}"


# Each case is (surface, the file that offends, the text written into it). The FORM matters as
# much as the surface: four of the seven are the qualified call the previous pass tested, and
# three are the bare-name forms the shipped counter-examples are actually written in — a table
# row of a system's own verbs, a foreign file naming another system's verb, and a template that
# belongs to no system at all.
_OFFENDING_CASES = [
    ("skill-prose", ("skills", "alpha", "SKILL.md"),
     "use `query(system='alpha', verb='peek')` to fetch it\n"),
    ("committed-template", ("skills", "gather", "queries", "alpha-peek.md"),
     "use `query(system='alpha', verb='peek')` to fetch it\n"),
    ("hidden-template", ("skills", "gather", "queries", "_draft", "beta-peek.md"),
     "use `query(system='alpha', verb='peek')` to fetch it\n"),
    ("post-generation-re-edit", ("skills", "beta", "execution.md"),
     "use `query(system='alpha', verb='peek')` to fetch it\n"),
    ("bare-name-in-its-own-file", ("skills", "alpha", "SKILL.md"),
     "| Subcommand | Measurement |\n|---|---|\n| `peek <name>` | the full record |\n"),
    ("bare-name-in-a-foreign-file", ("skills", "alpha", "SKILL.md"),
     f"there is no endpoint for that here; use the beta stub's `{BETA_ONLY_VERB} <name>` "
     f"instead.\n"),
    ("bare-name-in-an-unattributed-template", ("skills", "gather", "queries", "probe.md"),
     f"run `{BETA_ONLY_VERB}` against the host and summarise what comes back\n"),
]


@pytest.mark.parametrize(("surface", "parts", "text"), _OFFENDING_CASES,
                         ids=[c[0] for c in _OFFENDING_CASES])
def test_no_model_read_surface_names_a_verb_the_grant_withholds(
    tmp_path: Path, surface: str, parts: tuple[str, ...], text: str,
):
    """No build-time artifact the model reads names a verb the role's verb_grant withholds.
    Prose surrounding the generated roster, a committed query template, a template the
    generated index hides but a search still reaches, and a post-generation re-edit that
    writes a withheld verb back in are the SAME violation, with no carve-out — the demand
    covers the search surface, not only the generated index, and the change is not done
    until such artifacts are corrected.

    WHAT THE AUDIT MUST BE ABLE TO READ IS PART OF THE DEMAND, and it is where the previous
    pass left the escape: pinned against the fully qualified call alone, the audit was blind
    to two of the four sites this demand was minted to correct — including the file that tells
    the model to use a verb the grant withholds, which names it as a bare name in another
    system's prose. An audit that reads one syntax reports zero offenders over a tree that
    still carries the instruction, and the demand's stated bar goes unenforced. The grant
    still decides on the `(system, verb)` PAIR; this is about what the scan can SEE.

    Three attributions, each with its own case below:

    * QUALIFIED — `query(system=…, verb=…)` or the `S.v` call id: attributes to the pair.
    * BARE, IN ITS OWN SYSTEM'S FILE — a name the owning system declares, in that system's
      own directory. Attributes to that system, which is what lets beta's prose about beta's
      granted `peek` stay clean while the identical name in alpha's prose is an offender.
      The shipped shape is the ticket store's query table, whose rows are bare subcommands.
    * BARE, UNATTRIBUTABLE — a declared verb name in a file whose system does not declare it,
      or in a template belonging to no system. It attributes to nothing, so it is judged
      against every system declaring it and offends if any of those pairs is withheld. The
      accepted cost is false positives, and the correction for one is to qualify the name.

    The tree is built so a NAME-keyed audit cannot pass either: `peek` is granted on beta and
    withheld on alpha — the shipped `identity.list-roles` / `cmdb.list-roles` collision,
    reproduced locally so it is the audit's own contract rather than an accident of today's
    grant contents.

    The real tree is asserted on too, in both directions, because a synthetic corpus proves
    only that the instrument works on prose the test wrote. The committed prose must report
    ZERO offenders — which it does not today, and that is the demand — and the audit must
    demonstrably reach the files that name a verb ONLY as a bare name, computed off the tree
    rather than recalled, or the zero is blindness rather than compliance.

    A hit identifies its file by PATH, not by name: six committed surfaces are called
    SKILL.md, and a finding a human cannot act on without searching for it is not a finding.

    The negative's positive control is the roster itself, which DOES name every granted
    verb: a bare "no withheld verb appears anywhere" is also green over an empty corpus."""
    tree = _tree(tmp_path / "tree")
    grant = grant_of("gather", (("alpha", "look"), ("beta", "peek")))
    generate_roster(grant, defender_dir=tree)

    # Two controls, in place for every parametrization: a system's prose naming a verb ITS OWN
    # grant entry names is not an offender, in either form, even while that same verb NAME is
    # withheld on the sibling system.
    legitimate = tree / "skills" / "gather" / "queries" / "beta-fetch.md"
    legitimate.write_text(
        "call `query(system='beta', verb='peek')` to fetch it\n", encoding="utf-8")
    bare_legitimate = tree / "skills" / "beta" / "SKILL.md"
    bare_legitimate.write_text(
        "---\nname: beta\ndescription: the beta system of record\n---\n\n"
        "| Subcommand | Measurement |\n|---|---|\n| `peek <name>` | the full record |\n",
        encoding="utf-8")
    assert audit_read_surfaces(tree, (grant,)) == (), (
        "the clean tree reports offenders — the audit flags a verb NAME where the owning "
        "system's own grant entry names it"
    )

    offending = tree.joinpath(*parts)
    offending.parent.mkdir(parents=True, exist_ok=True)
    offending.write_text(text, encoding="utf-8")

    found = audit_read_surfaces(tree, (grant,))
    assert found, f"the {surface} surface naming a withheld verb was not flagged"
    assert any(str(offending.relative_to(tree)) in hit for hit in found), (
        f"no hit identifies {offending.relative_to(tree)} by its path — six committed surfaces "
        f"share the name SKILL.md, so a hit that names only the file is not actionable"
    )
    assert not any(str(bare_legitimate.relative_to(tree)) in hit for hit in found), \
        "beta's own bare mention of its own granted verb was flagged alongside alpha's"
    assert not any(str(legitimate.relative_to(tree)) in hit for hit in found), \
        "the template naming beta's OWN granted verb was flagged alongside alpha's withheld one"

    roster = generate_roster(grant, defender_dir=tree)
    assert ("alpha", "look") in roster_pairs(roster), \
        "the control is vacuous — the roster names no granted verb either"

    # THE REAL TREE, first direction: the committed prose must name no verb gather's shipped
    # grant withholds. Four sites do today — two of them bare names — so this is red until
    # they are corrected, which is the whole of what "the change is not done until such
    # artifacts are corrected" means.
    offenders = audit_read_surfaces(DEFENDER, (GATHER_DEF.verb_grant,))
    assert offenders == (), (
        "committed prose still advertises a verb the shipped grant withholds "
        f"({len(offenders)} sites): {offenders[:8]}"
    )

    # Second direction: the zero above is earned only if the audit can read the real files
    # that name a verb ONLY as a bare name. Under a grant that names nothing, every verb the
    # committed prose advertises is withheld, so each of those files must be flagged — an
    # audit that parses only the qualified call flags none of them and passes the zero above
    # with the instruction to call a withheld verb still committed.
    bare_only = bare_only_surfaces(model_read_surfaces(DEFENDER), declared_verbs_everywhere())
    assert bare_only, "no committed surface names a verb in bare form — the control is vacuous"
    reached = audit_read_surfaces(DEFENDER, (grant_of("gather", ()),))
    unseen = [str(p.relative_to(DEFENDER)) for p in bare_only
              if not any(str(p.relative_to(DEFENDER)) in hit for hit in reached)]
    assert not unseen, (
        f"the audit cannot see a bare verb name in {len(unseen)} committed file(s): {unseen[:8]}"
    )


def test_the_committed_model_read_surfaces_are_the_enumerated_set():
    """The enumerated set §7 R8 scopes the correspondence demand to is read off the tree on
    every run, never recalled: the per-system skill and execution prose, the committed
    query templates including drafts a search reaches, and the generated roster.

    This is the live census that keeps the scope honest — the enumeration the demand rests
    on was an outstanding probe obligation, and a hand-recalled list would go stale the
    first time a surface is added.

    The census is what the correspondence demand ranges over, so its own reach is the thing
    asserted here; whether the prose inside those files is clean is the correspondence
    demand's, and it is asserted against the real tree there. What this test adds is that
    the set is not narrower than the surfaces the model actually reads — a census that
    quietly omitted the per-system prose would make a clean audit meaningless."""
    surfaces = model_read_surfaces(DEFENDER)

    assert surfaces, "the model-read surface census is empty — the correspondence is vacuous"
    names = {p.name for p in surfaces}
    assert "SKILL.md" in names
    assert "execution.md" in names
    assert any("queries" in p.parts for p in surfaces), "the committed template surface is missing"
    assert all(p.is_file() for p in surfaces), "the census names an artifact that is not on disk"

    systems = {p.parent.name for p in surfaces if p.name in {"SKILL.md", "execution.md"}}
    for system, _ in WITHHELD_FROM_GATHER:
        assert system in systems, \
            f"the census omits `{system}`, whose committed prose advertises a withheld verb"
    assert WITHHELD_FROM_GATHER, "the withheld set is empty — nothing to be advertised"


def test_two_roles_in_one_process_each_get_their_own_catalog(tmp_path: Path):
    """Two roles resolving the advertised catalog in one process each get their OWN view:
    the role is part of the memo key. The builder is memoised on its argument tuple, so a
    role passed as an ARGUMENT enters the key automatically — the trap is a role read from
    deps inside the body, or defaulted.

    Two DISTINCT REAL role ids, never placeholders (§7 R16): a placeholder pair passes under
    exactly the falsy-key collapse this exists to exclude. And the key is the ROLE, not the
    grant object's identity — keying on identity turns every reconstruction into a cache
    miss that quietly rebuilds the view the memo exists to stabilise."""
    tree = _tree(tmp_path / "tree")
    skills, adapters = tree / "skills", tree / "scripts" / "adapters"
    descriptor_catalog.cache_clear()

    gather = grant_of("gather", (("alpha", "look"),))
    judge = grant_of("judge", (("beta", "look"),))

    gather_view = descriptor_catalog(skills, adapters, gather)
    judge_view = descriptor_catalog(skills, adapters, judge)

    assert gather_view is not None
    assert judge_view is not None
    assert "alpha" in gather_view
    assert "beta" not in gather_view, "gather's catalog names a system its grant never reaches"
    assert "beta" in judge_view
    assert "alpha" not in judge_view, \
        "the second role was served the first caller's memoised view"

    rebuilt = grant_of("gather", (("alpha", "look"),))
    assert rebuilt is not gather
    assert descriptor_catalog(skills, adapters, rebuilt) == gather_view, \
        "an equal grant rebuilt from the same role missed the memo — the key is object identity"


def test_a_newly_authored_verb_is_denied_and_unadvertised_until_a_grant_names_it(tmp_path: Path):
    """A newly authored verb shipped through the authoring path does not execute for any role
    until a verb_grant names it, and is never advertised before then: the scaffold gets no
    weaker gate than the runtime. This is the one instance of deny-by-default that is NOT
    vacuous against today's code, and it is what makes the general clause more than prose.

    The obligation has TWO shapes now, because §7 R11 read literally splits them, and only
    one of them is still a DENIAL:

    * A new verb on a system the role ALREADY holds is DENIED — the non-vacuous instance
      survives intact, and it is asserted first below because it is the one that keeps the
      deny-by-default clause from becoming prose.
    * A whole NEW SYSTEM is UNRESOLVABLE, never denied, because the role's grant reaches it
      nowhere. Recorded as RS14 rather than left silent: deny-by-default's reach over
      newly scaffolded SYSTEMS is now carried by the unresolvable path — nothing executes,
      but no policy-denial record is written for it either, so a role probing for
      newly-shipped systems leaves its trace in the queries table alone.

    Both shapes share the advertisement half: unnamed by the grant means absent from the
    roster, whichever refusal the call meets."""
    tree = _tree(tmp_path / "tree", systems=("alpha",))
    adapters = tree / "scripts" / "adapters"
    (adapters / "gamma_adapter.py").write_text(ADAPTER_SRC, encoding="utf-8")
    (tree / "skills" / "gamma").mkdir(parents=True)
    (tree / "skills" / "gamma" / "SKILL.md").write_text(
        "---\nname: gamma\ndescription: the new system\n---\n\nbody\n", encoding="utf-8")

    before = grant_of("gather", (("alpha", "look"),))
    registry = ModuleVerbRegistry(adapters, before)

    # A newly authored verb on a system the role already holds: the DENIAL that keeps
    # deny-by-default non-vacuous. `alpha.peek` ships in the same adapter as the granted
    # `alpha.look` and is named by no grant.
    assert registry.decide("alpha", "peek").outcome == DENIED, \
        "a newly authored verb on a granted system was reachable before any grant named it"
    assert ("alpha", "peek") not in roster_pairs(generate_roster(before, defender_dir=tree))

    # A newly scaffolded SYSTEM: nothing executes, and the label is unresolvable (RS14).
    assert registry.decide("gamma", "look").outcome == UNDECLARED, \
        "a newly scaffolded system read as denied rather than unresolvable"
    assert registry.decide("gamma", "look").outcome != GRANTED
    assert "gamma" not in generate_roster(before, defender_dir=tree)

    after = grant_of("gather", (("alpha", "look"), ("gamma", "look")))
    granted = ModuleVerbRegistry(adapters, after)
    assert granted.decide("gamma", "look").outcome == GRANTED
    assert ("gamma", "look") in roster_pairs(generate_roster(after, defender_dir=tree))




def test_roster_generation_failure_leaves_no_roster_rather_than_the_authored_text(tmp_path: Path):
    """When roster generation fails — the grant unreadable, the source prose missing, a
    system that will not resolve — the result is NO ROSTER, never a fall back to the
    authored text (§7 R9). Fail-open here would re-expose exactly the withheld verbs the
    hand-written prose advertises today, which is why this is a security decision rather
    than an operational one: a mechanism whose unavailability posture is unstated defaults
    to whichever the author typed first."""
    tree = _tree(tmp_path / "tree")
    grant = grant_of("gather", (("alpha", "look"),))
    generate_roster(grant, defender_dir=tree)
    path = roster_path(tree, "gather")
    assert path.is_file()

    stale = "you may call query(system='alpha', verb='peek')\n"
    path.write_text(stale, encoding="utf-8")

    with pytest.raises(RosterError):
        generate_roster(grant, defender_dir=tree / "nowhere")
    assert not roster_path(tree / "nowhere", "gather").exists(), \
        "a failed generation still left a roster behind"

    with pytest.raises(RosterError):
        load_roster(tree, "gather")
    assert "peek" in path.read_text(encoding="utf-8"), \
        "the failing load silently rewrote the artifact instead of refusing it"


def test_the_committed_roster_regenerates_identically_and_drift_fails_the_load(tmp_path: Path):
    """The verb_roster is a COMMITTED artifact with a regenerate-and-compare check, so a
    grant change produces a reviewable diff and drift is a LOAD FAILURE rather than a silent
    divergence (§7 R9). Deriving it twice from one unchanged grant yields the same bytes;
    an edited artifact refuses to load."""
    tree = _tree(tmp_path / "tree")
    grant = grant_of("gather", (("alpha", "look"), ("beta", "look")))

    first = generate_roster(grant, defender_dir=tree)
    second = generate_roster(grant, defender_dir=tree)
    assert first == second, "generation is not deterministic — the drift check cannot bite"
    assert load_roster(tree, "gather") == first

    roster_path(tree, "gather").write_text(first + "\n- also `beta.peek`\n", encoding="utf-8")
    with pytest.raises(RosterError):
        load_roster(tree, "gather")


def test_a_system_with_no_granted_verbs_for_a_role_is_omitted_from_the_roster(tmp_path: Path):
    """A system for which a role's verb_grant names no verb is OMITTED from that role's
    roster entirely — not present-but-empty, and not a generation failure (§7 R9). A
    present-but-empty section still tells the model the system exists and invites the call
    the grant will refuse, which is the failure mode the narrowing exists to remove."""
    tree = _tree(tmp_path / "tree")
    grant = grant_of("gather", (("alpha", "look"),))

    roster = generate_roster(grant, defender_dir=tree)

    assert ("alpha", "look") in roster_pairs(roster)
    assert "beta" not in roster, "a system with no granted verbs was still named to the model"
