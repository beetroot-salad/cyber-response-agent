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

THE AUDIT IS KEYED BY ROLE, because one audit and two roles collide the moment the second
roster is committed. The judge is granted two ticket verbs gather is not — and those two are
two of the four counter-examples the "reach zero" demand is built on — so an audit that scores
the whole committed tree against gather's grant reports the judge's own correct roster as an
offence. The three attribution rules below cannot express the fix: they attribute a NAME to a
`(system, verb)` pair and say nothing about which role's permissions a file should be judged
against. A fourth rule does: a generated roster is scored against ITS OWN ROLE's grant, read
off the role-keyed path it is committed under, and every other audited surface against
gather's — well defined because the non-roster surfaces have exactly one production consumer.

The rejected option is recorded because it costs nothing and a later reader will re-propose
it: excluding rosters from the audited surface breaks no assertion, which is precisely the
problem — it is what a lazy or dishonest implementer does to clear the red, and the suite
could not tell the two apart. Under rule 4 the exit is closed by construction, and the
closure is asserted directly: scoring the judge's roster against gather's grant must FLAG it,
so a roster quietly dropped from the audited set fails that assertion rather than passing
everything.

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

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.driver import GATHER_DEF  # noqa: E402
from defender.runtime.verb_roster import (  # noqa: E402
    RosterError,
    generate_roster,
    load_roster,
    roster_path,
)
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DENIED,
    DONE,
    GATHER_ROLE,
    GRANTED,
    GRANTED_COLLIDING_PAIR,
    UNDECLARED,
    WITHHELD_COLLIDING_PAIR,
    WITHHELD_FROM_GATHER,
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


_TEMPLATE_ID = re.compile(r"^id:\s*(\S+)\s*$", re.M)

# The committed query-template ids the golden replay corpus references — the 21 of its 243
# `query_id` values that name a template on disk today (the rest are ad-hoc probe ids, which
# never named a template and are not this check's business). Written as literals because the
# whole point is that the two sides are independent: derived from the same tree it audits,
# this check would agree with itself under any rename.
GOLDEN_REFERENCED_TEMPLATE_IDS = frozenset({
    "change-mgmt.active-changes", "change-mgmt.list-changes",
    "cmdb.host-trust-edges", "cmdb.hostname-by-ip", "cmdb.list-all-hosts",
    "elastic.detection-alerts", "elastic.doc-fetch-by-id", "elastic.falco-alerts",
    "elastic.ip-to-host-search", "elastic.sshd-auth-event-by-id",
    "elastic.sshd-auth-history", "elastic.sshd-session-lifecycle",
    "elastic.sudo-commands", "elastic.syslog-ip-search",
    "elastic.zeek-outbound-by-source",
    "host-state.authorized-keys", "host-state.container-identity-and-uid",
    "host-state.user-account",
    "identity.access-check", "identity.user-authorization", "identity.user-profile",
})
# The paths the gather skill's own prose tells the model to read. Prose describing content
# that moved is the failure this pins: the skill is not regenerated from anything, so a file
# corrected out of existence leaves the instruction standing.
_GATHER_SKILL_REFERENTS = (
    "skills/gather/queries",
    "skills/gather/failure-modes.md",
    "skills/gather/defender-sql.md",
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






def test_gathers_committed_roster_regenerates_from_its_own_shipped_grant():
    """The same pin `test_the_judge_has_its_own_generated_roster_scored_against_its_own_grant`
    holds the judge to, held for gather: `load_roster` only refuses a HAND-EDIT (its digest
    is over its own body, not over `GATHER_DEF.verb_grant`), and the audit's "no withheld verb
    is advertised" direction only catches a roster naming MORE than the grant now allows, never
    one naming LESS. A `GATHER_DEF.verb_grant` widened without re-running `generate_roster`
    would load clean and audit clean — a widened grant with a stale, narrower roster is a
    silent gap in what the model believes it may call, undetected by either mechanism until
    this pin existed only for the judge's side of the two shipped rosters."""
    committed = roster_path(DEFENDER, GATHER_ROLE)
    assert committed.is_file(), \
        "gather ships no generated roster — its model-facing verb prose is still authored"

    granted = {(s, v) for s, v, _ in GATHER_DEF.verb_grant.entries}
    advertised = roster_pairs(committed.read_text(encoding="utf-8"))
    assert advertised == granted, (
        "gather's roster and gather's grant disagree: "
        f"advertised-not-granted={sorted(advertised - granted)} "
        f"granted-not-advertised={sorted(granted - advertised)}"
    )

    assert generate_roster(GATHER_DEF.verb_grant, defender_dir=DEFENDER) == \
        committed.read_text(encoding="utf-8"), \
        "the committed gather roster is not what its own grant generates — regenerate it"






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
