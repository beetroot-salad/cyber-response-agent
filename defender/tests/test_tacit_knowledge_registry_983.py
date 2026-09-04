"""#983 mechanism B — the tacit-knowledge registry: the file, its loader, and its one verb.

The registry is the ONLY thing in this change that discharges an authorization contract, and
its whole safety argument is provenance: every entry traces to a human commit, because nothing
an agent run can reach writes the file. So the suite is three questions —

  1. Does one ENTRY mean what the design says (exactly eight fields, a bounded `review_by`, no
     blanket scope, no fuzzy scope match)?
  2. Is the lookup reachable the way every other system of record is (a rostered gather verb,
     read-only, digest-guarded roster)?
  3. Is the file unreachable from the run path (`decide_write` refuses it for MAIN and for
     GATHER, and GATHER has no write scope at all)?

THE API THIS SUITE PINS, and why each name was chosen rather than invented freely — the design
doc routes "exact file format/location" here explicitly ("a write-tests/write-code call, not a
design fork", fork F1), so these are the write-tests half of that call:

  * `defender/skills/tacit-knowledge/registry.yaml` — the per-system directory convention
    `defender/CLAUDE.md` documents, NOT the frontier's provisional
    `skills/invlang/tacit_knowledge_registry.yaml`. It is a system's data, queried through a
    gather verb; `runtime.verb_roster.model_read_surfaces` already enumerates `skills/*/`.
    Deliberately NOT `knowledge/environment/systems/{system}/` (the stub-transport config
    lane): that lane holds endpoints and credentials for a live service, and this system has
    no service — the file IS the system of record.
  * `defender/scripts/adapters/tacit_knowledge_adapter.py`, because `verbs._system_of` derives
    the system name from the filename with `_`→`-`, so this file and only this file spells
    `tacit-knowledge`.
  * `VERBS = {"health-check": ..., "lookup": ...}` as a DICT LITERAL with string-literal keys:
    `verbs.declared_verb_names` reads it cold off the AST, and a table assembled any other way
    declares nothing, which makes `ModuleVerbRegistry.__init__` raise on the grant.
  * `find_entry(entries, *, actor, host, pattern, now)` is the pure half the semantics tests
    drive, and `lookup(ctx, *, actor, host, pattern) -> {"matched": <entry>|None}` the verb
    that wraps it. Split so the expiry and scope rules are testable without a `VerbContext`,
    and so "now" enters as a VALUE rather than a clock a test would have to patch. ONE key on
    the return, not a `hit` boolean beside the entry: two spellings of one fact is the
    duplicated-derivation shape `lint-owns` watches for, and `matched is None` already says
    "miss" to a reader and to a gather model looking at the payload.
  * `TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS` — the frontier's provisional 180 (fork F2), held as
    one module-level constant so the policy knob is tunable in one place.
  * `TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS` — the second policy knob, added by this suite's
    hardening pass. See `test_blanket_scope_entry_is_refused` for why a denylist of spellings
    was not enough and what replaced it.

The loader DROPS one bad entry rather than refusing the file, mirroring
`defender/_corpus.iter_query_templates`: a registry is a curated list, and one malformed row
sinking every sanctioned pattern in the estate is a worse failure than one row going missing.

The malformed-registry fixtures (wildcard scope, over-span `review_by`, missing and unknown
keys) are written INLINE into `tmp_path` rather than committed as files. That is this tree's
convention for adapter and registry fixtures — there is no `tests/fixtures/`, and every
adapter/roster suite builds its tree in `tmp_path` (`test_verb_roster_632._tree`,
`test_ticket_adapter`). Each bad entry is one keyword away from the good one, which reads far
better as `_entry(actor_scope="*")` than as a second checked-in YAML file a reader has to diff.
The one registry that IS a committed file is the real one, and
`test_the_shipped_registry_file_is_human_authored_and_loads` is what reads it.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from defender._git import REPO_ROOT
from defender.runtime import permission
from defender.runtime.agent_definition import compile_policy_for
from defender.runtime.driver import GATHER_DEF, MAIN_DEF
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verb_roster import generate_roster, load_roster, roster_path
from defender.runtime.verbs import (
    GRANTED,
    ModuleVerbRegistry,
    VerbContext,
    declared_verb_names,
    is_system_name,
)
from defender.tests import _tacit983 as scene

DEFENDER = REPO_ROOT / "defender"
ADAPTERS = DEFENDER / "scripts" / "adapters"

SYSTEM = scene.REGISTRY_SYSTEM
LOOKUP = "lookup"

#: The alerted actor/host/pattern the #983 case turns on — container UID 0 rewriting the CA
#: bundle on a build-runner host. Read off the shared scene rather than respelled, so a suite
#: cannot assert a hit against an actor the document names differently.
ACTOR = scene.ACTOR
HOST = scene.HOST
PATTERN = scene.PATTERN

NOW = dt.date(2026, 5, 5)


def registry():
    """The tacit-knowledge adapter module.

    Imported inside the call rather than at module scope on purpose: a module-level import of a
    module that does not exist yet is a COLLECTION error, and pytest aborts the whole run on
    one — so a red spec suite would take every other suite in the tree down with it instead of
    reporting its own failures beside them."""
    from defender.scripts.adapters import tacit_knowledge_adapter

    return tacit_knowledge_adapter


#: The entry builder and the fixture writer live in `tests/_tacit983.py`, not here: the e2e
#: drives the real adapter against a fixture tree and needs the same two (`lint-dup`), and the
#: entry's id is one of the ids that module already names for the `:R authz` citation.
_entry = scene.registry_entry
_write_registry = scene.write_registry


def _load(root: Path, *entries: dict):
    return registry().load_entries(_write_registry(root, *entries))


def _ids(entries) -> list[str]:
    return [e["id"] for e in entries]


# ---------------------------------------------------------------- the entry shape


def test_registry_entry_fields(tmp_path):
    """One entry carries exactly `id`, `pattern`, `actor_scope`, `host_scope`, `added_by`,
    `added_at`, `review_by` and `justification`; an entry missing any of them, or carrying an
    unknown key, is refused at load and does not discharge anything
    (demand `registry_entry_shape`, fork F1).

    ONE entry is dropped, never the file. A registry is a curated list and one malformed row
    sinking every sanctioned pattern in the estate is the worse failure — the same argument
    `_corpus.iter_query_templates` makes for the query catalog."""
    assert set(registry().ENTRY_FIELDS) == {
        "id", "pattern", "actor_scope", "host_scope",
        "added_by", "added_at", "review_by", "justification",
    }

    good = _entry()
    assert _ids(_load(tmp_path / "ok", good)) == [good["id"]], "positive control"

    missing = _entry(id="tk-missing-justification")
    del missing["justification"]
    assert _ids(_load(tmp_path / "missing", good, missing)) == [good["id"]], (
        "an entry with no stated justification loaded — the field that makes a sanction "
        "reviewable is the one it was allowed to omit"
    )

    unknown = _entry(id="tk-unknown-key", expires_never="true")
    assert _ids(_load(tmp_path / "unknown", good, unknown)) == [good["id"]], (
        "an unrecognised key loaded — a field the loader does not read is a field a human "
        "reviewer would take for a control"
    )


def test_review_by_beyond_the_bound_is_refused(tmp_path):
    """An entry whose `review_by` is further than the policy bound past its `added_at` is
    refused AT LOAD: the freshness bound is enforced, not self-set (demand
    `review_by_bounded_span`, fork F2).

    A file entry does not re-verify itself on every read the way a live IAM or
    change-management query does, so the bound is what stands in for that re-verification. The
    span is read off the module constant rather than restated as 180 here, so tuning the policy
    does not silently leave this test measuring the old one."""
    span = registry().TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS
    assert isinstance(span, int)
    assert span > 0

    added = dt.date(2026, 3, 1)
    at_the_bound = _entry(
        id="tk-at-the-bound",
        added_at=added.isoformat(),
        review_by=(added + dt.timedelta(days=span)).isoformat(),
    )
    over_the_bound = _entry(
        id="tk-over-the-bound",
        added_at=added.isoformat(),
        review_by=(added + dt.timedelta(days=span + 1)).isoformat(),
    )

    loaded = _load(tmp_path / "span", at_the_bound, over_the_bound)
    assert _ids(loaded) == ["tk-at-the-bound"], (
        "an entry set to review itself beyond the policy bound loaded — the sanction can name "
        "its own expiry, which is the rubber stamp the bound exists to prevent"
    )


def test_blanket_scope_entry_is_refused(tmp_path):
    """An entry whose `actor_scope` or `host_scope` is blank, blanket, or MOSTLY WILDCARD is
    refused at load, so one overly broad entry cannot silently authorize an entire estate
    (demand `no_wildcard_scope`, fork F6).

    Blanket is four things, and the fourth is what this suite's hardening pass added:

      1. empty; 2. exactly `*`; 3. a case-insensitive `all`/`any`;
      4. fewer than `TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS` LITERAL characters — anything
         that is not a wildcard metacharacter.

    (1)–(3) alone are a denylist of spellings, and a denylist cannot tell a blanket wildcard
    from a legitimate scoped glob: `actor_scope: "*-0"` matches `uid-0`, `svc-0`, `root-0` and
    every other actor whose name happens to end that way, and it sails through all three
    arms. Counting literal characters is the property that actually separates the two — this
    suite's own good fixture (`host_scope: "build-runner-*.prod"`, eighteen literal characters
    around one star) is nearly all literal, and `*-0` is nearly all star.

    THE LIMIT, recorded rather than papered over: this is a shape rule, not a breadth
    proof. `host_scope: "prod-*"` is mostly literal and still covers a fleet, and no
    character count can tell a fleet-wide sanction a human MEANT from one they wrote
    carelessly. What the rule buys is that the spellings that cover EVERYTHING cannot be
    written at all; who may author a broad-but-legal entry is a process risk on the registry
    itself and outside this design's reach (the design doc's own residual-risk note).

    Read off the module constant rather than restated as a number here, so tuning the policy
    does not leave this test measuring the old one — and the two concrete cases below pin the
    tuning range from both sides at once: raise the minimum past five and the good fixture's
    own `actor_scope: "uid-0"` stops loading; lower it below three and `*-0` starts."""
    good = _entry()
    assert _ids(_load(tmp_path / "control", good)) == [good["id"]], "positive control"

    minimum = registry().TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS
    assert isinstance(minimum, int)
    assert minimum > 0

    blanket = ["", "*", "all", "ALL", "any", "Any", "*-0", "**", "*.*", "*" * minimum]
    for i, value in enumerate(blanket):
        actor_wild = _entry(id=f"tk-actor-{i}", actor_scope=value)
        host_wild = _entry(id=f"tk-host-{i}", host_scope=value)
        loaded = _load(tmp_path / f"wild{i}", good, actor_wild, host_wild)
        assert _ids(loaded) == [good["id"]], (
            f"a scope of {value!r} loaded — one entry now covers every actor or every host, "
            f"or very nearly"
        )

    for i, (field, value) in enumerate((
        ("host_scope", "build-runner-*.prod"),
        ("host_scope", "build-runner-0?.prod"),
        ("actor_scope", "uid-0"),
        ("actor_scope", "svc-build-*"),
    )):
        scoped = _entry(id=f"tk-scoped-{i}", **{field: value})
        assert _ids(_load(tmp_path / f"scoped{i}", scoped)) == [scoped["id"]], (
            f"a legitimately scoped {field} of {value!r} was refused as blanket — the rule has "
            f"been tuned past the entries the registry is FOR, and the one anchor kind a "
            f"container-root case can reach is unwritable"
        )


# ---------------------------------------------------------------- the lookup


def test_scope_mismatch_does_not_discharge(tmp_path):
    """An unexpired entry whose `actor_scope` or `host_scope` does not cover the alerted actor
    and host is not a hit, and the contract stays unresolved (demand `scope_must_match`).

    `find_entry` is the pure half: `now` enters as a VALUE, so expiry and scope are testable
    without a clock to patch and without a `VerbContext` to build."""
    entries = _load(tmp_path / "scope", _entry())

    assert registry().find_entry(
        entries, actor=ACTOR, host=HOST, pattern=PATTERN, now=NOW,
    ) is not None, "positive control: the alerted actor and host are inside the entry's scope"

    for label, kwargs in (
        ("actor", {"actor": "uid-1000"}),
        ("host", {"host": "web-frontend-02.prod"}),
        ("pattern", {"pattern": "rewrite /etc/shadow"}),
    ):
        call = {"actor": ACTOR, "host": HOST, "pattern": PATTERN, "now": NOW, **kwargs}
        assert registry().find_entry(entries, **call) is None, (
            f"an entry whose scope does not cover the alerted {label} was a hit"
        )


def test_expired_entry_is_not_a_hit_at_lookup(tmp_path):
    """An entry whose `review_by` is in the past does not discharge — the lookup is simply no
    hit (the loader/lookup half of demand `expired_entry_does_not_discharge`; the
    falls-through-to-`indeterminate` half is the e2e).

    Expiry is a property of the READ, not of the load: an entry that is well formed and inside
    the review span still stops answering once its own review date passes, which is what makes
    the bound stand in for a live system's re-verification."""
    entries = _load(tmp_path / "expiry", _entry(added_at="2026-03-01", review_by="2026-04-15"))

    assert registry().find_entry(
        entries, actor=ACTOR, host=HOST, pattern=PATTERN, now=dt.date(2026, 4, 14),
    ) is not None, "positive control: the same entry answers the day before it expires"

    assert registry().find_entry(
        entries, actor=ACTOR, host=HOST, pattern=PATTERN, now=dt.date(2026, 5, 5),
    ) is None, (
        "an entry past its own `review_by` still discharged — a stale sanction authorizes "
        "forever, which is the one thing a file entry cannot be trusted to notice about itself"
    )


def _ctx(root: Path, tmp_path: Path, *, as_of: dt.datetime) -> VerbContext:
    """A `VerbContext` pointing at a throwaway tree and a fixed moment.

    Both are VALUES the context already carries (`defender_dir`, `as_of`), which is the whole
    reason the verb takes one: the registry it reads and the clock expiry is judged against
    enter through the seam rather than through a module attribute a test would have to patch
    (`lint-monkeypatch`)."""
    return VerbContext(
        defender_dir=root, run_dir=tmp_path / "run", env={}, as_of=as_of,
    )


def test_lookup_verb_answers_off_the_registry_it_is_handed(tmp_path):
    """`lookup` — the VERB, not the pure helper under it — loads the registry out of the tree
    its `VerbContext` names and answers a genuine hit, a genuine miss and an expired entry
    (demand `registry_lookup_gather_verb`).

    THE test the pure-`find_entry` ones cannot stand in for. Everything above drives
    `find_entry` against an already-loaded list, so a `lookup` that ignored all of it — a
    hardcoded `{"matched": {...}}`, a lookup reading a path it computed itself, a lookup that
    forgot to apply expiry on the way out — passes every one of them. This is the only test
    that runs the verb the gather roster actually dispatches.

    The fixture entry is spelled with an id NO shipped registry carries, which is what makes
    "off the tree it is handed" observable rather than asserted: a `lookup` resolving the
    registry off `REPO_ROOT` (or off an import-time constant) cannot return `tk-fixture-only`,
    and would come back with the shipped entry or with a miss.
    """
    root = tmp_path / "tree"
    _write_registry(root, _entry(id="tk-fixture-only", added_at="2026-03-01",
                                 review_by="2026-06-01"))
    ctx = _ctx(root, tmp_path, as_of=dt.datetime(2026, 5, 5, 3, 42, 11, tzinfo=dt.UTC))

    hit = registry().lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    assert isinstance(hit, dict)
    assert hit["matched"] is not None, (
        "the verb came back empty for the actor, host and pattern its own fixture entry "
        "covers — the lookup is not reading the registry it was handed"
    )
    assert hit["matched"]["id"] == "tk-fixture-only", (
        "the verb answered with something other than the entry in the tree its `VerbContext` "
        "names — a registry resolved off an import-time path answers for the wrong estate"
    )
    assert set(hit["matched"]) == set(registry().ENTRY_FIELDS), (
        "the matched entry reaching the model is not the loaded entry — the payload a human "
        "reviews and the row a `:R consultations` cites have to be the same record"
    )

    miss = registry().lookup(ctx, actor=ACTOR, host="web-frontend-02.prod", pattern=PATTERN)
    assert miss["matched"] is None, (
        "a host outside every entry's `host_scope` was a hit — an unconditional-hit lookup "
        "authorizes the whole estate through one verb call"
    )

    expired = registry().lookup(
        _ctx(root, tmp_path, as_of=dt.datetime(2026, 7, 1, tzinfo=dt.UTC)),
        actor=ACTOR, host=HOST, pattern=PATTERN,
    )
    assert expired["matched"] is None, (
        "the entry answered past its own `review_by` — expiry is applied by `find_entry` and "
        "the verb is not going through it"
    )


def test_no_authz_grounding_from_a_past_ai_verdict(tmp_path):
    """Nothing in the tacit-knowledge path derives an `authorized` verdict from resemblance to a
    past AI-resolved case (demand `no_precedent_by_similarity`, non-obligation 4).

    Two mechanical halves, because the rejection has to be observable rather than asserted in
    prose. (1) The entry shape has NOWHERE for a case reference to live — `ENTRY_FIELDS` is
    closed and holds no `cites_past_case`, `similar_to` or `precedent` — so "this resembles a
    resolved case" cannot be recorded as a sanction in the first place. (2) The lookup does no
    partial or fuzzy matching beyond straightforward scope containment: a near miss is a miss,
    so resemblance cannot become a hit at read time either."""
    assert not any(
        term in field
        for field in registry().ENTRY_FIELDS
        for term in ("case", "precedent", "similar")
    ), (
        "the entry shape grew a field that can cite a past case — the convention-vs-bad-habit "
        "problem relocated to 'what counts as similar', now carrying a human's signature"
    )

    entries = _load(tmp_path / "similar", _entry())
    near_misses = [
        {"actor": "uid-00"},
        {"actor": "uid-0-build"},
        {"host": "build-runner-07.prod.example"},
        {"host": "staging-build-runner-07.prod"},
        {"pattern": "rewrite /etc/ssl/certs/ca-bundle.crt.bak"},
    ]
    for miss in near_misses:
        call = {"actor": ACTOR, "host": HOST, "pattern": PATTERN, "now": NOW, **miss}
        assert registry().find_entry(entries, **call) is None, (
            f"a near miss matched: {miss!r} — the lookup is doing similarity, not containment"
        )


# ---------------------------------------------------------------- the seam


def test_registry_lookup_is_a_rostered_gather_verb():
    """The registry lookup is reachable only as a gather verb through the existing roster and
    dispatch seam: it appears in the generated `verb-roster.md` under its own system with the
    roster's digest recomputed, and a lead reaches it the same way it reaches `cmdb.get-host`
    (demand `registry_lookup_gather_verb`, claim c16).

    The roster file is GENERATED and digest-guarded, so a new verb lands as an adapter plus a
    declared grant plus a regeneration — never as a hand-edit, which `load_roster` would refuse
    as drift."""
    assert is_system_name(SYSTEM)
    assert registry().SYSTEM == SYSTEM
    assert LOOKUP in registry().VERBS
    assert registry().VERBS[LOOKUP] is registry().lookup
    assert "health-check" in registry().VERBS, (
        "every rostered system answers `health-check` (skills/connect's merge bar)"
    )
    assert LOOKUP in declared_verb_names(ADAPTERS, SYSTEM), (
        "`VERBS` is read COLD off the AST — it has to be a dict literal with literal keys"
    )

    grant: VerbGrant = GATHER_DEF.verb_grant
    assert (SYSTEM, LOOKUP, "r") in grant.entries, (
        "the lookup is not in gather's grant, so no lead can reach it"
    )
    assert all(
        entry[2] == "r" for entry in grant.entries if entry[0] == SYSTEM
    ), "the registry is a READ — no run-path verb may write it"

    assert ModuleVerbRegistry(ADAPTERS, grant).decide(SYSTEM, LOOKUP).outcome == GRANTED

    committed = roster_path(DEFENDER, "gather")
    assert generate_roster(grant, defender_dir=DEFENDER) == \
        committed.read_text(encoding="utf-8"), (
            "the committed gather roster is not what its own grant generates — regenerate it "
            "rather than hand-editing the file, which the digest guard refuses"
        )
    assert f"`{SYSTEM}.{LOOKUP}`" in load_roster(DEFENDER, "gather")


def test_the_shipped_registry_file_is_human_authored_and_loads(tmp_path):
    """The committed registry loads clean through its own loader, and its companion `SKILL.md`
    is the per-system reference every other system of record ships.

    The positive control for `test_no_run_path_writes_the_registry` below: that test's claim is
    only meaningful about a file that EXISTS and is read."""
    path = registry().registry_path(DEFENDER)
    assert path == DEFENDER / "skills" / SYSTEM / "registry.yaml"
    assert path.is_file(), "the registry file itself is part of this change"
    assert (DEFENDER / "skills" / SYSTEM / "SKILL.md").is_file()

    entries = registry().load_entries(path)
    assert all(set(e) == set(registry().ENTRY_FIELDS) for e in entries)


def test_no_run_path_writes_the_registry(tmp_path):
    """No path an agent run can reach writes the registry file: the gather verb is read-only and
    the file tools refuse the path, so every entry traces to a human commit
    (demand `registry_never_agent_written`).

    This is the whole of mechanism B's provenance argument, so it is checked against the real
    compiled policies rather than asserted in prose. A registry populated from the agent's own
    automated closes would be the system vouching for itself, and no human-in-the-loop step
    exists anywhere between `close_investigation` and the ticket close (claim c5) to catch it.

    Deliberately NOT a new sign-off step inside the run loop — the commit/PR IS the sign-off.

    A NEGATIVE BY OMISSION, which is why it has a twin: nothing calls a write function here,
    and nothing would even if the adapter grew one, so this test passes with zero code and
    keeps passing right up until the day something does call one.
    `test_the_adapter_module_exports_nothing_that_writes` guards the other half — that the
    adapter has no such function to call in the first place."""
    target = registry().registry_path(DEFENDER)
    assert target.is_file(), "a negative reachability claim about a file that does not exist"

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text('{"rule": {"name": "probe"}}', encoding="utf-8")

    forged = "entries:\n  - id: tk-forged\n"
    for defn, label in ((MAIN_DEF, "main"), (GATHER_DEF, "gather")):
        policy = compile_policy_for(defn, run_dir, defender_dir=DEFENDER)
        decision = permission.decide_write(
            target, forged, run_dir=run_dir, defender_dir=DEFENDER, policy=policy,
        )
        assert not decision.allow, (
            f"the {label} role may write the tacit-knowledge registry — the agent can author "
            f"its own authorization"
        )

    assert compile_policy_for(GATHER_DEF, run_dir, defender_dir=DEFENDER).write_allow == (), (
        "gather grew a write scope; the lookup lane must stay read-only end to end"
    )

    # The positive control on the control: MAIN's one writable path still is writable, so the
    # two refusals above are the allowlist working rather than the policy being empty.
    investigation = run_dir / "investigation.md"
    main_policy = compile_policy_for(MAIN_DEF, run_dir, defender_dir=DEFENDER)
    assert permission.decide_write(
        investigation, "```invlang\n```\n", run_dir=run_dir, defender_dir=DEFENDER,
        policy=main_policy,
    ).allow, "positive control: main's own artifact is still writable"


#: Verb-name and function-name stems that MUTATE. A name is the cheapest signal a reviewer
#: reads, and the adapter that grows a `save_entry` beside `lookup` is the one where "the
#: registry is only ever human-authored" quietly stops being true.
_MUTATING_STEMS = (
    "write", "save", "add", "append", "put", "post", "create", "insert", "upsert",
    "update", "set", "delete", "remove", "drop", "edit", "patch", "sync", "commit",
)


def test_the_adapter_module_exports_nothing_that_writes():
    """The tacit-knowledge adapter's own PUBLIC SURFACE carries no write-capable function, and
    its source performs no filesystem mutation (demand `registry_never_agent_written`).

    The static twin of `test_no_run_path_writes_the_registry`, and the reason both exist.
    That test asks whether any path an agent run can reach WRITES the file, and it passes
    today with zero code — which is correct (it is a negative-by-omission property) and is
    also the whole of its weakness: it is satisfied by nothing calling a write function that
    happens not to exist yet. This one asks the complementary question of the module itself,
    so the guard survives the day someone adds `record_entry(ctx, ...)` "just for the
    curator" and wires it to nothing.

    TWO ARMS, and the second is a source scan with the limits a source scan has. Names catch
    the ordinary case; the scan catches a write spelled through the stdlib without a telling
    name. Neither sees a write assembled dynamically (`getattr(path, "write" + "_text")`), and
    neither is meant to — `permission.decide_write` is the enforcement boundary and this is a
    surface guard in front of it.
    """
    import inspect
    import re

    mod = registry()
    public = [n for n in dir(mod) if not n.startswith("_")]
    own = [
        n for n in public
        if callable(getattr(mod, n))
        and getattr(getattr(mod, n), "__module__", None) == mod.__name__
    ]
    assert own, "the module exports no functions of its own at all — read the import list"

    offenders = [n for n in own if n.split("_")[0].lower() in _MUTATING_STEMS]
    assert offenders == [], (
        f"the registry adapter exports {offenders} — a write-capable name on the one system "
        f"whose entire safety argument is that every entry traces to a human commit"
    )
    verb_offenders = [v for v in mod.VERBS if v.split("-")[0].lower() in _MUTATING_STEMS]
    assert verb_offenders == [], (
        f"the roster would advertise {verb_offenders} to a lead — a mutating verb on a "
        f"read-only system of record"
    )

    src = inspect.getsource(mod)
    for token in (
        ".write_text(", ".write_bytes(", ".mkdir(", ".unlink(", ".rmdir(", ".rename(",
        ".touch(", "yaml.safe_dump", "yaml.dump", "shutil.", "os.remove", "os.replace",
    ):
        assert token not in src, (
            f"the adapter's source calls {token!r} — the registry lane is a READ end to end"
        )
    assert not re.search(r"open\([^)]*['\"][wax]", src), (
        "the adapter opens a file for writing or appending"
    )


@pytest.mark.parametrize("verb", ["health-check", LOOKUP])
def test_every_registry_verb_takes_a_verb_context_first(verb):
    """The lookup is an ordinary adapter verb: a leading `VerbContext` and keyword-only
    annotated parameters, so `skills/connect/validate_scaffold.check_signatures` admits it and
    the real query tool can validate a lead's bound params against its real signature.

    `VerbContext` is also the injection seam the semantics tests avoid needing: it carries the
    `defender_dir` the registry is read from and the `as_of` moment expiry is judged against,
    so a scenario hands the verb a tree and a clock as VALUES."""
    import inspect

    params = list(inspect.signature(registry().VERBS[verb]).parameters.values())
    assert params[0].name == "ctx"
    assert params[0].annotation in (VerbContext, "VerbContext")
    assert all(p.kind is p.KEYWORD_ONLY and p.annotation is not p.empty for p in params[1:])
