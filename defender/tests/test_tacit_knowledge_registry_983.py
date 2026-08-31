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
    drive, and `lookup(ctx, ...)` the verb that wraps it. Split so the expiry and scope rules
    are testable without a `VerbContext`, and so "now" enters as a VALUE rather than a clock
    a test would have to patch.
  * `TACIT_KNOWLEDGE_MAX_REVIEW_SPAN_DAYS` — the frontier's provisional 180 (fork F2), held as
    one module-level constant so the policy knob is tunable in one place.

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

DEFENDER = REPO_ROOT / "defender"
ADAPTERS = DEFENDER / "scripts" / "adapters"

SYSTEM = "tacit-knowledge"
LOOKUP = "lookup"

#: The alerted actor/host/pattern the #983 case turns on — container UID 0 rewriting the CA
#: bundle on a build-runner host. Spelled once here and in `tests/_tacit983.py`'s document.
ACTOR = "uid-0"
HOST = "build-runner-07.prod"
PATTERN = "rewrite /etc/ssl/certs/ca-bundle.crt"

NOW = dt.date(2026, 5, 5)


def registry():
    """The tacit-knowledge adapter module.

    Imported inside the call rather than at module scope on purpose: a module-level import of a
    module that does not exist yet is a COLLECTION error, and pytest aborts the whole run on
    one — so a red spec suite would take every other suite in the tree down with it instead of
    reporting its own failures beside them."""
    from defender.scripts.adapters import tacit_knowledge_adapter

    return tacit_knowledge_adapter


def _entry(**overrides) -> dict[str, str]:
    """One well-formed registry entry. Eight fields: the seven the design names plus the `id`
    the `:R authz` row cites as `anchor_id` (fork F1's provisional eighth — without it a
    citation names a `pattern` string, and every edit becomes a silent re-identification)."""
    base = {
        "id": "tk-ca-bundle-build-runner",
        "pattern": PATTERN,
        "actor_scope": ACTOR,
        "host_scope": "build-runner-*.prod",
        "added_by": "sre-platform@example.invalid",
        "added_at": "2026-03-01",
        "review_by": "2026-08-01",
        "justification": "image build's own ca-trust step; no identity system holds UID 0",
    }
    base.update(overrides)
    return base


def _write_registry(root: Path, *entries: dict) -> Path:
    """A registry file under a throwaway `defender_dir`, written as YAML by hand.

    Hand-written rather than dumped, because the file is a HUMAN-EDITED artifact and the loader
    has to read what a human commits — a round trip through the same dumper the loader's parser
    feeds would be an oracle re-deriving itself (`lint-oracle`'s shape)."""
    path = root / "skills" / SYSTEM / "registry.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["entries:"]
    for entry in entries:
        first = True
        for key, value in entry.items():
            lines.append(f"{'  - ' if first else '    '}{key}: {value!r}")
            first = False
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


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
    """An entry whose `actor_scope` or `host_scope` is blank or blanket is refused at load, so
    one overly broad entry cannot silently authorize an entire estate
    (demand `no_wildcard_scope`, fork F6).

    Blanket = empty, `*`, or a case-insensitive `all`/`any`. A denylist misses novel spellings
    by construction — recorded here rather than papered over: what it buys is that the three
    spellings a human actually reaches for are refused, and what it does not buy is a proof
    that no broad entry exists, which is a process risk on the registry itself and outside this
    design's reach (the design doc's own residual-risk note)."""
    good = _entry()
    assert _ids(_load(tmp_path / "control", good)) == [good["id"]], "positive control"

    blanket = ["", "*", "all", "ALL", "any", "Any"]
    for i, value in enumerate(blanket):
        actor_wild = _entry(id=f"tk-actor-{i}", actor_scope=value)
        host_wild = _entry(id=f"tk-host-{i}", host_scope=value)
        loaded = _load(tmp_path / f"wild{i}", good, actor_wild, host_wild)
        assert _ids(loaded) == [good["id"]], (
            f"a scope of {value!r} loaded — one entry now covers every actor or every host"
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

    Deliberately NOT a new sign-off step inside the run loop — the commit/PR IS the sign-off."""
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
