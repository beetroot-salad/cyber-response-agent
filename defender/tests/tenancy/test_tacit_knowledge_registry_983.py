"""#983 mechanism B, the tacit-knowledge registry: entry fields and bounds (review_by, no blanket scope, exact scope match), expiry at lookup, the rostered read-only lookup verb, and that no run path can write the registry file."""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from defender._git import REPO_ROOT
from defender.investigation import permission
from defender.investigation.agent_definition import compile_policy_for
from defender.investigation.driver import MAIN_DEF
from defender.tests.support.tenancy import _tenants1106
from defender.systems.verb_grant import VerbGrant
from defender.systems.verbs import (
    GRANTED,
    ModuleVerbRegistry,
    VerbContext,
    is_system_name,
    read_roster,
)
from defender.tests.support.shared.contracts import _tacit983 as scene

DEFENDER = REPO_ROOT / "defender"
ADAPTERS = DEFENDER / "integrations"
#: The registry is tenant knowledge: the committed fixture tenant's agent half carries the one
#: this repo ships (the product tree carries none).
FIXTURE_AGENT = REPO_ROOT / "knowledge" / "tenant-fixture" / "agent"

SYSTEM = scene.REGISTRY_SYSTEM
LOOKUP = "lookup"

ACTOR = scene.ACTOR
HOST = scene.HOST
PATTERN = scene.PATTERN

NOW = dt.date(2026, 5, 5)


def registry():
    """The platform registry module (#1390: `systems/tacit_registry.py`, what the adapter was)."""
    from defender.systems import tacit_registry

    return tacit_registry


#: The entry builder and the fixture writer live in `tests/support/shared/contracts/_tacit983.py`,
#: shared with the e2e that drives the real lookup against a fixture tree.
_entry = scene.registry_entry
_write_registry = scene.write_registry


def _load(root: Path, *entries: dict):
    return list(registry().read_registry(_write_registry(root, *entries)).entries)


def _ids(entries) -> list[str]:
    return [e["id"] for e in entries]


# ---------------------------------------------------------------- the entry shape


def test_registry_entry_fields(tmp_path):
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
            f"a legitimately scoped {field} of {value!r} was refused as blanket"
        )


# ---------------------------------------------------------------- the lookup


def test_scope_mismatch_does_not_discharge(tmp_path):
    """An unexpired entry whose `actor_scope` or `host_scope` does not cover the alerted actor
    and host is not a hit, and the contract stays unresolved."""
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
    entries = _load(tmp_path / "expiry", _entry(added_at="2026-03-01", review_by="2026-04-15"))

    assert registry().find_entry(
        entries, actor=ACTOR, host=HOST, pattern=PATTERN, now=dt.date(2026, 4, 14),
    ) is not None, "positive control: the same entry answers the day before it expires"

    assert registry().find_entry(
        entries, actor=ACTOR, host=HOST, pattern=PATTERN, now=dt.date(2026, 5, 5),
    ) is None, (
        "an entry past its own `review_by` still discharged"
    )


def _ctx(root: Path, tmp_path: Path) -> VerbContext:
    """A `VerbContext` pointing at a throwaway tree (no moment: an adapter is handed none, #1385
    O1; with no run clock or branch point held, the lookup judges against today's wall time, so a
    test dates its entries around today, `_around_today`). The registry is the
    run's agent knowledge (`<agent root>/skills/tacit-knowledge/registry.yaml`), so the
    throwaway tree is the run tenant's agent root — never `defender_dir`, which holds none."""
    return VerbContext(
        defender_dir=DEFENDER, run_dir=tmp_path / "run", env={},
        tenant=_tenants1106.fixture_run_tenant(agent_root=root),
    )


def _around_today(*, added: int, review: int) -> dict[str, str]:
    """The `added_at` and `review_by` of an entry dated `added` and `review` days from today (the
    day a lookup with no call-scoped clock judges against, #1390 amendment 4), so the test needs no
    pinned clock."""
    today = dt.datetime.now(dt.UTC).date()
    return {"added_at": (today + dt.timedelta(days=added)).isoformat(),
            "review_by": (today + dt.timedelta(days=review)).isoformat()}


def test_lookup_verb_answers_off_the_registry_it_is_handed(tmp_path):
    root = tmp_path / "tree"
    _write_registry(root, _entry(id="tk-fixture-only", **_around_today(added=-30, review=30)))
    ctx = _ctx(root, tmp_path)

    hit = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    assert isinstance(hit, dict)
    assert hit["matched"] is not None, (
        "the verb came back empty for the actor, host and pattern its own fixture entry "
        "covers — the lookup is not reading the registry it was handed"
    )
    assert hit["matched"]["id"] == "tk-fixture-only", (
        "the verb answered from a tree other than the one its `VerbContext` names"
    )
    assert set(hit["matched"]) == set(registry().ENTRY_FIELDS), (
        "the matched entry reaching the model is not the loaded entry — the payload a human "
        "reviews and the row a `:R consultations` cites have to be the same record"
    )

    miss = _platform_lookup(ctx, actor=ACTOR, host="web-frontend-02.prod", pattern=PATTERN)
    assert miss["matched"] is None, (
        "a host outside every entry's `host_scope` was a hit — an unconditional-hit lookup "
        "authorizes the whole estate through one verb call"
    )

    _write_registry(root, _entry(id="tk-fixture-only", **_around_today(added=-60, review=-30)))
    expired = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    assert expired["matched"] is None, (
        "the entry answered past its own `review_by` — expiry is applied by `find_entry` and "
        "the verb is not going through it"
    )


def test_no_authz_grounding_from_a_past_ai_verdict(tmp_path):
    """Nothing in the tacit-knowledge path derives an `authorized` verdict from resemblance to a
    past AI-resolved case."""
    assert not any(
        term in field
        for field in registry().ENTRY_FIELDS
        for term in ("case", "precedent", "similar")
    ), (
        "the entry shape grew a field that can cite a past case"
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
    assert is_system_name(SYSTEM)
    assert registry().SYSTEM == SYSTEM
    roster = read_roster(ADAPTERS)
    assert SYSTEM in roster.verbs, "the roster's systems do not include the platform-served registry"
    assert roster.verbs[SYSTEM] == {LOOKUP, "health-check"}, (
        "every rostered system answers `health-check` (skills/connect's merge bar), and the "
        "registry offers the lead one more verb, a read"
    )
    assert SYSTEM not in roster.adapter_files, "the registry is dispatched from an adapter file"
    assert LOOKUP in roster.declared_verbs(SYSTEM)

    grant: VerbGrant = _tenants1106.fixture_grants().gather
    assert (SYSTEM, LOOKUP, "r") in grant.entries, (
        "the lookup is not in gather's grant, so no lead can reach it"
    )
    assert all(
        entry[2] == "r" for entry in grant.entries if entry[0] == SYSTEM
    ), "the registry is a READ — no run-path verb may write it"

    assert ModuleVerbRegistry(roster, grant).decide(SYSTEM, LOOKUP).outcome == GRANTED


def test_the_shipped_registry_file_is_human_authored_and_loads(tmp_path):
    """The committed registry loads clean through its own loader, and its companion `SKILL.md`
    is the per-system reference every other system of record ships. Both are tenant knowledge
    (the fixture tenant's `agent/skills/tacit-knowledge/`); the product tree holds neither."""
    path = registry().registry_path(FIXTURE_AGENT)
    assert path == FIXTURE_AGENT / "skills" / SYSTEM / "registry.yaml"
    assert path.is_file(), "the registry file itself is part of this change"
    assert (FIXTURE_AGENT / "skills" / SYSTEM / "SKILL.md").is_file(), (
        "the fixture tenant's tacit-knowledge registry ships no per-system SKILL.md")
    assert not registry().registry_path(DEFENDER).exists(), (
        "the product tree still carries a tacit-knowledge registry")

    entries = registry().read_registry(path).entries
    assert all(set(e) == set(registry().ENTRY_FIELDS) for e in entries)


def test_no_run_path_writes_the_registry(tmp_path):
    # The registry a run reads is its tenant's (the fixture tenant's here).
    target = registry().registry_path(FIXTURE_AGENT)
    assert target.is_file(), "a negative reachability claim about a file that does not exist"

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text('{"rule": {"name": "probe"}}', encoding="utf-8")

    forged = "entries:\n  - id: tk-forged\n"
    gather_def = _tenants1106.fixture_gather_def()
    for defn, label in ((MAIN_DEF, "main"), (gather_def, "gather")):
        policy = compile_policy_for(defn, run_dir, defender_dir=DEFENDER)
        decision = permission.decide_write(
            target, forged, run_dir=run_dir, defender_dir=DEFENDER, policy=policy,
        )
        assert not decision.allow, (
            f"the {label} role may write the tacit-knowledge registry — the agent can author "
            f"its own authorization"
        )

    assert compile_policy_for(gather_def, run_dir, defender_dir=DEFENDER).write_allow == (), (
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


_MUTATING_STEMS = (
    "write", "save", "add", "append", "put", "post", "create", "insert", "upsert",
    "update", "set", "delete", "remove", "drop", "edit", "patch", "sync", "commit",
)


def test_the_registry_module_exports_nothing_that_writes():
    """The registry module's own public surface and served verbs carry no write-capable name; the
    source half is `tooling/lint/lint_isolated_modules.py`."""

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
        f"the registry module exports {offenders} — a write-capable name on the one system "
        f"whose entire safety argument is that every entry traces to a human commit"
    )
    served = ModuleVerbRegistry(
        read_roster(ADAPTERS), _tenants1106.fixture_grants().gather).verbs(SYSTEM)
    verb_offenders = [v for v in served if v.split("-")[0].lower() in _MUTATING_STEMS]
    assert verb_offenders == [], (
        f"the roster would advertise {verb_offenders} to a lead — a mutating verb on a "
        f"read-only system of record"
    )


@pytest.mark.parametrize("verb", ["health-check", LOOKUP])
def test_every_registry_verb_takes_a_verb_context_first(verb):
    import inspect

    served = ModuleVerbRegistry(
        read_roster(ADAPTERS), _tenants1106.fixture_grants().gather).verbs(SYSTEM)
    params = list(inspect.signature(served[verb]).parameters.values())
    assert params[0].name == "ctx"
    assert params[0].annotation in (VerbContext, "VerbContext")
    assert all(p.kind is p.KEYWORD_ONLY and p.annotation is not p.empty for p in params[1:])


# ---------------------------------------------------------------- #1390: a platform-served system


def _verbs(roster=None) -> dict:
    """`tacit-knowledge`'s verbs as the gather registry over the checkout's adapters serves them
    (the frame the query tool calls), never through an adapter module."""
    return ModuleVerbRegistry(
        read_roster(ADAPTERS) if roster is None else roster,
        _tenants1106.fixture_grants().gather).verbs(SYSTEM)


def _platform_lookup(ctx: VerbContext, **params: str) -> dict:
    return _verbs()[LOOKUP](ctx, **params)


def _clocked_ctx(root: Path, tmp_path: Path) -> VerbContext:
    """A `VerbContext` over the throwaway agent root `root`. It carries no day (#1385 O1): the
    day comes from the call-scoped run clock (`scene.judged_on`), else wall time."""
    return VerbContext(
        defender_dir=DEFENDER, run_dir=tmp_path / "run", env={},
        tenant=_tenants1106.fixture_run_tenant(agent_root=root),
    )


def _current_entry(**overrides: str) -> dict:
    """A well-formed entry in force on the day the suite runs (wall clock)."""
    today = dt.datetime.now(dt.UTC).date()
    return _entry(added_at=str(today - dt.timedelta(days=10)),
                  review_by=str(today + dt.timedelta(days=30)), **overrides)


def test_1390_lookup_is_answered_with_no_adapter_module(tmp_path):
    """The gather registry over the real roster answers `tacit-knowledge.lookup` off the registry file, with no adapter module. O1."""
    root = tmp_path / "tree"
    entry = _current_entry(id="tk-1390-now")
    _write_registry(root, entry)
    ctx = _clocked_ctx(root, tmp_path)

    hit = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    miss = _platform_lookup(ctx, actor=ACTOR, host="web-frontend-02.prod", pattern=PATTERN)

    assert hit == {"matched": entry}
    assert miss == {"matched": None}
    assert not (ADAPTERS / "tacit_knowledge_adapter.py").exists(), (
        "the tacit-knowledge adapter module still ships in the adapters folder")


def test_1390_a_tenant_without_a_registry_answers_every_lookup_with_a_miss_that_says_so(tmp_path):
    """No registry file: every lookup misses and says a miss proves nothing, and `health-check` says it is not connected. P4, amendment 8."""
    root = tmp_path / "tree"
    root.mkdir()
    ctx = _clocked_ctx(root, tmp_path)

    lookup = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    assert lookup["matched"] is None, lookup
    assert lookup.get("registry_problems"), lookup
    health = _verbs()["health-check"](ctx)
    assert (health["connected"], health["entries"]) == (False, 0)
    assert "registry_problems" not in health

    _write_registry(root, _current_entry())
    assert _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)["matched"] is not None, (
        "positive control: the same context answers a hit once the file exists")


def test_1390_health_check_names_the_registry_relative_to_the_agent_root(tmp_path):
    """`health-check` reports the registry by its agent-relative path and the count of entries that load, never a host path. Registry path."""
    root = tmp_path / "tree"
    _write_registry(root, _entry(id="tk-1390-a"), _entry(id="tk-1390-b"))

    health = _verbs()["health-check"](_clocked_ctx(root, tmp_path))

    assert health["system"] == SYSTEM
    assert (health["connected"], health["entries"]) == (True, 2)
    assert health["registry"] == "/".join(scene.REGISTRY_RELPATH)
    assert str(root) not in json.dumps(health), "health-check leaks the host path of the registry"


# The day a lookup is judged against (O2). The entry is in force from 2026-04-01 to 2026-07-01:
# valid at a replay's branch point, expired by today.
_BRANCH_ENTRY = dict(id="tk-1390-branch", added_at="2026-04-01", review_by="2026-07-01")
_IN_WINDOW = dt.datetime(2026, 5, 1, 12, 0, tzinfo=dt.UTC)


def _ask(root: Path, tmp_path: Path, *, run_state=None) -> dict | None:
    """The lookup's match with `run_state` held as the call-scoped run clock (`None`: no run)."""
    with scene.judged_on(run_state=run_state):
        return _platform_lookup(_clocked_ctx(root, tmp_path),
                                actor=ACTOR, host=HOST, pattern=PATTERN)["matched"]


def test_1390_lookup_is_judged_against_the_runs_own_clock_not_wall_time(tmp_path):
    """A replay sibling's clock (resumed at the branch point) hits an entry expired by today, which wall time would miss; a live run's clock misses it. O2."""
    from defender.investigation.run_state import RunState

    root = tmp_path / "tree"
    _write_registry(root, _entry(**_BRANCH_ENTRY))
    live = RunState(tmp_path / "live", "r-live")
    assert live.now().date() > dt.date(2026, 7, 1), "premise: the entry has expired by today"
    sibling = RunState(tmp_path / "sibling", "r-sibling")
    sibling.resume_clock(_IN_WINDOW, 0.0)

    hit = _ask(root, tmp_path, run_state=sibling)
    miss = _ask(root, tmp_path, run_state=live)

    assert (hit or {}).get("id") == "tk-1390-branch", (
        "the replay was judged on wall time, not at its own clock")
    assert miss is None, "a live run was not judged at its own clock"


def test_1390_without_a_run_state_the_day_is_wall_time(tmp_path):
    """No run state (pre-flight, the oracle's side queries): today's wall time decides, so an entry in force only at a past branch point misses, one not yet in force misses, and one in force today hits. O2."""
    root = tmp_path / "tree"
    _write_registry(root, _entry(**_BRANCH_ENTRY))
    assert dt.datetime.now(dt.UTC).date() > dt.date(2026, 7, 1), "premise: expired by today"

    assert _ask(root, tmp_path) is None, "with no run clock the entry was not judged by today"

    today = dt.datetime.now(dt.UTC).date()
    _write_registry(root, _entry(id="tk-1390-not-yet", added_at=str(today + dt.timedelta(days=2)),
                                 review_by=str(today + dt.timedelta(days=30))))
    assert _ask(root, tmp_path) is None, "an entry not yet in force today answered on wall time"

    _write_registry(root, _current_entry(id="tk-1390-today"))
    assert (_ask(root, tmp_path) or {}).get("id") == "tk-1390-today", (
        "positive control: an entry in force today answers on wall time")


# What a lookup says about a registry it could not read whole (O9 as amended, H8):
# `registry_problems`, a notice naming no entry, beside an unchanged `matched`.
_NOT_YAML = b"entries: [unclosed\n"
_NOT_UTF8 = b"\xff\xfe entries:\n"
_WHOLE_FILE_FAULTS = {
    "no-entries-list": b"sanctions:\n  - id: tk-misfiled\n",
    "top-level-list": b"- id: tk-1\n",
    "not-yaml": _NOT_YAML,
    "not-utf8": _NOT_UTF8,
}


@pytest.mark.parametrize("fault", sorted(_WHOLE_FILE_FAULTS))
def test_1390_a_registry_refused_whole_answers_a_miss_carrying_a_notice(tmp_path, fault):
    """A registry refused whole answers `matched: None` plus a `registry_problems` notice that is not the reader's refusal text and names no host path. O9."""
    root = tmp_path / "tree"
    path = registry().registry_path(root)
    path.parent.mkdir(parents=True)
    path.write_bytes(_WHOLE_FILE_FAULTS[fault])
    reason = registry().read_registry(path).fatal
    assert reason, f"premise: the reader refuses a {fault} file whole, naming it"
    assert str(path) in reason, f"premise: the reader refuses a {fault} file whole, naming it"

    answer = _platform_lookup(_clocked_ctx(root, tmp_path), actor=ACTOR, host=HOST, pattern=PATTERN)

    assert set(answer) == {"matched", "registry_problems"}, answer
    assert answer["matched"] is None, answer
    assert "refused whole" in answer["registry_problems"], answer
    assert reason not in answer["registry_problems"], "the model was shown the author's refusal text"
    assert "tk-misfiled" not in str(answer), "the model was shown an id from a refused file"
    assert str(root) not in str(answer), "the model-visible answer names a host path"


def test_1390_dropped_entries_are_counted_beside_a_hit_and_a_miss_and_never_named(tmp_path):
    """Dropped entries are counted on a hit and on a miss, with no id or scope of theirs in the answer, so a refused entry cannot be cited; a clean file carries no key. O9."""
    good = _current_entry(id="tk-1390-good")
    blanket = _current_entry(id="tk-1390-blanket", actor_scope="*")
    root = tmp_path / "tree"
    _write_registry(root, good, blanket)
    dropped = list(registry().read_registry(registry().registry_path(root)).refusals)
    assert len(dropped) == 1, f"premise: the reader drops exactly the blanket entry: {dropped}"
    assert "tk-1390-blanket" in dropped[0], f"premise: the reader drops exactly the blanket entry: {dropped}"
    ctx = _clocked_ctx(root, tmp_path)

    hit = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    miss = _platform_lookup(ctx, actor=ACTOR, host="web-frontend-02.prod", pattern=PATTERN)

    assert hit["matched"] == good, hit
    assert miss["matched"] is None, miss
    for answer in (hit, miss):
        assert "1 registry entr(ies) were refused" in answer["registry_problems"], answer
        assert "tk-1390-blanket" not in str(answer), "the model was shown a refused entry's id"
        assert "blanket scope" not in str(answer), "the model was shown the author's refusal text"

    clean = tmp_path / "clean"
    _write_registry(clean, good)
    assert _platform_lookup(_clocked_ctx(clean, tmp_path), actor=ACTOR, host=HOST,
                            pattern=PATTERN) == {"matched": good}, (
        "positive control: a clean file answers `matched` alone")


def test_1390_health_check_carries_the_same_registry_problems(tmp_path):
    """`health-check` carries the lookup's notice for a dropped entry and for a whole-file refusal, and none for a clean file. O9."""
    root = tmp_path / "tree"
    _write_registry(root, _current_entry(id="tk-1390-ok"), _current_entry(id="tk-1390-x", host_scope="*"))
    ctx = _clocked_ctx(root, tmp_path)
    health = _verbs()["health-check"](ctx)
    assert health["registry_problems"] == _platform_lookup(
        ctx, actor=ACTOR, host=HOST, pattern=PATTERN)["registry_problems"]
    assert "tk-1390-x" not in str(health), "the model was shown a refused entry's id"

    whole = tmp_path / "whole"
    path = registry().registry_path(whole)
    path.parent.mkdir(parents=True)
    path.write_bytes(_WHOLE_FILE_FAULTS["no-entries-list"])
    health = _verbs()["health-check"](_clocked_ctx(whole, tmp_path))
    relative = "/".join(scene.REGISTRY_RELPATH)
    assert "refused whole" in health["registry_problems"], health
    assert health["registry"] == relative

    clean = tmp_path / "clean"
    _write_registry(clean, _current_entry())
    assert "registry_problems" not in _verbs()["health-check"](_clocked_ctx(clean, tmp_path)), (
        "positive control: a clean registry reports no problems")


def test_1390_health_check_says_nothing_about_a_grant_it_cannot_see(tmp_path):
    """`health-check` reports the file alone: it cannot see the grant, so a note that a registry may be unused would be false wherever `lookup` is granted. Amendment 8."""
    root = tmp_path / "tree"
    _write_registry(root, _current_entry())

    health = _verbs()["health-check"](_clocked_ctx(root, tmp_path))

    assert "grant" not in json.dumps(health).lower(), f"health-check talks about the grant: {health}"
    assert (health["connected"], health["entries"]) == (True, 1), health


def test_1390_the_connect_page_no_longer_says_the_registry_is_already_connected_and_says_lookup_needs_a_grant():
    """`skills/connect/tacit.md` says the registry is unused until `lookup` is granted and drops "already connected". H7."""
    text = " ".join((DEFENDER / "skills" / "connect" / "tacit.md").read_text(encoding="utf-8").lower().split())

    assert "already connected" not in text, "the page still presents the registry as a connected system"
    assert re.search(r"lookup.{0,80}grant|grant.{0,80}lookup", text), "the page does not say lookup must be granted"


_PLANTED_TACIT = '''\
from defender.kit.verbs import VerbContext


def lookup(ctx: VerbContext, *, actor: str, host: str, pattern: str) -> dict:
    return {"matched": {"id": "tk-planted-by-an-adapter"}}


def health_check(ctx: VerbContext) -> dict:
    return {"system": "tacit-knowledge", "connected": True}


VERBS = {"lookup": lookup, "health-check": health_check}
'''

_ORDINARY = '''\
from defender.kit.verbs import VerbContext


def health_check(ctx: VerbContext) -> dict:
    return {"system": "cmdb"}


VERBS = {"health-check": health_check}
'''


def test_1390_an_adapter_named_tacit_knowledge_is_refused_with_its_reason_and_not_served(tmp_path):
    """An adapter file claiming the reserved name is refused with a reason, other adapters keep working, and a lookup is still the platform's. A5."""
    adapters = tmp_path / "integrations"
    adapters.mkdir()
    (adapters / "tacit_knowledge_adapter.py").write_text(_PLANTED_TACIT, encoding="utf-8")
    (adapters / "cmdb_adapter.py").write_text(_ORDINARY, encoding="utf-8")

    roster = read_roster(adapters)

    assert "cmdb" in roster.adapter_files, "positive control: an ordinary adapter is accepted"
    assert "cmdb" in roster.verbs
    assert "cmdb" not in roster.refused
    assert SYSTEM not in roster.adapter_files, "the reserved name was dispatched from a file"
    assert SYSTEM in roster.refused, "the reserved name was dropped silently"
    assert "reserved" in roster.refused[SYSTEM], (
        f"the refusal does not say why: {roster.refused[SYSTEM]!r}")
    root = tmp_path / "tree"
    _write_registry(root, _current_entry())
    only_lookup = VerbGrant("gather", ((SYSTEM, LOOKUP, "r"),))
    served = ModuleVerbRegistry(roster, only_lookup).verbs(SYSTEM)[LOOKUP](
        _clocked_ctx(root, tmp_path), actor=ACTOR, host=HOST, pattern=PATTERN)
    assert (served["matched"] or {}).get("id") == scene.ENTRY_ID, (
        "the lookup was served by the planted adapter, not the platform")


@pytest.mark.parametrize("kind", ["directory", "dangling-symlink", "symlink-loop"])
def test_1390_a_non_regular_thing_at_the_registry_path_is_refused_whole_in_both_answers(tmp_path, kind):
    """A directory, dangling symlink or symlink loop at the registry path answers lookup and health-check with `registry_problems` (the reader's reason, no host path), never as an absent registry. P4, O9."""
    root = tmp_path / "tree"
    path = registry().registry_path(root)
    path.parent.mkdir(parents=True)
    if kind == "directory":
        path.mkdir()
    elif kind == "dangling-symlink":
        path.symlink_to("nowhere-1390.yaml")
    else:
        path.symlink_to(path.name)
    ctx = _clocked_ctx(root, tmp_path)

    lookup = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    health = _verbs()["health-check"](ctx)

    assert lookup["matched"] is None, f"not refused: {lookup}"
    assert lookup.get("registry_problems"), f"not refused: {lookup}"
    assert health.get("registry_problems"), f"not refused: {health}"
    assert health["connected"] is True, f"not refused: {health}"
    assert str(root) not in str(lookup) + str(health), "a model-visible answer names a host path"


def test_1390_a_path_that_cannot_be_looked_at_is_refused_never_absent(tmp_path):
    """A registry path whose look-up fails for any reason but "nothing there" (here a looping parent directory, which also fails as root, unlike a permission bit) is refused whole in the reader and both answers: a broken registry never reads as an empty one. P4."""
    root = tmp_path / "tree"
    path = registry().registry_path(root)
    path.parent.parent.mkdir(parents=True)
    path.parent.symlink_to(path.parent.name)

    read = registry().read_registry(path)
    assert not read.absent, read
    assert read.problems, read
    ctx = _clocked_ctx(root, tmp_path)
    lookup = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    assert lookup["matched"] is None, lookup
    assert lookup.get("registry_problems"), lookup
    assert _verbs()["health-check"](ctx)["connected"] is True


def test_1390_a_pipe_at_the_registry_path_is_refused_without_hanging(tmp_path):
    """A named pipe at the registry path is refused whole. An ordinary open would block forever waiting for a writer, so the read runs on a thread that a failing test abandons rather than holding the suite. P4."""
    import os
    import threading

    path = registry().registry_path(tmp_path / "tree")
    path.parent.mkdir(parents=True)
    os.mkfifo(path)
    answers = []
    reader = threading.Thread(target=lambda: answers.append(registry().read_registry(path)), daemon=True)

    reader.start()
    reader.join(timeout=10)

    assert answers, "read_registry blocked on a named pipe"
    assert answers[0].fatal, answers[0]
    assert not answers[0].absent, answers[0]


def test_1390_a_regular_file_where_a_parent_folder_belongs_is_refused_not_absent(tmp_path):
    """A parent of the registry path that is not a folder is a broken tree, not a tenant with no registry. P4."""
    path = registry().registry_path(tmp_path / "tree")
    path.parent.parent.mkdir(parents=True)
    path.parent.write_text("not a folder\n", encoding="utf-8")

    read = registry().read_registry(path)

    assert read.fatal, read
    assert not read.absent, read


def test_1390_a_dangling_link_as_a_parent_folder_still_warns_a_lookup(tmp_path):
    """A dangling link in a parent reports "not found", so it reads as absent. The `lookup` still says a miss proves nothing, which is the harm a broken tree would otherwise do. P4, amendment 8."""
    root = tmp_path / "tree"
    path = registry().registry_path(root)
    path.parent.parent.mkdir(parents=True)
    path.parent.symlink_to("nowhere-1390")

    lookup = _platform_lookup(_clocked_ctx(root, tmp_path), actor=ACTOR, host=HOST, pattern=PATTERN)

    assert lookup["matched"] is None, lookup
    assert lookup.get("registry_problems"), lookup


def test_1390_nothing_at_the_path_is_a_notice_to_a_lookup_and_a_failure_to_the_authors_check(tmp_path, capsys):
    """No registry file is no problem to `health-check` or the shared problem list. To a `lookup`, which runs only under a grant, it is a notice that a miss proves nothing. To `tacit_cli check` it is a failure: someone checking a file that is not there is probably in the wrong tree. P4, amendment 8."""
    from defender.cli import tacit_cli

    root = tmp_path / "tree"
    path = registry().registry_path(root)
    read = registry().read_registry(path)
    assert read.absent, read
    assert read.problems == []
    ctx = _clocked_ctx(root, tmp_path)
    lookup = _platform_lookup(ctx, actor=ACTOR, host=HOST, pattern=PATTERN)
    assert lookup["matched"] is None, lookup
    assert "does not show that nobody sanctioned" in lookup.get("registry_problems", ""), lookup
    health = _verbs()["health-check"](ctx)
    assert health["connected"] is False, health
    assert "registry_problems" not in health, health

    assert tacit_cli.main(["check", "--defender-dir", str(root)]) == 1
    assert "no registry at this path" in capsys.readouterr().out


@pytest.mark.parametrize("field", ["actor_scope", "host_scope"])
@pytest.mark.parametrize("make", [
    lambda n: "x" * n + "*", lambda n: "*" + "x" * n, lambda n: "x" * (n // 2) + "*" + "x" * (n - n // 2),
    lambda n: "x" * n + "?*", lambda n: "[ab]" + "x" * n + "*"], ids=["trail", "lead", "mid", "q", "bracket"])
def test_1390_a_wildcard_scope_loads_iff_it_has_the_minimum_literal_characters(tmp_path, field, make):
    """A wildcard scope with MIN-1 literal characters is refused and one with MIN loads, for both scope fields and several placements."""
    minimum = registry().TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS
    for n in (minimum - 1, minimum):
        value = make(n)
        assert registry().literal_chars(value) == n, f"premise: {value!r}"
        entry = _entry(id=f"tk-lit-{n}", **{field: value})
        loaded = _ids(_load(tmp_path / f"n{n}", entry))
        assert (loaded == [entry["id"]]) == (n >= minimum), f"{field}={value!r} ({n} literal chars): {loaded}"
