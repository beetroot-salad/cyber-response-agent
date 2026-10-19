"""#983 mechanism B, the tacit-knowledge registry: entry fields and bounds (review_by, no blanket scope, exact scope match), expiry at lookup, the rostered read-only lookup verb, and that no run path can write the registry file."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from defender._git import REPO_ROOT
from defender.runtime import permission
from defender.runtime.agent_definition import compile_policy_for
from defender.runtime.driver import MAIN_DEF
from defender.tests.support.tenancy import _tenants1106
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import (
    GRANTED,
    ModuleVerbRegistry,
    VerbContext,
    is_system_name,
    read_roster,
)
from defender.tests.support.shared.contracts import _tacit983 as scene

DEFENDER = REPO_ROOT / "defender"
ADAPTERS = DEFENDER / "integrations"

SYSTEM = scene.REGISTRY_SYSTEM
LOOKUP = "lookup"

ACTOR = scene.ACTOR
HOST = scene.HOST
PATTERN = scene.PATTERN

NOW = dt.date(2026, 5, 5)


def registry():
    """The tacit-knowledge adapter module."""
    from defender.integrations import tacit_knowledge_adapter

    return tacit_knowledge_adapter


#: The entry builder and the fixture writer live in `tests/support/shared/contracts/_tacit983.py`, not here: the e2e
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
            f"a legitimately scoped {field} of {value!r} was refused as blanket — the rule has "
            f"been tuned past the entries the registry is FOR, and the one anchor kind a "
            f"container-root case can reach is unwritable"
        )


# ---------------------------------------------------------------- the lookup


def test_scope_mismatch_does_not_discharge(tmp_path):
    """An unexpired entry whose `actor_scope` or `host_scope` does not cover the alerted actor
    and host is not a hit, and the contract stays unresolved (demand `scope_must_match`)."""
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
        "an entry past its own `review_by` still discharged — a stale sanction authorizes "
        "forever, which is the one thing a file entry cannot be trusted to notice about itself"
    )


def _ctx(root: Path, tmp_path: Path, *, as_of: dt.datetime) -> VerbContext:
    """A `VerbContext` pointing at a throwaway tree and a fixed moment."""
    return VerbContext(
        defender_dir=root, run_dir=tmp_path / "run", env={}, as_of=as_of,
        tenant=_tenants1106.fixture_run_tenant(),
    )


def test_lookup_verb_answers_off_the_registry_it_is_handed(tmp_path):
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
    past AI-resolved case (demand `no_precedent_by_similarity`, non-obligation 4)."""
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
    assert is_system_name(SYSTEM)
    assert registry().SYSTEM == SYSTEM
    assert LOOKUP in registry().VERBS
    assert registry().VERBS[LOOKUP] is registry().lookup
    assert "health-check" in registry().VERBS, (
        "every rostered system answers `health-check` (skills/connect's merge bar)"
    )
    assert LOOKUP in read_roster(ADAPTERS).declared_verbs(SYSTEM), (
        "`VERBS` is read COLD off the AST — it has to be a dict literal with literal keys"
    )

    grant: VerbGrant = _tenants1106.fixture_grants().gather
    assert (SYSTEM, LOOKUP, "r") in grant.entries, (
        "the lookup is not in gather's grant, so no lead can reach it"
    )
    assert all(
        entry[2] == "r" for entry in grant.entries if entry[0] == SYSTEM
    ), "the registry is a READ — no run-path verb may write it"

    assert ModuleVerbRegistry(read_roster(ADAPTERS), grant).decide(SYSTEM, LOOKUP).outcome == GRANTED


def test_the_shipped_registry_file_is_human_authored_and_loads(tmp_path):
    """The committed registry loads clean through its own loader, and its companion `SKILL.md`
    is the per-system reference every other system of record ships."""
    path = registry().registry_path(DEFENDER)
    assert path == DEFENDER / "skills" / SYSTEM / "registry.yaml"
    assert path.is_file(), "the registry file itself is part of this change"
    assert (DEFENDER / "skills" / SYSTEM / "SKILL.md").is_file()

    entries = registry().load_entries(path)
    assert all(set(e) == set(registry().ENTRY_FIELDS) for e in entries)


def test_no_run_path_writes_the_registry(tmp_path):
    target = registry().registry_path(DEFENDER)
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


def test_the_adapter_module_exports_nothing_that_writes():
    """The tacit-knowledge adapter's own PUBLIC SURFACE carries no write-capable function, and
    its source performs no filesystem mutation (demand `registry_never_agent_written`)."""
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
    import inspect

    params = list(inspect.signature(registry().VERBS[verb]).parameters.values())
    assert params[0].name == "ctx"
    assert params[0].annotation in (VerbContext, "VerbContext")
    assert all(p.kind is p.KEYWORD_ONLY and p.annotation is not p.empty for p in params[1:])
