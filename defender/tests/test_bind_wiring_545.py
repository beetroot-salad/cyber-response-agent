"""Executable spec (written BEFORE the code) for design #545 — wire bind/compile_policy
into production (AgentDefinition consolidation step two). The demand list, structure, and
gate live in `spec_graph_545.yaml` beside this file.

#544 shipped the primitive layer (AgentDefinition / ToolSet / BashGrammar / RunScope →
resolve_roots → compile_policy → bind, + the AGENTS registry) as CHARACTERIZATION ONLY —
`bind`/`compile_policy` have zero production callers; every agent's deps + AgentPolicy is
still built by the per-agent factories (policy_for / _judge_policy / _actor_policy /
_ORACLE_POLICY / _VERIFY_POLICY / _lead_author_policy). #545 makes `bind` the single
deps + policy seam for all 7 roles and closes the #544 xhigh-review footguns.

Resolved decisions (ycochav):
  (1a) bind gains a `salt` seam (salt=None → fresh uuid4 for the stages; a carried run salt
       for MAIN/GATHER) → it becomes the real deps factory. The run salt is the untrusted-
       data trust token, threaded to BOTH the deps and orient's alert wrap; a fresh uuid4
       for MAIN would split it and fail the injection defense open.
  (2)  LEAD_AUTHOR is FULLY BINDABLE via a `repo_root` seam (the worktree), threaded as
       LeadAuthorDeps.for_run does today; compile_policy grows the worktree-anchored write
       scope (build_write_allow(<wt>/defender/skills, '.md')) + the rm-of-drafts grant, and
       bind raises without repo_root (symmetric with the actor-confine fail-loud).
  (3)  read_shapes is CONSUMED as read-tool↔bash-lane filename PARITY — decide_read admits
       exactly the filename set the bash cat lane does; read_shapes is an ADDITIVE 10th
       AgentPolicy field, so field-for-field parity is over the 9 LEGACY fields.

Red/green at HEAD: the primitive layer already EXISTS (from #544), so every import resolves
— the expected red is RUNTIME (a bind kwarg not yet accepted; a footgun not yet closed;
read_shapes not yet filtered), not a collection ImportError. Parity + isolation + the
positive controls are GREEN@HEAD characterization (the fold must keep them green); the
salt-carry / footgun-A / lead-author / read_shapes / task-2 / wiring tests are RED@HEAD.

The one end-to-end salt-coherence canary is driven through the replay harness in
`tests/e2e/test_salt_coherence_545.py` (kept out of this unit file per the e2e layout).

Hermetic: unit tests call bind / compile_policy / the gate directly. No network, no key.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender._paths import PATHS  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.leads.lead_author_engine import (  # noqa: E402
    LEAD_AUTHOR_DEF,
    LeadAuthorDeps,
    _lead_author_policy,
)
from defender.learning.pipeline.actor_engine import ActorDeps, _actor_policy  # noqa: E402
from defender.learning.pipeline.judge.engine_pydantic import (  # noqa: E402
    JudgeDeps,
    _judge_policy,
)
from defender.learning.pipeline.oracle_engine import OracleDeps, _ORACLE_POLICY  # noqa: E402
from defender.learning.author.verify_forward.engine import (  # noqa: E402
    VerifierDeps,
    _VERIFY_POLICY,
)
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.permission.policies._common import reader_patterns  # noqa: E402
from defender.runtime.tools import AgentDeps, GatherDeps  # noqa: E402

from defender.runtime.agent_definition import (  # noqa: E402
    BashGrammar,
    RunScope,
    ToolSet,
    bind,
    compile_policy,
    resolve_roots,
)
from defender.runtime.agents import (  # noqa: E402
    ACTOR_DEF,
    GATHER_DEF,
    JUDGE_DEF,
    MAIN_DEF,
    ORACLE_DEF,
    VERIFY_DEF,
)

_DEFENDER = PATHS.defender_dir

# Real repo-relative script/confine paths (mirrors test_agent_definition.py) — the actor's
# _script_pattern does script.resolve().relative_to(REPO_ROOT), so synthetic paths raise.
_ENV_RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_ACTOR_INDEX = config.LESSONS_ACTOR_INDEX_SCRIPT
_ACTOR_DIR = config.LESSONS_ACTOR_DIR
_ENV_DIR = config.LESSONS_ENVIRONMENT_DIR

_DEFAULT_SCOPE = RunScope()  # frozen — one safe module-level singleton


def _policy9(p) -> tuple:
    """The 9 LEGACY AgentPolicy fields as a comparable tuple (bash_allow / write_allow
    Patterns → their source strings). Deliberately INCLUDES write_allow — the field the
    repo's `_policy_fields` OMITS (see policy_fields_covers_write_allow) — and EXCLUDES the
    additive read_shapes (the intended #545 delta, tested separately). This is what
    'field-for-field parity' means for the wiring: no unintended widening in any legacy
    field, write scope included."""
    return (
        tuple(pat.pattern for pat in p.bash_allow),
        p.jq_operand_gated, p.adapters, p.adapter_sql_pipe, p.raw_reads,
        tuple(str(r) for r in p.read_roots),
        tuple(str(r) for r in p.read_confine),
        tuple(pat.pattern for pat in p.write_allow),
        p.deny_reason,
    )


def _actor_scope() -> RunScope:
    return RunScope(scripts=(_ENV_RETRIEVE, _ACTOR_INDEX), read_confine=(_ACTOR_DIR, _ENV_DIR))


# ============================================================================
# Demand #0 — the return-value contract (decision 1a)
# ============================================================================

def test_bind_return_contract(tmp_path):
    """d0_bind_return_contract: bind returns the role's AgentDeps subtype carrying
    compile_policy's AgentPolicy as .policy, run_id == run_dir.name, and (salt seam) the
    passed salt verbatim. RED@HEAD on the salt kwarg (bind's signature has no `salt`)."""
    deps = bind(JUDGE_DEF, tmp_path, scope=RunScope(add_dirs=(tmp_path / "cmp",)), salt="a" * 16)
    assert isinstance(deps, JudgeDeps)
    assert isinstance(deps.policy, permission.AgentPolicy)
    assert deps.run_id == tmp_path.name
    assert deps.salt == "a" * 16


# ============================================================================
# Salt carriage (decision 1a) — the injection-defense trust token
# ============================================================================

def test_salt_fresh_by_default(tmp_path):
    """salt_fresh_by_default (GREEN@HEAD, positive control): with no salt bind mints a fresh
    32-hex uuid4, and two calls differ — the stages' behavior, preserved."""
    d1 = bind(ORACLE_DEF, tmp_path)
    d2 = bind(ORACLE_DEF, tmp_path)
    assert re.fullmatch(r"[0-9a-f]{32}", d1.salt)  # a fresh 32-hex uuid4
    assert d1.salt != d2.salt


def test_salt_carried_when_given(tmp_path):
    """salt_carried_when_given (RED@HEAD): bind(..., salt=S) returns deps whose .salt == S
    verbatim — identity carried, never re-minted. bind grows a `salt` kw."""
    deps = bind(ORACLE_DEF, tmp_path, salt="feedface" * 2)
    assert deps.salt == "feedface" * 2


def test_gather_inherits_parent_salt(tmp_path):
    """gather_inherits_parent_salt (RED@HEAD): the GATHER reroute binds with the parent run's
    salt so the subagent's read tags + return wrapper carry the ONE salt per run (otherwise
    the gather return is tagged with a salt the main loop does not distrust)."""
    parent = "cafebabe" * 2
    gdeps = bind(GATHER_DEF, tmp_path, salt=parent)
    assert isinstance(gdeps, GatherDeps)
    assert gdeps.salt == parent


# ============================================================================
# Full-role policy parity (task 1 + acceptance C) — all 9 LEGACY fields
# ============================================================================

def test_parity_main_nine_fields(tmp_path):
    """parity_main (GREEN@HEAD): bind(MAIN_DEF).policy == policy_for('main') over all 9 legacy
    fields, write_allow INCLUDED (the run-dir write subtree)."""
    bound = bind(MAIN_DEF, tmp_path).policy
    authored = permission.policy_for("main", run_dir=tmp_path, defender_dir=_DEFENDER)
    assert _policy9(bound) == _policy9(authored)


def test_parity_gather_nine_fields(tmp_path):
    """parity_gather (GREEN@HEAD): bind(GATHER_DEF).policy == policy_for('gather') over all 9
    legacy fields (adapters/adapter_sql_pipe/raw_reads True, no write_allow)."""
    bound = bind(GATHER_DEF, tmp_path).policy
    authored = permission.policy_for("gather", run_dir=tmp_path, defender_dir=_DEFENDER)
    assert _policy9(bound) == _policy9(authored)


def test_parity_judge_nine_fields(tmp_path):
    """parity_judge (GREEN@HEAD): bind(JUDGE_DEF, scope=add_dirs).policy == _judge_policy over
    all 9 legacy fields (jq_operand_gated + raw_reads True, read_roots == the add-dirs)."""
    cmp = (tmp_path / "cmp1", tmp_path / "cmp2")
    bound = bind(JUDGE_DEF, tmp_path, scope=RunScope(add_dirs=cmp)).policy
    authored = _judge_policy(read_roots=cmp, ticket_cli=None)
    assert _policy9(bound) == _policy9(authored)


def test_parity_actor_nine_fields(tmp_path):
    """parity_actor (GREEN@HEAD with a confine scope): bind(ACTOR_DEF, scope=scripts+confine)
    .policy == _actor_policy over all 9 legacy fields (read_confine REPLACES defender_dir; one
    python3 pattern per pinned script)."""
    scope = _actor_scope()
    bound = bind(ACTOR_DEF, tmp_path, scope=scope).policy
    authored = _actor_policy(scope.scripts, read_confine=scope.read_confine)
    assert _policy9(bound) == _policy9(authored)


def test_parity_oracle_nine_fields(tmp_path):
    """parity_oracle (GREEN@HEAD): bind(ORACLE_DEF).policy == _ORACLE_POLICY (all-deny)."""
    assert _policy9(bind(ORACLE_DEF, tmp_path).policy) == _policy9(_ORACLE_POLICY)


def test_parity_verifier_nine_fields(tmp_path):
    """parity_verifier (GREEN@HEAD): bind(VERIFY_DEF).policy == _VERIFY_POLICY (all-deny)."""
    assert _policy9(bind(VERIFY_DEF, tmp_path).policy) == _policy9(_VERIFY_POLICY)


def test_parity_lead_author_nine_fields(tmp_path):
    """parity_lead_author (RED@HEAD): bind(LEAD_AUTHOR_DEF, repo_root=wt).policy ==
    _lead_author_policy(<wt>/defender/skills) over all 9 legacy fields — write_allow anchored
    on the worktree skills subtree (.md suffix) + the rm-of-drafts bash grant. RED@HEAD: no
    repo_root kw + no LEAD_AUTHOR arm in _deps_class."""
    skills_dir = tmp_path / "defender" / "skills"
    bound = bind(LEAD_AUTHOR_DEF, tmp_path / "run", repo_root=tmp_path).policy
    authored = _lead_author_policy(skills_dir)
    assert _policy9(bound) == _policy9(authored)


# ============================================================================
# The parity projection must cover write_allow (footgun B, 2nd half)
# ============================================================================

def test_policy_fields_covers_write_allow():
    """policy_fields_covers_write_allow (RED@HEAD): the _policy_fields projection in BOTH
    test files must include write_allow, so two policies differing ONLY in write_allow project
    UNEQUAL. RED@HEAD: both copies omit write_allow, so the projections are (wrongly) equal."""
    from defender.tests.test_agent_definition import _policy_fields as pf_main
    from defender.tests.test_agent_deps_construction import _policy_fields as pf_deps

    wide = permission.AgentPolicy(write_allow=(re.compile(r"/anything/.*"),), deny_reason="d")
    narrow = permission.AgentPolicy(write_allow=(), deny_reason="d")
    assert pf_main(wide) != pf_main(narrow), "test_agent_definition._policy_fields omits write_allow"
    assert pf_deps(wide) != pf_deps(narrow), "test_agent_deps_construction._policy_fields omits write_allow"


# ============================================================================
# _deps_class maps all 7 roles (footgun C + decision 2)
# ============================================================================

def test_deps_class_all_seven_roles(tmp_path):
    """deps_class_all_seven (RED@HEAD on LEAD_AUTHOR): bind maps every AgentRole to its
    subtype and returns an instance of it. RED@HEAD: LEAD_AUTHOR has no _deps_class arm (and
    no repo_root seam), so bind(LEAD_AUTHOR_DEF) raises a generic ValueError today."""
    cases = [
        (bind(MAIN_DEF, tmp_path), AgentDeps),
        (bind(GATHER_DEF, tmp_path), GatherDeps),
        (bind(JUDGE_DEF, tmp_path, scope=RunScope(add_dirs=(tmp_path / "c",))), JudgeDeps),
        (bind(ACTOR_DEF, tmp_path, scope=_actor_scope()), ActorDeps),
        (bind(ORACLE_DEF, tmp_path), OracleDeps),
        (bind(VERIFY_DEF, tmp_path), VerifierDeps),
        (bind(LEAD_AUTHOR_DEF, tmp_path / "run", repo_root=tmp_path), LeadAuthorDeps),
    ]
    # exactly one deps subtype per role member — no role left unmapped
    assert len({role for role in AgentRole}) == 7
    for deps, expected in cases:
        assert type(deps) is expected, f"{deps.role} → {type(deps).__name__}, want {expected.__name__}"


# ============================================================================
# Footgun A — actor confine fail-loud (R5 safe-by-construction)
# ============================================================================

def test_bind_actor_default_scope_fails_loud(tmp_path):
    """actor_default_scope_fails_loud (RED@HEAD): bind(ACTOR_DEF, run_dir) with the default
    empty-read_confine scope RAISES — no ActorDeps is ever constructed via bind whose resolved
    read roots widen to the whole defender_dir (the #512 gray-box rubric leak). RED@HEAD: bind
    silently produces an unconfined actor today."""
    with pytest.raises((ValueError, TypeError)):
        bind(ACTOR_DEF, tmp_path)  # no read_confine in the default RunScope


def test_bind_actor_with_confine_succeeds(tmp_path):
    """actor_confine_positive_control (GREEN@HEAD): bind(ACTOR_DEF, scope=<confine>) succeeds;
    policy.read_confine == the confine, and the resolved read roots do NOT include the whole
    defender_dir (the confine REPLACES the defender_dir base)."""
    from defender.runtime.permission import files

    scope = _actor_scope()
    deps = bind(ACTOR_DEF, tmp_path, scope=scope)
    assert deps.policy.read_confine == scope.read_confine
    roots = files._resolved_read_roots(deps.policy, tmp_path, _DEFENDER)
    assert _DEFENDER.resolve() not in roots  # the whole corpus is NOT reachable


def test_bind_main_empty_confine_ok(tmp_path):
    """main_empty_confine_ok (GREEN@HEAD): bind(MAIN_DEF, run_dir) with the default empty
    confine SUCCEEDS — the empty-confine ban is actor-specific; main legitimately reads
    defender_dir."""
    deps = bind(MAIN_DEF, tmp_path)
    assert deps.policy.read_confine == ()


# ============================================================================
# LEAD_AUTHOR fully bindable (decision 2)
# ============================================================================

def test_lead_author_write_anchored_worktree(tmp_path):
    """lead_author_write_anchored_worktree (RED@HEAD, negative): the bound lead-author's
    write_allow admits <wt>/defender/skills/x.md but NOT run_dir/x.md (wrong root) and NOT
    <wt>/defender/skills/x.txt (wrong suffix) — never the run-dir widening a naive
    compile_policy would emit. Positive control: the sanctioned .md write IS admitted."""
    repo_root = tmp_path
    run_dir = tmp_path / "run"
    skills_dir = repo_root / "defender" / "skills"
    pol = bind(LEAD_AUTHOR_DEF, run_dir, repo_root=repo_root).policy

    def _writable(p: Path) -> bool:
        return permission.decide_write(p, run_dir=run_dir, defender_dir=repo_root / "defender", policy=pol).allow

    assert _writable(skills_dir / "gather" / "x.md")          # positive control (sanctioned .md)
    assert not _writable(run_dir / "x.md")                    # NOT the run dir (the naive widening)
    assert not _writable(skills_dir / "gather" / "x.txt")     # NOT a non-.md file


def test_lead_author_rm_scope_preserved(tmp_path):
    """lead_author_rm_scope_preserved (RED@HEAD, negative): the bound lead-author's bash_allow
    admits `rm <wt>/defender/skills/<draft>` and denies a bare `rm` and an rm outside skills —
    the scoped rm grant is not dropped (a naive compile_policy has no rm arm → bash_allow==())
    or widened to a general rm."""
    repo_root = tmp_path
    run_dir = tmp_path / "run"
    skills_dir = repo_root / "defender" / "skills"
    pol = bind(LEAD_AUTHOR_DEF, run_dir, repo_root=repo_root).policy

    def _bash_ok(cmd: str) -> bool:
        return permission.decide_bash(cmd, policy=pol, run_dir=run_dir, defender_dir=repo_root / "defender").allow

    assert _bash_ok(f"rm {skills_dir}/gather/_draft/x.md")   # positive control (scoped rm)
    assert not _bash_ok("rm -rf /")                          # not a general rm
    assert not _bash_ok(f"rm {run_dir}/report.md")           # not outside the skills subtree


def test_lead_author_defender_dir_worktree(tmp_path):
    """lead_author_defender_dir_worktree (RED@HEAD): bind(LEAD_AUTHOR_DEF, repo_root=wt) returns
    LeadAuthorDeps whose defender_dir == wt/defender (the worktree tree the gate resolves
    against), not PATHS.defender_dir — the identity carriage decision 2 requires."""
    deps = bind(LEAD_AUTHOR_DEF, tmp_path / "run", repo_root=tmp_path)
    assert deps.defender_dir == tmp_path / "defender"


def test_lead_author_missing_repo_root_fails_loud(tmp_path):
    """lead_author_missing_repo_root_fails_loud (fail-loud guard, both ways): bind(LEAD_AUTHOR_DEF)
    without repo_root RAISES — the worktree root is required to anchor the write scope; never a
    silent PATHS.defender_dir fallback that would write to the MAIN checkout. GREEN@HEAD (raises
    today via the missing _deps_class arm) and must STAY green after decision 2 (raises via the
    required-repo_root guard) — the reason changes, the fail-loud must not."""
    with pytest.raises((ValueError, TypeError)):
        bind(LEAD_AUTHOR_DEF, tmp_path / "run")  # no repo_root


# ============================================================================
# read_shapes cross-via parity (task 3, decision 3 — R3)
# ============================================================================

# Probe files (need not exist — the gate is textual/root-based):
#   corpus .md under lessons  → both the bash cat lane AND decide_read admit
#   non-.md under skills      → the bash cat lane REJECTS; decide_read must too (after impl)
_CORPUS_MD = _DEFENDER / "lessons" / "_probe_545.md"
_NON_MD = _DEFENDER / "skills" / "gather" / "run.py"   # a real non-.md corpus file


def test_read_shapes_allows_corpus_md(tmp_path):
    """read_shapes_allows_corpus_md (GREEN@HEAD, positive control): decide_read ALLOWS a corpus
    .md under lessons for the reader agent — the mechanism fires and the channel distinguishes
    allow from deny."""
    pol = bind(MAIN_DEF, tmp_path).policy
    assert permission.decide_read(_CORPUS_MD, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_read_shapes_allows_run_dir_file(tmp_path):
    """read_shapes_allows_run_dir_file (GREEN@HEAD, positive control): decide_read ALLOWS any
    file directly under run_dir regardless of filename — the run dir is unconditionally
    in-roots; the read_shapes filter applies to the corpus surface, not the run dir."""
    pol = bind(MAIN_DEF, tmp_path).policy
    assert permission.decide_read(tmp_path / "scratch.bin", run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_read_shapes_denies_nonmatching(tmp_path):
    """read_shapes_denies_nonmatching (RED@HEAD, negative): decide_read DENIES a non-.md corpus
    file for the reader agent, matching the bash cat lane's rejection. RED@HEAD: read_shapes is
    unconsumed, so decide_read is root-only and (wrongly) admits the .py file."""
    pol = bind(MAIN_DEF, tmp_path).policy
    assert not permission.decide_read(_NON_MD, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


def test_read_gate_bash_lane_parity(tmp_path):
    """read_gate_bash_lane_parity (RED@HEAD, R3): for the reader agent, decide_read and the bash
    cat lane agree on the SAME probe files — the constraint enforced on the bash via is enforced
    on the read-tool via. RED@HEAD: the .py probe is admitted by decide_read but rejected by cat
    (the step-one asymmetry). Mirrors test_read_confine_bash.py:329 'the two surfaces agree'."""
    pol = bind(MAIN_DEF, tmp_path).policy
    for probe in (_CORPUS_MD, _NON_MD):
        read_ok = permission.decide_read(probe, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow
        bash_ok = permission.decide_bash(f"cat {probe}", policy=pol, run_dir=tmp_path, defender_dir=_DEFENDER).allow
        assert read_ok == bash_ok, f"read-tool vs bash disagree on {probe}: read={read_ok} bash={bash_ok}"


def test_empty_read_shapes_no_filtering(tmp_path):
    """empty_read_shapes_no_filtering (GREEN@HEAD, positive control): a policy compiled with an
    EMPTY read_shapes applies no filename filter — decide_read admits any in-roots file. The
    filter is opt-in (backward compatible for non-reader agents)."""
    roots = resolve_roots(tmp_path, (), RunScope())
    pol = compile_policy(ToolSet(read=True, bash=BashGrammar()), (), roots, "deny")
    assert permission.decide_read(_NON_MD, run_dir=tmp_path, defender_dir=_DEFENDER, policy=pol).allow


# ============================================================================
# Task 2 — grammar contents load-bearing
# ============================================================================

def test_grammar_contents_load_bearing(tmp_path):
    """grammar_contents_load_bearing (RED@HEAD): compile_policy builds the reader bash_allow
    from the BashGrammar's declared viewers CONTENTS — two grammars differing in their viewers
    tuples compile to different bash_allow program sets. RED@HEAD: compile_policy inspects only
    non-emptiness (delegates wholesale to reader_patterns), so both compile identically."""
    roots = resolve_roots(tmp_path, (), RunScope())
    p_full = compile_policy(ToolSet(read=True, bash=BashGrammar(viewers=("cat", "grep"))), (), roots, "d")
    p_less = compile_policy(ToolSet(read=True, bash=BashGrammar(viewers=("cat",))), (), roots, "d")
    assert {pat.pattern for pat in p_full.bash_allow} != {pat.pattern for pat in p_less.bash_allow}


# ============================================================================
# Cleanups + subtraction (R5)
# ============================================================================

def test_main_gather_production_routed_through_bind():
    """factories_removed_from_production (RED@HEAD): the MAIN + GATHER production deps sites
    obtain their AgentDeps via bind, not a direct policy_for() call. RED@HEAD: driver.py and
    tools_gather.py still call policy_for('main'/'gather') inline."""
    driver_src = (PATHS.repo_root / "defender" / "runtime" / "driver.py").read_text()
    gather_src = (PATHS.repo_root / "defender" / "runtime" / "tools_gather.py").read_text()
    assert "bind(MAIN_DEF" in driver_src, "run_investigation must build MAIN deps via bind"
    assert 'policy_for("main"' not in driver_src, "the inline policy_for('main') path must be gone"
    assert "bind(GATHER_DEF" in gather_src, "_run_gather must build GATHER deps via bind"
    assert 'policy_for("gather"' not in gather_src, "the inline policy_for('gather') path must be gone"


def test_reader_patterns_kept_as_api():
    """reader_patterns_kept_as_api (GREEN@HEAD): reader_patterns and policy_for remain
    importable/callable as the kept gate API (the canonical grammar spelling + many gate-test
    consumers), so removing the parallel factory path does not break the gate suite. This pins
    the 'keep, do not delete' decision for the impl."""
    assert callable(reader_patterns)
    assert callable(permission.policy_for)


def test_resolve_roots_per_run_distinct(tmp_path):
    """resolve_roots_per_run_distinct (GREEN@HEAD, R2 isolation guard): two different run_dirs
    bound through bind get distinct resolved read_confine — one run's confine never appears in
    another run's policy (no corpus-only cache-key bleed, the #497/#534 hazard)."""
    run_a, run_b = tmp_path / "a", tmp_path / "b"
    a = bind(ACTOR_DEF, run_a, scope=RunScope(scripts=(_ENV_RETRIEVE,), read_confine=(run_a / "corpus",)))
    b = bind(ACTOR_DEF, run_b, scope=RunScope(scripts=(_ENV_RETRIEVE,), read_confine=(run_b / "corpus",)))
    assert a.policy.read_confine != b.policy.read_confine
    assert (run_a / "corpus") not in b.policy.read_confine
