"""#996 — the CLERK role, its knobs, its prompt asset, and its price.

A deny-all role modelled on the questioner's: no tools, no verb grant, a frozen deps subtype
carrying only its role, an effort literal on the definition and a model resolved through the
same `provider_for` every other role goes through. Registering a TWELFTH role moves the same
hand-maintained census sites the eleventh did — and one more that the eleventh's own suite
now hardcodes.

RED against `7fa49f04`: `AgentRole` declares eleven members, `defender/skills/clerk/SKILL.md`
does not exist, and neither the `glm-5.3-flash` price row nor its Fireworks alias is in the
tree (they are working-tree throwaway edits, PROBED as absent at this base).
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._run_paths import RunPaths  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.scripts import pricing  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402

DEFENDER = C.DEFENDER
CLERK_SKILL = DEFENDER / "skills" / "clerk" / "SKILL.md"


def _clerk_def():
    return C.sym("agents", "CLERK_DEF")


def _role():
    return C.sym("runtime.agent_role", "AgentRole").CLERK


@pytest.fixture
def credentialed(monkeypatch: pytest.MonkeyPatch):
    """Every provider credentialed with a value that could not buy anything.

    The role-model preflight returns 2 on TWO unrelated conditions — a model thunk it cannot
    use, and a provider key it cannot resolve — and only the first is what these demands are
    about. Left to the ambient environment the assertions measure whether the HOST holds a
    billable key, which is the shape that makes a suite look flaky. The #947 suite learned
    this the same way."""
    providers = C.mod("runtime.providers")
    for var in providers.api_key_vars():
        monkeypatch.setenv(var, "not-a-billable-key")
    return monkeypatch


# ---------------------------------------------------------------------------------------
# the role and its registration (D4, S1)
# ---------------------------------------------------------------------------------------


def test_996_the_clerk_role_is_registered_and_bindable() -> None:
    """The clerk is a member of the role enum, its definition is registered in the agent
    registry under that member, and the registry still holds exactly one definition per role.

    D4 MINTS the key rather than reusing SUPPORT, and the reason is recorded on the enum
    itself: an enum key names a trace file, so a zero-grant call sharing SUPPORT's key would
    share its trace and its agent id. The deps subtype is checked here too, because a deps
    class that carries a run dir or a document into a deny-all call is the surface S1 is
    about."""
    AgentRole = C.sym("runtime.agent_role", "AgentRole")
    AGENTS = C.sym("agents", "AGENTS")
    clerk_def = _clerk_def()
    assert AgentRole.CLERK in AGENTS
    assert AGENTS[AgentRole.CLERK] is clerk_def
    assert clerk_def.role is AgentRole.CLERK
    assert AgentRole.CLERK.value == "clerk"
    assert set(AGENTS.keys()) == set(AgentRole)

    deps_cls = clerk_def.deps_cls
    assert dataclasses.is_dataclass(deps_cls)
    assert deps_cls.role is AgentRole.CLERK


def test_996_the_clerk_definition_grants_nothing() -> None:
    """NEGATIVE (S1): the clerk definition grants nothing on any surface it could reach — no
    tool set, no verb entry, no bash program, no read root and no write root. Deny-all by
    OMISSION, the way the oracle's and the questioner's definitions are, rather than by a grant
    line that can be edited open.

    POSITIVE CONTROL on the same address under the complementary condition: MAIN's definition,
    compiled through the identical call, DOES yield bash programs — so an empty policy here is
    the definition and not a broken compiler.

    Not `read_roots` (PROBED: MAIN's own compiled `read_roots` is `()` too, unconditionally —
    `resolve_roots` sets it from `scope.add_dirs`, and MAIN is never bound with a non-default
    `RunScope`, in this test or in production; MAIN's actual read access is `read_allow`, a
    regex allowlist, an entirely different field). `bash_allow` is the one MAIN-only surface
    among the four the negative checks that a bare-default-scope compile still lands non-empty
    for MAIN, which is what makes the clerk's empty one mean something."""
    compile_policy_for = C.sym("runtime.permission", "compile_policy_for")
    MAIN_DEF = C.sym("agents", "MAIN_DEF")
    clerk_def = _clerk_def()

    assert tuple(clerk_def.tools) == ()
    assert clerk_def.verb_grant.entries == ()
    policy = compile_policy_for(clerk_def, run_dir=DEFENDER, defender_dir=DEFENDER)
    assert not policy.bash_allow
    assert not policy.write_roots
    assert not policy.read_roots

    control = compile_policy_for(MAIN_DEF, run_dir=DEFENDER, defender_dir=DEFENDER)
    assert control.bash_allow, (
        "MAIN's compiled policy is empty too, so the clerk's empty one proves nothing"
    )


def test_996_clerk_effort_is_a_literal_with_an_env_override() -> None:
    """The clerk's reasoning effort is a LITERAL on the definition — never the provider table's
    role branch — with an environment override.

    The provider table maps effort per ROLE, so a zero-grant role added there would inherit
    whatever the main/gather branch happens to say; the literal is what makes the clerk's
    effort a property of the clerk. `low` is the shipped value because the alternative, `none`,
    is refused by the shipped model — a live-call check the validation run owns, and the reason
    `none` is the domain's distinguished member rather than its default."""
    clerk_def = _clerk_def()
    assert clerk_def.effort() == C.DEFAULT_CLERK_EFFORT


def test_996_clerk_effort_reads_its_environment_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The override is read at CALL time from the environment — the operator's seam."""
    monkeypatch.setenv(C.EFFORT_ENV, "medium")
    assert _clerk_def().effort() == "medium"


def test_996_every_hand_maintained_role_census_counts_twelve() -> None:
    """Every hand-maintained role census agrees the roster is TWELVE — both hardcoded counts
    and both enumerations, including the compiled-policy sweep whose omission is SILENT rather
    than red.

    Registering a role moves four sites, not two: `_all_policies` in `test_grant_gate_575.py`
    is the control S1 rests on, and a role registered in the registry but absent there is "a
    compiled policy the audit never looks at". The fourth site is the #947 suite's own count,
    which hardcodes eleven in its assertions AND in its function name — a site P12's own list
    omitted, and the one a reader most easily misses because it lives in another issue's
    file."""
    AgentRole = C.sym("runtime.agent_role", "AgentRole")
    AGENTS = C.sym("agents", "AGENTS")
    assert len(AgentRole) == 12
    assert len(AGENTS) == 12

    bind_src = (DEFENDER / "tests" / "test_bind_sole_seam_551.py").read_text(encoding="utf-8")
    assert "== 12" in bind_src, "the bind-case count still reads eleven"
    assert "CLERK_DEF" in bind_src, "the bind-case enumeration was not moved"

    grant_src = (DEFENDER / "tests" / "test_grant_gate_575.py").read_text(encoding="utf-8")
    assert "len(AGENTS) == 12" in grant_src, "the grant gate's hardcoded count was not moved"
    assert '"clerk"' in grant_src, "_all_policies never compiles the clerk's policy"

    prior_src = (DEFENDER / "tests" / "test_947_triplet_questioner.py").read_text(
        encoding="utf-8")
    assert "== 11" not in prior_src, (
        "the eleventh role's own census still asserts eleven, so the two censuses now "
        "contradict each other and one of them is asserting a roster that does not exist"
    )


# ---------------------------------------------------------------------------------------
# startup resolution (PO-5; cluster M)
# ---------------------------------------------------------------------------------------


def test_996_an_unresolvable_clerk_model_aborts_the_run_before_the_first_request(
    credentialed: pytest.MonkeyPatch,
) -> None:
    """An unrecognised clerk model id fails FAST at startup — rc 2 before any request — because
    the clerk role is registered into the agent registry the preflight sweeps.

    PROBED: two disjoint mechanisms with opposite philosophies live here. `provider_for` raises
    synchronously for any unrecognised string and is ALREADY wired to a real startup fail-fast
    over the registry; the pricing key never raises for any input. Registering the role buys
    the first and nothing in this port fixes the second.

    POSITIVE CONTROL: the same sweep with the SHIPPED default returns 0, so rc 2 is the model
    id and not a credential the runner lacks."""
    preflight = C.sym("run", "preflight_role_models")
    credentialed.setenv(C.MODEL_ENV, C.DEFAULT_CLERK_MODEL)
    assert preflight(None) == 0, (
        "the sweep already refuses the shipped default, so the refusal below says nothing "
        "about the clerk's model id"
    )

    credentialed.setenv(C.MODEL_ENV, "not-a-model-anyone-ships")
    assert preflight(None) == 2, (
        "an unresolvable clerk model did not abort the run at startup — the clerk role is not "
        "in the registry the preflight sweeps, so the failure lands mid-run instead"
    )


def test_996_an_unmatched_model_key_falls_through_to_the_generic_glm_row() -> None:
    """An unmatched model is silently MISPRICED, never refused — the standing warning this
    port does not fix.

    PROBED: the pricing key is a substring chain with no `else: raise` anywhere, so an unknown
    `glm*` prices as `glm-5.2` and anything else as the Anthropic default. That is the named
    bug beside the routing half, and fixing routing does not touch it: a run whose operator
    typos the clerk model gets a plausible cost number rather than a refusal. Pinned so the
    port cannot be read as having closed it."""
    assert pricing.model_key("accounts/fireworks/models/glm-9p9-imaginary") == "glm-5.2"
    assert pricing.model_key("a-model-nobody-ships") == "claude-sonnet-4-6"
    assert pricing.usage_cost("a-model-nobody-ships", {"input_tokens": 1}) > 0


def _defender_tree(tmp_path: Path, *, with_clerk_skill: bool) -> Path:
    """A defender dir the run can actually start against, with the clerk's prompt present or
    absent and NOTHING ELSE different between the two arms.

    Copied from the shipped tree rather than stubbed: an empty directory aborts the run for a
    dozen unrelated reasons, and a test that accepted any abort would go green on every one of
    them."""
    import shutil

    tree = tmp_path / ("with-clerk" if with_clerk_skill else "without-clerk")
    tree.mkdir()
    shutil.copytree(DEFENDER / "skills", tree / "skills")
    shutil.copytree(DEFENDER / "scripts", tree / "scripts")
    shutil.copy(DEFENDER / "SKILL.md", tree / "SKILL.md")
    clerk_dir = tree / "skills" / "clerk"
    if with_clerk_skill:
        clerk_dir.mkdir(parents=True, exist_ok=True)
        (clerk_dir / "SKILL.md").write_text(
            "# clerk\n\nCompile MAIN's prose into invlang rows. Unknown means `??`.\n",
            encoding="utf-8")
    elif clerk_dir.exists():
        shutil.rmtree(clerk_dir)
    return tree


def _start_a_run(run_dir: Path, defender_dir: Path):
    """One `run_investigation` against a chosen defender dir, with the model and the review
    bundle injected so the ONLY thing that can differ between the two arms is the clerk's
    prompt asset."""
    import asyncio

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.runtime.providers import BuiltModel
    from defender.tests import _review_bundle
    from defender.tests.e2e._replay_harness import Turn

    built = BuiltModel(FunctionModel(C.MainWithReceipts([Turn(text="Holding here.")])), None)
    with override_allow_model_requests(False):
        return asyncio.run(C.mod("runtime.driver").run_investigation(
            alert_path=run_dir / "alert.json", run_dir=run_dir, run_id=C.RUN_ID,
            defender_dir=defender_dir,
            make_model=lambda name, effort: built,
            review_stages=_review_bundle.bundle(
                composer=_review_bundle.composer_reply("holds")),
        ))


def test_996_a_missing_clerk_prompt_asset_aborts_at_startup(tmp_path: Path) -> None:
    """A missing clerk prompt asset aborts at composition-root construction, and the run-dir
    artifacts already opened are closed cleanly on the way out.

    Today the clerk's caller is built BELOW the request logger, so an unreadable asset fails
    after the log is open AND permanently registered in the process — and a second
    `run_investigation` could then never reopen that path for the rest of the process. The live
    review bundle already carries its own handler for exactly this reason, and its comment says
    why the handler has to be the clerk's own rather than the store-setup one: a missing prompt
    asset is not a store fault and must not be reported as one.

    THE CONTROL IS THE WHOLE TEST. The same run against the same tree WITH the prompt present
    completes, so the abort is attributable to the asset rather than to any of the dozen other
    reasons a hand-built defender dir fails to start. And the leak assertion is the second
    half: after the abort, the wire log can be opened again."""
    ok_run = C.new_run_dir(tmp_path, name="control-run")
    summary = _start_a_run(ok_run, _defender_tree(tmp_path, with_clerk_skill=True))
    assert summary.get("truncated_by") != "store", summary

    run_dir = C.new_run_dir(tmp_path, name="missing-run")
    # The BREADTH below is the demand, hence the suppression: the missing-prompt-asset
    # demand says the run ABORTS, not which class it aborts with, and a startup path can
    # leave through `SystemExit` as readily as through an ordinary exception — narrowing
    # here would let the arm the demand is about walk straight past the assertion. The two
    # asserts that follow carry what a `match=` would, and carry it with a real message.
    with pytest.raises(BaseException) as excinfo:  # noqa: PT011
        _start_a_run(run_dir, _defender_tree(tmp_path, with_clerk_skill=False))
    assert not isinstance(excinfo.value, KeyboardInterrupt)
    assert "clerk" in str(excinfo.value).lower(), (
        f"the run aborted for something other than the clerk's prompt asset: {excinfo.value!r}"
    )

    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    logger.close()


# ---------------------------------------------------------------------------------------
# the price and the alias (D8, O5)
# ---------------------------------------------------------------------------------------


def test_996_glm_5p3_flash_prices_under_its_own_key() -> None:
    """The clerk's model prices under its OWN row, not through the generic glm branch.

    At this base the provider model id falls through `"glm" in m` to the 5.2 rate, so every
    clerk call in the experiment was billed at roughly ten times its price. The branch must sit
    AHEAD of the generic one — order is the whole mechanism, the same way the K3 branch has to
    precede the generic kimi branch — so the discriminator is the COST, not the presence of a
    row: a row added behind the generic branch is unreachable and prices nothing."""
    assert C.CLERK_PRICE_KEY in pricing.PRICING, "the clerk's price row is not in the table"
    assert pricing.model_key(C.CLERK_PROVIDER_MODEL) == C.CLERK_PRICE_KEY, (
        "the clerk's model still keys to the generic glm row — the new branch is behind the "
        "generic one and is unreachable"
    )
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000}
    assert pricing.usage_cost(C.CLERK_PROVIDER_MODEL, usage) != pricing.usage_cost(
        "accounts/fireworks/models/glm-5p2", usage
    ), "the clerk's model bills at the 5.2 rate"


def test_996_glm_5p3_flash_alias_resolves_to_a_provider_model() -> None:
    """The shipped clerk model id resolves through the ordinary provider table to a real
    Fireworks model, and it is one of the ids an operator may select.

    The alias table is what `provider_for` consults first, and `selectable_aliases` derives the
    operator-facing list from it — so an alias added to one and not the other tells an operator
    a supported model looks unsupported."""
    providers = C.mod("runtime.providers")
    assert providers.FIREWORKS.aliases.get(C.DEFAULT_CLERK_MODEL) == C.CLERK_PROVIDER_MODEL
    assert providers.provider_for(C.DEFAULT_CLERK_MODEL) is providers.FIREWORKS
    assert C.DEFAULT_CLERK_MODEL in providers.selectable_aliases()


# ---------------------------------------------------------------------------------------
# the prompt asset (mechanism 4, F18)
# ---------------------------------------------------------------------------------------


def test_996_the_shipped_clerk_skill_states_the_row_contract(tmp_path: Path) -> None:
    """The shipped clerk prompt states the row contract, and its BYTES are what reach the
    clerk.

    Four things the port adds to the ported prompt are checked because each is a decision the
    design records: unknown means the placeholder rather than an invention (D1); a repair-mode
    section, because the clerk now answers repair pairs (D14); a held-block section, because a
    stopped call re-hands its block (D7); and `## REPORT` as the header that compiles a
    conclude (S6). Gather summaries are REMOVED (D5) — the throwaway inlined them.

    The wiring is the load-bearing half: a shipped file nothing reads is a file, not a prompt,
    so a distinctive line of it is asserted to appear in the turn the clerk was handed."""
    assert CLERK_SKILL.is_file(), f"{CLERK_SKILL} does not exist"
    body = CLERK_SKILL.read_text(encoding="utf-8")
    for required in ("??", "fix_row", "## REPORT", ":T conclude"):
        assert required in body, f"the shipped clerk prompt never mentions {required!r}"
    for banned in ("gather_summaries", "gather summaries"):
        assert banned not in body, (
            f"the shipped clerk prompt still mentions {banned!r}; D5 removes the summaries "
            f"language the throwaway carried"
        )

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)
    probe = next(
        (ln for ln in body.splitlines() if ln.startswith("#") and len(ln) > 12), None)
    assert probe is not None, "the shipped clerk prompt has no heading to probe the wiring with"
    assert probe in clerk.only(), (
        "the shipped clerk prompt's own bytes are not in the turn the clerk was handed"
    )


def test_996_the_clerk_skill_enters_the_audited_model_read_surface(tmp_path: Path) -> None:
    """The clerk's prompt joins the audited model-read surface, and the AUDIT's answer changes
    because of it.

    The surface census is read off the tree fresh on every call, so the demand is not "a
    constant was edited" but "the file sits where the sweep reaches" — and enumerating the
    census would certify only that the path is listed, never that anything looks at it. So the
    audit itself is driven: a clerk prompt that advertises a verb the clerk's own deny-all
    grant withholds must be REPORTED, by path.

    Driven over a copied tree rather than the real one, because the real clerk prompt is
    supposed to be clean — and a clean tree cannot tell "audited" from "not reached".

    THROUGH `shipped_grants()`, the mapping the real-tree audit is handed, never a mapping
    built here. A hand-built `{gather: …, clerk: …}` goes green over a path production does
    not take: `shipped_grants()` used to carry only the roles that ship a generated ROSTER, so
    the clerk — which ships a prompt and no roster — had no key, and `_grant_for_surface` fell
    through to the gather default. The most restricted prompt in the tree was being scored
    against the most permissive grant, and a test that supplies the missing key itself cannot
    see that."""
    verb_roster = C.mod("runtime.verb_roster")
    surfaces = verb_roster.model_read_surfaces(DEFENDER)
    assert surfaces, "the model-read surface census is empty — every audit over it is vacuous"
    assert CLERK_SKILL in surfaces, (
        f"{CLERK_SKILL} is outside the audited model-read surface, so nothing checks the "
        f"prompt the clerk is actually given"
    )

    import shutil

    tree = tmp_path / "defender-copy"
    shutil.copytree(DEFENDER / "skills", tree / "skills")
    shutil.copytree(DEFENDER / "scripts" / "adapters", tree / "scripts" / "adapters")
    from defender.tests._verb_authorization_632 import shipped_grants

    grants = shipped_grants()
    assert grants.get("clerk") == _clerk_def().verb_grant, (
        "the mapping the real audit is handed carries no clerk grant, so the clerk's prompt "
        f"is scored against the default role's: {sorted(grants)}"
    )
    clean = verb_roster.audit_read_surfaces(tree, grants)
    planted = tree / "skills" / "clerk" / "SKILL.md"
    planted.write_text(
        planted.read_text(encoding="utf-8") + "\n\nCall `elastic.query` yourself.\n",
        encoding="utf-8")
    dirty = verb_roster.audit_read_surfaces(tree, grants)
    assert len(dirty) > len(clean), (
        "the audit did not notice a withheld verb advertised in the clerk's own prompt, so "
        "the prompt is listed in the census but not actually examined"
    )
    assert any("clerk" in hit for hit in dirty), dirty


def _experiment_imports(root: Path) -> list[str]:
    """Every import line under `root` that reaches `experiments/`."""
    hits: list[str] = []
    for path in sorted(root.rglob("*.py")):
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")) and "experiments" in stripped:
                hits.append(f"{path}: {stripped}")
    return hits


def test_996_the_runtime_does_not_import_experiments(tmp_path: Path) -> None:
    """NEGATIVE: nothing under the shipped runtime imports from `experiments/`, and the two
    ported prompts are read from the shipped tree rather than from the directory they came
    from.

    Both prompts are PORTED — MAIN's from the prose-only variant, the clerk's from that
    variant's clerk prompt — so the shortcut the port creates is a runtime that reads its
    prompt out of the experiment directory. That directory is not shipped, is not on the
    installed path, and holds only gitignored logs on this branch.

    POSITIVE CONTROL on the observation channel: the same scan over a planted tree that DOES
    carry such an import reports it, so a clean result above is a clean runtime rather than a
    scan that never matches anything."""
    assert _experiment_imports(DEFENDER / "runtime") == [], (
        "the runtime imports from experiments/"
    )
    assert "experiments" not in CLERK_SKILL.read_text(encoding="utf-8"), (
        "the shipped clerk prompt points the reader back at the experiment directory"
    )

    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "x.py").write_text(
        "from experiments.invlang_clerk_986.variants import CLERK\n", encoding="utf-8")
    assert _experiment_imports(planted), (
        "the scan does not find an experiments import even where one exists, so the clean "
        "result above says nothing"
    )


# ---------------------------------------------------------------------------------------
# the module graph and the trace path (#1004 review)
# ---------------------------------------------------------------------------------------


def test_996_the_clerk_module_imports_on_its_own() -> None:
    """`import defender.runtime.clerk` works as the FIRST defender import of a process.

    The caller needs `AgentDeps`, which lives under `runtime.tools`, and `record` needs the
    round budget, the pending cap, the malformed-reply class and the trace path, which live
    with the caller — a cycle. It stayed invisible because every entry point in the tree
    (`defender.agents`, this suite) happens to reach `runtime.tools` first, so the cycle
    resolves in that order and raises in the other: a script whose first defender import is the
    clerk breaks on import order alone, and `experiments/invlang-clerk-986/clerk_dryrun.py` is
    one such script. Driven in a SUBPROCESS because an import order cannot be re-tested inside
    a process that has already imported the tree."""
    import subprocess
    import sys

    probe = (
        "import defender.runtime.clerk as c; "
        "assert c.CLERK_ROUND_BUDGET and c.PENDING_CAP and c.ClerkMalformedReply"
    )
    done = subprocess.run(  # noqa: S603 — this interpreter, a literal probe, no shell
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False,
    )
    assert done.returncode == 0, (
        "importing `defender.runtime.clerk` first fails — the clerk and the tools package "
        f"close an import cycle:\n{done.stderr}"
    )


def test_996_the_trace_writer_and_the_resume_reader_share_one_path(tmp_path: Path) -> None:
    """The `clerk_trace.jsonl` WRITER and the resume READER derive the path from one helper.

    `record_n` is seeded off the row count so a resumed process cannot re-issue a trace
    identity a prior pass already used (HD-2's one exception). A reader spelling the path
    independently of the writer finds no file the day the wire-log component moves — seeding
    ZERO, silently, on exactly the resume the seeding exists for.

    Asserted on the OWNERSHIP, because agreement today is what a second spelling also has: the
    two sides referenced `wire_logs/clerk_trace.jsonl` through two different expressions, which
    is a filename with two owners and reads correct until one of them moves. The end-to-end
    count is the companion half — the rows a real run wrote through the writer are the rows the
    reader counts."""
    writer = C.sym("runtime.tools._clerk", "_append_trace")
    reader = C.sym("runtime.clerk", "_highest_clerk_trace_n")
    for fn in (writer, reader):
        assert "clerk_trace_path" in fn.__code__.co_names, (
            f"`{fn.__name__}` builds the trace path itself instead of asking the one helper "
            "that owns the filename — the writer and the resume reader would then move apart"
        )

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    C.record_run(tmp_path, run_dir=run_dir, clerk=C.ScriptedClerk(C.clerk_reply("")),
                 prose=[C.PROSE, C.SECOND_PROSE])

    written = C.trace_rows(run_dir)
    assert written, "the run wrote no trace rows, so the reader has nothing to disagree with"
    assert reader(run_dir) == max(int(r["n"]) for r in written), (
        f"the resume reader answered {reader(run_dir)} where the writer's highest trace `n` "
        f"is {max(int(r['n']) for r in written)}"
    )


def test_996_the_resume_seeds_from_the_highest_identity_not_the_count(tmp_path: Path) -> None:
    """Both identity counters resume from the HIGHEST value already issued, never from a count.

    `ClerkCaller.call` spends its id before it awaits and logs only on success, and
    `_append_trace` is best effort — so both streams can carry gaps. With `clerk:1` and
    `clerk:3` on disk a count seeds 2 and the resumed process issues `clerk:3` a second time,
    which is the exact collision HD-2's seeding exists to prevent and it fails silently: two
    calls become one identity and the run's clerk spend stops being attributable per call.

    Driven on a wire log and a trace written with a hole in each, because a gap is the only
    input on which a count and a maximum differ."""
    run_dir = C.new_run_dir(tmp_path)
    wire = RunPaths(run_dir).wire_log
    wire.parent.mkdir(parents=True, exist_ok=True)
    wire.write_text(
        '{"agent_id": "clerk:1"}\n{"agent_id": "main"}\n{"agent_id": "clerk:3"}\n',
        encoding="utf-8")
    C.trace_path(run_dir).write_text(
        '{"n": 1}\n{"n": 4}\n', encoding="utf-8")

    assert C.sym("runtime.clerk", "_highest_clerk_wire_call")(run_dir) == 3, (
        "the wire-log seed counted rows instead of reading the highest id — the next call "
        "re-issues `clerk:3`"
    )
    assert C.sym("runtime.clerk", "_highest_clerk_trace_n")(run_dir) == 4, (
        "the trace seed counted rows instead of reading the highest `n`"
    )

    caller = C.sym("runtime.clerk", "make_clerk_caller")(
        run_dir, C.DEFENDER, logger=None, raw=lambda prompt: prompt)
    assert (caller.n, caller.record_n) == (3, 4), (
        f"the caller resumed at {(caller.n, caller.record_n)} — its next call collides with "
        "an identity already on disk"
    )


def test_996_the_clerk_ceiling_releases_the_queue_it_can_no_longer_drain(
    tmp_path: Path,
) -> None:
    """Past the clerk ceiling, a non-empty queue is RELEASED and named — never held against a
    close that can no longer be earned.

    `close_investigation` refuses a MODEL close while `pending` is non-empty and tells MAIN to
    call `record` again so it compiles. Past the ceiling every `record` makes no clerk call at
    all, so that step provably cannot happen: held, the queue refuses every close for the rest
    of the run and the framework force-closes `unresolved`, discarding the disposition the run
    reached. The entries' prose is on the document, so what is lost is the compilation, and the
    receipt says which.

    Driven at a ceiling of one, with a faulted first call to put something in the queue."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)

    class _FaultThenSilent:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            raise ConnectionError("scripted clerk transport fault")

    clerk = _FaultThenSilent()
    _, main, _ = C.record_run(
        tmp_path, run_dir=run_dir, clerk=clerk,
        limits={**DEFAULT_LIMITS, "max_tool_calls": 1},
        prose=[C.PROSE, C.SECOND_PROSE])

    metered = main.receipts[-1]
    assert "ceiling" in metered.lower(), (
        f"the last call did not take the metered arm: {C.outcome_lines(metered)}"
    )
    assert "will not be compiled" in metered, (
        f"the queue was held past the ceiling with no way to drain it: {metered!r}"
    )

    close_tool = C.mod("runtime.close_tool")
    caller = C.sym("runtime.clerk", "ClerkCaller")(
        run_dir=run_dir, defender_dir=C.DEFENDER, logger=None, instructions="")
    close_tool._refuse_if_pending_prose(caller)  # an emptied queue refuses nothing
