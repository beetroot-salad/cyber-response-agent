"""#776 — four low-severity findings from the codebase security scan.

Each section pins the *correction*, and each carries the positive control that keeps the
correction from being satisfied by a check that simply denies everything.

The four are independent; they share a file because none is large enough to own one, and
the roll-up issue is the record they trace back to.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender._paths import DefenderPaths  # noqa: E402
from defender.agents import ACTOR_DEF, GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.learning.author.verify_forward import env as fwd_env  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import RunScope, bind  # noqa: E402
from defender.runtime.box import BoxResult  # noqa: E402
from defender.runtime.driver import _gather_instructions  # noqa: E402
from defender.runtime.tools import _tool_bash  # noqa: E402
from defender.scripts.lessons._lessons_common import rel_to_repo  # noqa: E402

from defender.tests._curator_691_harness import (  # noqa: E402
    corpus as corpus_dir,
    curator_deps,
    make_worktree,
    pending_run_dir,
    rel,
    write_file,
)
from defender.tests._frames680 import Box, DEFENDER, FRAME_RE  # noqa: E402

RETRIEVE = config.LESSONS_ENV_RETRIEVE_SCRIPT
_VENV_PY = DEFENDER / ".venv" / "bin" / "python3"
_PY = str(_VENV_PY) if _VENV_PY.is_file() else sys.executable


def _lesson(corpus: Path, name: str, *, rule: str = "rule-1") -> Path:
    corpus.mkdir(parents=True, exist_ok=True)
    path = corpus / f"{name}.md"
    path.write_text(
        f"---\nsubject: {name}\nalert_rule_ids: [{rule}]\nstatus: live\n"
        f"relevance_criteria: about {name}\n---\n\nbody\n",
        encoding="utf-8",
    )
    return path


# =========================================================================== #
# 1. The actor's pinned-script grant admits arbitrary trailing argv, so the
#    script itself is the only containment there is.
# =========================================================================== #

def _actor_deps(tmp_path: Path):
    defender_dir = tmp_path / "tree" / "defender"
    (defender_dir / "lessons-environment").mkdir(parents=True)
    run = tmp_path / "run"
    run.mkdir(parents=True)
    return bind(
        ACTOR_DEF, run, defender_dir=defender_dir,
        scope=RunScope(
            read_confine=((defender_dir / "lessons-environment"),), scripts=(RETRIEVE,),
        ),
    )


def _retrieve(corpus: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_PY, str(RETRIEVE), "--corpus", str(corpus), *args],
        capture_output=True, text=True,
    )


def test_the_gate_still_lets_the_actor_name_any_corpus_it_likes(tmp_path):
    """The premise the fix rests on, pinned so it cannot rot into a false sense of safety.

    The actor's grant is `pins_path=True` with no operand scope, and `python3` opens
    nothing, so the bash gate short-circuits before it ever looks at the arguments. That
    argv-blindness is INTENDED (`docs/runtime-gates.md` names the two exemptions) — which
    is exactly why the containment has to live inside the pinned script. If this ever
    starts denying, the gate grew an operand check and the script-side check below stopped
    being the only thing standing between the actor and the defender's playbook."""
    deps = _actor_deps(tmp_path)
    for tail in ("--corpus defender/lessons", "--corpus /etc", "--include-stale"):
        decision = permission.decide_bash(
            f"python3 {RETRIEVE} {tail}", policy=deps.policy,
            run_dir=deps.run_dir, defender_dir=deps.defender_dir,
            cwd_anchor=deps.cwd_anchor,
        )
        assert decision.allow, tail


def test_env_retrieve_refuses_to_walk_a_corpus_that_is_not_the_environment_one(tmp_path):
    """The correction: `--corpus` relocates the environment corpus, it does not select a
    different one. The malicious actor is the one agent the gray-box design blinds to the
    defender's playbook, and `decide_read` denies it `defender/lessons` — this closed the
    route around that denial."""
    playbook = tmp_path / "defender" / "lessons"
    _lesson(playbook, "how-the-defender-catches-you")
    proc = _retrieve(playbook)
    assert proc.returncode == 2
    assert "how-the-defender-catches-you" not in proc.stdout
    assert "lessons-environment" in proc.stderr


def test_a_traversal_cannot_dress_another_corpus_up_in_the_right_name(tmp_path):
    """The name is checked AFTER `resolve()`, so `<env corpus>/../lessons` is the corpus it
    resolves to, not the one it is spelled as."""
    root = tmp_path / "defender"
    _lesson(root / "lessons", "playbook")
    proc = _retrieve(root / "lessons-environment" / ".." / "lessons")
    assert proc.returncode == 2
    assert "playbook" not in proc.stdout


def test_a_relocated_environment_corpus_still_walks(tmp_path):
    """Positive control, and the reason the rule is the leaf name rather than one absolute
    path: the forward-check points this walk at a worktree's copy and the tests point it at
    a fixture. Both change the root; neither changes the corpus."""
    corpus = tmp_path / "worktree" / "defender" / "lessons-environment"
    _lesson(corpus, "vpn-egress")
    proc = _retrieve(corpus, "--alert-rule-ids", "rule-1")
    assert proc.returncode == 0
    assert "vpn-egress" in proc.stdout


# =========================================================================== #
# 2. Gather's one reduce step delivered attacker-chosen payloads unframed.
# =========================================================================== #

def _bash_scene(tmp_path: Path, definition, payload: bytes = b"reduced\n"):
    run = tmp_path / "run"
    defender_dir = tmp_path / "tree" / "defender"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    defender_dir.mkdir(parents=True)
    (run / "gather_raw" / "l-001" / "1.json").write_text("{}", encoding="utf-8")
    (run / "alert.json").write_text("{}", encoding="utf-8")
    (run / "report.md").write_text("trusted\n", encoding="utf-8")
    deps = bind(
        definition, run, defender_dir=defender_dir, box=Box(BoxResult(0, payload, b"")),
    )
    return deps, run


def _framed(out: str, deps) -> bool:
    m = FRAME_RE.search(out)
    return bool(m) and m.group("salt") == deps.salt and m.group("tag") == "untrusted"


def test_gathers_reduce_step_returns_the_payload_inside_the_runs_frame(tmp_path):
    """The channel the finding is about: `cat <payload> | defender-sql` is the one route
    that hands gather full attacker-chosen field values, and it is the route gather's own
    prompt tells it to use. It arrived bare while the same bytes through `read_file`, and
    the `query` tool's own return, arrived framed."""
    deps, run = _bash_scene(tmp_path, GATHER_DEF)
    payload = run / "gather_raw" / "l-001" / "1.json"
    out = _tool_bash(deps, f"cat {payload} | defender-sql 'SELECT count(*) FROM data'")
    assert _framed(out, deps)


def test_the_frame_follows_the_data_not_the_role(tmp_path):
    """Main's exposure was narrower but not empty: bound `raw=False` it cannot reach a
    payload at all, yet `cat alert.json` was unframed here while `read_file('alert.json')`
    was framed — the same bytes, two answers. Both roles now agree with `read_file`."""
    for definition in (GATHER_DEF, MAIN_DEF):
        deps, run = _bash_scene(tmp_path / definition.role.name, definition)
        assert _framed(_tool_bash(deps, f"cat {run / 'alert.json'}"), deps)


def test_trusted_content_on_the_same_lane_is_not_framed(tmp_path):
    """Positive control against a check that just wraps everything: a frame around content
    gather is meant to trust teaches it to distrust its own corpus, and a frame that is
    always present carries no signal. Main's own report.md stays bare."""
    for definition in (GATHER_DEF, MAIN_DEF):
        deps, run = _bash_scene(tmp_path / definition.role.name, definition)
        assert not _framed(_tool_bash(deps, f"cat {run / 'report.md'}"), deps)


def test_main_still_cannot_reach_a_raw_payload_at_all(tmp_path):
    """Framing is the trust boundary, not the containment one — pinned so a future reader
    does not mistake the new frame for main having gained raw access."""
    deps, run = _bash_scene(tmp_path, MAIN_DEF)
    with pytest.raises(ModelRetry):
        _tool_bash(deps, f"cat {run / 'gather_raw' / 'l-001' / '1.json'}")


def test_gathers_prompt_carries_the_untrusted_data_contract(tmp_path):
    """The frame is only a control if its reader has been told what it means. Gather's
    entire system prompt is `skills/gather/SKILL.md`, and it carried no contract at all —
    main's lives in `defender/SKILL.md`, which gather never sees. A frame with no contract
    is noise to its only reader."""
    prompt = _gather_instructions(DEFENDER)
    assert "<run-{salt}-" in prompt
    lowered = prompt.lower()
    assert "untrusted" in lowered
    assert "injection" in lowered
    assert "never an instruction" in lowered or "never an instruction to follow" in lowered


# =========================================================================== #
# 3. The env forward-check matched on basename.
# =========================================================================== #

def test_a_basename_collision_no_longer_certifies_a_lesson(tmp_path):
    """The defect: `lesson_returned` answered yes if ANY returned path merely shared the
    target's basename. A lesson at `<corpus>/sub/x.md` is invisible to the corpus walk
    (`glob('*.md')`) forever — and to the manifest, and to the idempotency scan — yet a
    pre-existing top-level `x.md` voted it retrievability-verified."""
    repo = tmp_path / "repo"
    corpus = repo / "defender" / "lessons-environment"
    _lesson(corpus, "vpn-egress")
    nested = corpus / "sub" / "vpn-egress.md"
    nested.parent.mkdir(parents=True)
    nested.write_text("---\nsubject: x\n---\nbody\n", encoding="utf-8")

    returned = [str(corpus / "vpn-egress.md")]
    assert not fwd_env.lesson_returned(nested, returned, corpus_dir=corpus)


def test_a_lesson_in_a_different_corpus_is_not_this_corpuss_lesson(tmp_path):
    """Same shape across corpora rather than across depth — identity is the resolved path,
    so a same-named lesson in a sibling corpus is not a hit either."""
    repo = tmp_path / "repo"
    env_corpus = repo / "defender" / "lessons-environment"
    other = _lesson(repo / "defender" / "lessons-actor", "vpn-egress")
    hit = _lesson(env_corpus, "vpn-egress")
    assert not fwd_env.lesson_returned(other, [str(hit)], corpus_dir=env_corpus)


def test_the_real_lesson_is_a_hit(tmp_path):
    """Positive control: identity must still LAND, or every lesson reverts."""
    corpus = tmp_path / "repo" / "defender" / "lessons-environment"
    lesson = _lesson(corpus, "vpn-egress")
    assert fwd_env.lesson_returned(lesson, [str(lesson)], corpus_dir=corpus)


def test_the_batch_worktree_is_nested_under_the_checkout_the_script_reads_from(tmp_path):
    """The geometry that made the spelling ambiguous, pinned because the whole anchor rests
    on it. `worktree_base` is `<repo>/.worktrees`, so a curator's corpus is INSIDE the
    checkout the retrieval script lives in — which means the script's `relative_to` succeeds
    and it prints a `.worktrees/…` spelling, not the absolute path a separate tree would get.
    If worktrees ever move outside the repo this test fails and the anchor below is moot."""
    assert DefenderPaths(tmp_path / "repo").worktree_base.parent == tmp_path / "repo"
    assert RETRIEVE.resolve().parents[3] == fwd_env.RETRIEVE_REPO_ROOT
    assert (fwd_env.RETRIEVE_REPO_ROOT / "defender").is_dir()


@pytest.mark.parametrize("where", ["under the script's checkout", "outside it"])
def test_a_returned_hit_resolves_against_the_root_the_script_spelled_it_against(where):
    """The spelling regression. The curator's `repo_root` is its WORKTREE; the retrieval
    script's is the MAIN checkout the worktree hangs under — two different directories, and
    the `.worktrees/…` line is meaningful against the second one only. Anchoring at the
    curator's root resolved every hit to a path that does not exist, so every environment
    lesson forward-checked BAD and got reverted.

    Both geometries round-trip through the one anchor: pure path arithmetic on either side,
    so this pins the contract without needing either tree to exist."""
    root = (
        fwd_env.RETRIEVE_REPO_ROOT if where == "under the script's checkout"
        else Path("/nowhere/other-checkout")
    )
    lesson = root / ".worktrees" / "lessons-abc" / "defender" / "lessons-environment" / "l.md"
    printed = rel_to_repo(lesson, fwd_env.RETRIEVE_REPO_ROOT)
    assert fwd_env.absolute_hit(printed) == str(lesson)
    assert fwd_env.lesson_returned(
        lesson, [fwd_env.absolute_hit(printed)], corpus_dir=lesson.parent
    )


def test_a_lesson_retrieval_did_not_return_is_still_a_miss(tmp_path):
    """The check must stay able to fail — a BAD verdict is what reverts an unretrievable
    lesson, so an identity comparison that accidentally matched everything would be worse
    than the basename one it replaces."""
    corpus = tmp_path / "repo" / "defender" / "lessons-environment"
    lesson = _lesson(corpus, "vpn-egress")
    other = _lesson(corpus, "sudo-cadence")
    assert not fwd_env.lesson_returned(lesson, [str(other)], corpus_dir=corpus)


@pytest.mark.parametrize("invisible", ["sub/buried.md", "_buried.md"])
def test_the_curator_can_no_longer_write_a_lesson_the_walk_cannot_see(tmp_path, invisible):
    """The other half of the same defect, closed at the source: the write allow admitted
    `<corpus>/SEG(/SEG)*.md` while every corpus reader goes through `iter_lesson_paths` —
    `glob('*.md')`, flat, MINUS any `_`-prefixed name (the corpus `_TEMPLATE.md`). Depth and
    a leading underscore are the same hole in two spellings, so both are refused. A curator
    can still author into its corpus; it can no longer author into a hole."""
    wt, run = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = curator_deps(wt, run, "lessons")
    (corpus_dir(wt, "lessons") / "sub").mkdir(parents=True, exist_ok=True)
    with pytest.raises(ModelRetry):
        write_file(deps, rel("lessons", invisible), "body\n")
    write_file(deps, rel("lessons", "visible.md"), "body\n")  # positive control
    assert (corpus_dir(wt, "lessons") / "visible.md").is_file()
