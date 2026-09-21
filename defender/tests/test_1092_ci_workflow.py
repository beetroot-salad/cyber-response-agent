"""#1092 — CI builds the image before it syncs or boxes (M4 amended, O3), and the operator's
README names the command the fault names (M5, O4).

Located by what the steps RUN rather than by name, with a count guard, for the reason
`test_771_alias_ban.py`'s census and `test_ci_gvisor_bounds_937.py` state: a selector that
silently matches nothing is the vacuous pass this idiom exists to avoid. The 937 step-sum
rule (strict `<` per job) is the existing observer the new 4-minute step nests under (d37).
"""
from __future__ import annotations

import re

import yaml

from defender.tests._spec1092 import BUILD_COMMAND_TAIL, CI_WORKFLOW, README_RUNTIME

BUILD_STEP_RUN = f"python3 {BUILD_COMMAND_TAIL}"
BOX_JOBS = ("test", "box-native", "box-dood")
OTHER_JOBS = ("lint", "code-smells")
STOCK_PREPULL = "docker pull python:3.11-slim"


def _jobs() -> dict:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _steps(job: dict) -> list[dict]:
    return list(job.get("steps", []))


def _run_text(step: dict) -> str:
    return str(step.get("run", "") or "")


def _build_step_index(steps: list[dict]) -> int:
    hits = [i for i, s in enumerate(steps) if _run_text(s).strip() == BUILD_STEP_RUN]
    assert len(hits) == 1, f"expected exactly one `{BUILD_STEP_RUN}` step, got {hits}"
    return hits[0]


def _checkout_index(steps: list[dict]) -> int:
    hits = [i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/checkout")]
    assert len(hits) == 1, hits
    return hits[0]


def _sync_lines(step: dict) -> list[str]:
    return [ln.strip() for ln in _run_text(step).splitlines() if re.search(r"\buv sync\b", ln)]


# ---- d36 -------------------------------------------------------------------------------------
def test_each_box_starting_job_builds_the_image_in_a_four_minute_step_immediately_after_checkout():
    """In `ci.yml` each of `test`, `box-native` and `box-dood` has a step whose `run` is
    `python3 defender/scripts/box_image.py build`, carrying `timeout-minutes: 4`, run at the
    checkout root (no `working-directory`), placed immediately after the `actions/checkout`
    step — before `Install uv` and the `uv sync` step in `test`/`box-native`, and before the
    DooD step in `box-dood`; the build precedes the gVisor step (SETTLED #48).

    # rejected: the issue body's "Build + publish in CI" — each job builds locally, nothing is
    # published (D2). `test_budget_seams_631` cannot see the step (it selects steps by
    # `pytest tests/`), and the 937 per-command census is over runsc steps only — the step
    # bound alone names a stall here. GHA layer cache is an option not taken; C15 sizes the
    # bound from the first run."""
    jobs = _jobs()
    for name in BOX_JOBS:
        steps = _steps(jobs[name])
        at = _build_step_index(steps)
        step = steps[at]
        assert int(step.get("timeout-minutes", 0)) == 4, (name, step)
        assert "working-directory" not in step, (name, step)
        assert at == _checkout_index(steps) + 1, (name, at)
        later = steps[at + 1:]
        assert any("runsc install" in _run_text(s) for s in later), name
        if name == "box-dood":
            assert any(".dood-inner.sh" in _run_text(s) for s in later), name
        else:
            assert any(_sync_lines(s) for s in later), name
            assert any(str(s.get("name", "")) == "Install uv" for s in later), name


# ---- d38 -------------------------------------------------------------------------------------
def test_box_dood_builds_on_the_runner_outside_the_inner_script_and_still_prepulls_the_stock_image():
    """`box-dood`'s build step is a runner step and not a line inside `.dood-inner.sh` (the
    inner script names no `box_image.py`), and its `docker pull python:3.11-slim` step — which
    warms the OUTER pytest-runner container, not a box — is still present.

    # rejected: the DooD job's OUTER `python:3.11-slim` container is the pytest runner, not a
    # box; it keeps the stock image and its pre-pull is untouched."""
    steps = _steps(_jobs()["box-dood"])
    _build_step_index(steps)
    inner = [s for s in steps if ".dood-inner.sh" in _run_text(s)]
    assert len(inner) == 1, inner
    assert "box_image.py" not in _run_text(inner[0])
    assert any(STOCK_PREPULL in _run_text(s) for s in steps), "box-dood lost its pre-pull"


# ---- d39 -------------------------------------------------------------------------------------
def test_the_three_box_starting_jobs_sync_with_locked_and_the_two_others_keep_their_plain_sync():
    """The `uv sync` lines of `test`, `box-native` and `box-dood`'s inner script carry
    `--locked`, and `lint`'s and `code-smells`'s syncs do not.

    # rejected: `lint`/`code-smells` keep their plain syncs because they start no box (M4
    # amended)."""
    jobs = _jobs()
    for name in BOX_JOBS:
        lines = [ln for s in _steps(jobs[name]) for ln in _sync_lines(s)]
        assert lines, f"{name} has no uv sync line"
        for ln in lines:
            assert "--locked" in ln, (name, ln)
    for name in OTHER_JOBS:
        lines = [ln for s in _steps(jobs[name]) for ln in _sync_lines(s)]
        assert lines, f"{name} has no uv sync line"
        for ln in lines:
            assert "--locked" not in ln, (name, ln)


# ---- d40 (negative; positive control: box-dood's pre-pull stays, d38) --------------------------
def test_test_and_box_native_no_longer_prepull_the_stock_image():
    """Neither `test` nor `box-native` has a step running `docker pull python:3.11-slim` any
    more (the build step supplies the only image those jobs box with), while `box-dood`'s
    pre-pull of the outer runner container is still there."""
    jobs = _jobs()
    for name in ("test", "box-native"):
        pulls = [s for s in _steps(jobs[name]) if STOCK_PREPULL in _run_text(s)]
        assert pulls == [], (name, pulls)
    assert any(STOCK_PREPULL in _run_text(s) for s in _steps(jobs["box-dood"]))


# ---- d41 (negative; positive control: the build steps exist, d36) ----------------------------------
def test_the_workflow_pushes_no_image_logs_into_no_registry_and_commits_nothing():
    """The workflow contains no `docker push`, no `docker login`, no registry-login action,
    no GHCR reference and no step that commits or pushes to the repository — while its three
    box-starting jobs each carry the local build step."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    for forbidden in ("docker push", "docker login", "login-action", "ghcr.io", "git push",
                      "git commit", "docker/build-push-action"):
        assert forbidden not in text, forbidden
    jobs = _jobs()
    for name in BOX_JOBS:
        _build_step_index(_steps(jobs[name]))


# ---- d45 -------------------------------------------------------------------------------------
def test_the_runtime_readme_documents_the_build_command_the_fault_names_relative_to_the_tree():
    """`.devcontainer/README.runtime.md` documents `python3 defender/scripts/box_image.py
    build` — the same script path, relative to the tree, that the fault remedy names
    absolutely — and says it builds over the socket onto the host daemon with no pull."""
    text = README_RUNTIME.read_text(encoding="utf-8")
    assert BUILD_STEP_RUN in text, "the README does not document the build command"
    window = text[max(0, text.index(BUILD_STEP_RUN) - 1500): text.index(BUILD_STEP_RUN) + 1500]
    assert "socket" in window.lower(), "the README does not say the build goes over the socket"
    assert "host" in window.lower(), "the README does not name the host daemon"
    assert re.search(r"\b(no|never|not|without)\b[^.\n]{0,40}\bpull", window, re.I), (
        "the README does not say no pull is involved"
    )
