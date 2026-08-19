"""#937 — the gVisor install stays bounded, and the bounds stay NESTED.

Run 32278695386 sat on `Install gVisor (runsc) for the box suite` for ~15 minutes and would
have run to GitHub's 6-hour job default: `set -eux` fails fast on an ERROR but not on a
STALL, and every network call in that step was unbounded. The step is bounded now — but a
bound is a value someone can raise, and the failure it prevents is invisible on a green run,
so nothing about it is self-evidencing. These pin it.

The load-bearing one is `test_the_per_command_bounds_nest_inside_the_step_bound`. Two layers
of timeout only pay off in one ordering: the per-command bounds have to SUM to less than the
step bound, or a run that stalls twice reaches `timeout-minutes` first and GitHub cancels the
step with a generic "exceeded the maximum execution time" — losing exactly the "which
command stalled" signal the per-command `timeout`s were added to produce. The arithmetic is
easy to break by raising one number, and no test that only checked for *presence* would
notice.

Located by what the steps RUN rather than by name, with a count guard, for the reason
`test_771_alias_ban.py`'s census states: a fixture assertion that silently matches nothing
is the vacuous pass this idiom exists to avoid.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: The three jobs that start real gVisor boxes and therefore register the runtime.
_EXPECTED_INSTALL_STEPS = 3

_TIMEOUT_CALL = re.compile(r"\btimeout (\d+)\b")
_CURL_MAX_TIME = re.compile(r"--max-time (\d+)\b")
_CURL_RETRY_MAX_TIME = re.compile(r"--retry-max-time (\d+)\b")


def _workflow() -> dict:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def _install_steps() -> list[dict]:
    steps = [s for job in _workflow()["jobs"].values() for s in job.get("steps", [])]
    installs = [s for s in steps if "runsc install" in str(s.get("run", ""))]
    assert len(installs) == _EXPECTED_INSTALL_STEPS, (
        f"expected the three gVisor install steps, got {len(installs)} — the step moved, so "
        f"re-scope this demand rather than trusting a vacuous pass"
    )
    return installs


def _curl_ceiling(run_text: str) -> int:
    """Worst-case wall clock of the step's one `curl`, in seconds.

    `--max-time` bounds ONE attempt and curl resets it per retry, so the series bound is the
    only thing that caps the line: `--retry-max-time` is the last instant a new attempt may
    START, and that attempt then gets a full `--max-time` of its own."""
    per_attempt = _CURL_MAX_TIME.search(run_text)
    series = _CURL_RETRY_MAX_TIME.search(run_text)
    assert per_attempt, "the gvisor key fetch lost its --max-time — one attempt is unbounded"
    assert series, (
        "the gvisor key fetch has --max-time but no --retry-max-time: with --retry N the "
        "per-attempt bound is reset on every retry, so the line as a whole is unbounded"
    )
    return int(per_attempt.group(1)) + int(series.group(1))


def test_every_gvisor_install_step_carries_a_step_timeout() -> None:
    for step in _install_steps():
        assert step.get("timeout-minutes"), (
            f"{step.get('name')!r} carries no timeout-minutes — a stall in it runs to the "
            f"6-hour job default, which is the #937 hang"
        )


def test_every_external_command_in_the_step_is_individually_bounded() -> None:
    """`apt-get` and `systemctl` run under `timeout`, and the pipeline reports curl's status.

    `pipefail` is part of the bound, not decoration: `curl | gpg` without it reports gpg's
    exit status, so a curl that hit its own `--max-time` surfaces as `no valid OpenPGP data
    found` and the reader is pointed at the wrong command."""
    for step in _install_steps():
        run_text = str(step["run"])
        # The `set` LINE, not the step text: the comment above it says the word too, and a
        # substring test over the whole block would keep passing on a step whose shell
        # options had been reverted under a comment that still claims otherwise.
        assert any(
            line.strip().startswith("set ") and "pipefail" in line
            for line in run_text.splitlines()
        ), (
            f"{step.get('name')!r} pipes curl into gpg without pipefail — a bounded curl "
            f"that timed out is reported as a gpg parse failure"
        )
        for line in run_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "apt-get" in stripped or "systemctl restart" in stripped:
                assert _TIMEOUT_CALL.search(stripped), (
                    f"{step.get('name')!r} runs {stripped!r} with no `timeout` — it is one "
                    f"of the two commands #937 observed stalling"
                )


def test_the_per_command_bounds_nest_inside_the_step_bound() -> None:
    for step in _install_steps():
        run_text = str(step["run"])
        inner = _curl_ceiling(run_text) + sum(
            int(n) for n in _TIMEOUT_CALL.findall(run_text)
        )
        outer = int(step["timeout-minutes"]) * 60
        assert inner < outer, (
            f"{step.get('name')!r} bounds sum to {inner}s against a {outer}s step bound — a "
            f"run that stalls more than once trips `timeout-minutes` first, and GitHub's "
            f"generic step cancel replaces the per-command exit 124 that names the culprit"
        )


def test_every_job_carries_a_job_timeout() -> None:
    """The backstop under the steps this file does not census.

    `docker pull`, `uv sync`, `npm install -g jscpd` and the DooD container's own apt/pip/curl
    reach hosts the runner does not control too. Bounding one step leaves those on the 6-hour
    default, so the job bound is what makes "nothing here can hang indefinitely" true rather
    than true of one step."""
    for name, job in _workflow()["jobs"].items():
        assert job.get("timeout-minutes"), (
            f"job {name!r} carries no timeout-minutes — any unbounded step in it runs to the "
            f"6-hour default"
        )
