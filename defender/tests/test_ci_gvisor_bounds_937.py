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


def test_apt_retries_come_with_a_bounded_per_connection_timeout() -> None:
    """A retry count with no connect timeout under it multiplies the stall it was added for.

    `Acquire::Retries` applies to EVERY source, not the one whose transient motivated it. On
    run 32294123321 the runner's azure.archive.ubuntu.com mirror was unreachable and the
    default 30s connect timeout x 4 attempts put a 120s floor under `apt-get update` — while
    the gvisor host, the reason the retry was added, answered in under a second. The retry
    turned a bounded command into one that could not finish inside its bound. Pinning them
    together is what keeps the outer `timeout` a bound rather than a race with whichever
    Ubuntu mirror is down that morning."""
    for step in _install_steps():
        # CODE lines only. The rationale comment above the options names both settings, so a
        # substring test over the block text keeps passing on a step whose actual apt-get
        # options were stripped out from under a comment that still explains them — the same
        # vacuity the `pipefail` check above reads the `set` line to avoid.
        run_text = "\n".join(
            line for line in str(step["run"]).splitlines() if not line.strip().startswith("#")
        )
        # Unconditional: the retry is itself load-bearing. #937's stall was transient and
        # cleared on a re-run in under 20s, so an apt with a kill and no retry converts that
        # same transient into three red jobs — the treatment curl already had, against a host
        # that had not even failed. Dropping the retry must fail here, not pass vacuously.
        assert "Acquire::Retries" in run_text, (
            f"{step.get('name')!r} runs apt-get with no Acquire::Retries — the bound now "
            f"turns the transient #937 observed into a red build instead of a re-fetch"
        )
        # `update` fetches ONLY the source this step added. Bounding a command that reaches
        # every mirror on the runner is a bet on all of them; run 32294715524 lost it on the
        # archive.ubuntu.com failover even with the connect timeout capped. runsc needs none
        # of those repos ("1 newly installed, 0 to remove"), so the scoping is what makes the
        # 60s bound a statement about one host we do need rather than about the internet.
        update_line = next(
            (ln for ln in run_text.splitlines() if "apt-get" in ln and ln.rstrip().endswith("update")),
            None,
        )
        assert update_line, "the step no longer runs `apt-get ... update` — re-scope this demand"
        assert "GVISOR_ONLY" in update_line or "Dir::Etc::sourcelist" in update_line, (
            f"{step.get('name')!r} runs an unscoped `apt-get update` — it refreshes every "
            f"mirror on the runner for a package that depends on none of them, so the bound "
            f"becomes a bet on whichever Ubuntu mirror is down"
        )
        for scheme in ("http", "https"):
            assert f"Acquire::{scheme}::Timeout" in run_text, (
                f"{step.get('name')!r} sets Acquire::Retries with no Acquire::{scheme}::"
                f"Timeout — a retry against an unreachable mirror inherits the 30s default "
                f"and multiplies it by the retry count, blowing the enclosing `timeout`"
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


def test_the_step_bounds_nest_inside_the_job_bound() -> None:
    """The third layer of the same argument, and the one a lowered job bound breaks first.

    A job bound at or under its own step bound preempts the step: GitHub cancels the job with
    a generic "exceeded the maximum execution time" before the step's `timeout-minutes` can
    fire, and the per-command exit 124 underneath it never gets read out. That makes the job
    bound and the step bound adversaries rather than layers, which is the #937 failure mode
    one level up. The margin between them is what the un-bounded steps run in."""
    for name, job in _workflow()["jobs"].items():
        step_bounds = sum(
            int(s["timeout-minutes"]) for s in job.get("steps", []) if s.get("timeout-minutes")
        )
        if not step_bounds:
            continue
        job_bound = int(job["timeout-minutes"])
        assert step_bounds < job_bound, (
            f"job {name!r} bounds its steps to {step_bounds}m against a {job_bound}m job "
            f"bound — the job cancel preempts the step timeout, so a stall is reported as "
            f"'the job was too slow' instead of naming the command that hung"
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
