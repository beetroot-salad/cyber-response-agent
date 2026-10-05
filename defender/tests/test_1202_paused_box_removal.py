"""#1202: removing a paused runsc box.

Under runsc, `docker rm -f` on a PAUSED container kills it but answers non-zero ("could not
kill: container … PID … is zombie and can not be killed") and leaves it behind. Observed on the
GitHub runner: the first `rm -f` failed 8/8 (#1200); after it, `docker wait` returned `137`
promptly and a second removal succeeded 15/15 (#1201). Every site that removes a box —
`stop_box` and the two reaps — must survive that answer, and none may thaw a frozen box to do
it (#1178).

The daemon is a scripted `docker=` seam answering `rm` from a queue with the observed fault
text; every call is recorded so the order (rm, wait, rm) and the absence of `unpause` are
asserted, not assumed.
"""
from __future__ import annotations

import subprocess

import pytest

from defender.runtime.box import BoxExecutor, BoxFault, BoxSpec, _DockerTransport, stop_box
from defender.runtime.box._docker import _reap_on_fault, _reap_stale_before_create

NAME = "defender-drain-r1202"

#: The daemon's answer to removing a paused runsc box, as CI logged it.
ZOMBIE = (
    f'Error response from daemon: cannot remove container "/{NAME}": could not kill: container '
    "9cb443c93025 PID 31569 is zombie and can not be killed. Use the --init option when "
    "creating containers to run an init inside the container that forwards signals and reaps "
    "processes"
)
STUCK = "Error response from daemon: removal of container is stuck"


class Daemon:
    """Answers `rm` from `rm_answers` (rc, stderr) in turn; `inspect` with `status`; `wait`
    with 137 (the exit code CI saw). Records every argv."""

    def __init__(self, rm_answers: list[tuple[int, str]], *, status: str = "exited") -> None:
        self.rm_answers = list(rm_answers)
        self.status = status
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kw) -> subprocess.CompletedProcess:
        self.calls.append(list(argv))
        verb = argv[1]
        if verb == "rm":
            rc, err = self.rm_answers.pop(0)
            return subprocess.CompletedProcess(argv, rc, stdout="" if rc else NAME, stderr=err)
        if verb == "wait":
            return subprocess.CompletedProcess(argv, 0, stdout="137\n", stderr="")
        if verb == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout=f"{self.status}\n", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]

    def removal_verbs(self) -> list[str]:
        return [v for v in self.verbs() if v in ("rm", "wait", "kill", "unpause")]


def _box() -> BoxExecutor:
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(NAME, spec), name=NAME)


def _stop(daemon: Daemon) -> None:
    stop_box(_box(), docker=daemon)


def _reap_stale(daemon: Daemon) -> None:
    _reap_stale_before_create(daemon, NAME)


def _reap_fault(daemon: Daemon) -> None:
    _reap_on_fault(daemon, NAME)


SITES = pytest.mark.parametrize(
    "remove", [_stop, _reap_stale, _reap_fault], ids=["stop_box", "reap_stale", "reap_on_fault"],
)


@SITES
def test_a_zombie_answer_is_waited_out_and_the_box_removed(remove):
    daemon = Daemon([(1, ZOMBIE), (0, "")])
    remove(daemon)
    assert daemon.removal_verbs() == ["rm", "wait", "rm"], daemon.calls
    rms = [c for c in daemon.calls if c[1] == "rm"]
    assert all(c == ["docker", "rm", "-f", NAME] for c in rms), rms
    assert ["docker", "wait", NAME] in daemon.calls, daemon.calls


@SITES
def test_a_removal_that_succeeds_at_once_asks_nothing_more(remove):
    daemon = Daemon([(0, "")])
    remove(daemon)
    assert daemon.removal_verbs() == ["rm"], daemon.calls


@SITES
def test_a_frozen_box_is_never_thawed_to_remove_it(remove):
    daemon = Daemon([(1, ZOMBIE), (1, STUCK)])
    with pytest.raises(BoxFault) if remove is _stop else _no_raise():
        remove(daemon)
    assert "unpause" not in daemon.verbs(), daemon.calls
    assert daemon.verbs().count("rm") == 2, "a stuck box was retried without bound, or not at all"


def test_stop_box_names_both_answers_when_the_box_will_not_go():
    daemon = Daemon([(1, ZOMBIE), (1, STUCK)])
    with pytest.raises(BoxFault) as caught:
        _stop(daemon)
    message = str(caught.value)
    assert "zombie" in message, message
    assert "stuck" in message, message


class _no_raise:  # noqa: N801 — reads as a context-manager keyword beside `pytest.raises`
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> bool:
        return False
