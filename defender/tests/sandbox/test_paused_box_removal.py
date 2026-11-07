"""#1202: removing a paused runsc box. `docker rm -f` on a paused box kills it but answers non-zero;
every removal site must wait it out and retry, and none may thaw the box. (The pre-create check
leaves a same-name container alone, so it is not a removal site.)"""
from __future__ import annotations

import subprocess

import pytest

from defender.box import BoxExecutor, BoxFault, BoxSpec, _DockerTransport, stop_box
from defender.box._docker import _reap_on_fault

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


def _reap_fault(daemon: Daemon) -> None:
    _reap_on_fault(daemon, NAME)


SITES = pytest.mark.parametrize(
    "remove", [_stop, _reap_fault], ids=["stop_box", "reap_on_fault"],
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


GONE = f"Error response from daemon: No such container: {NAME}"


class RemovedMeanwhile(Daemon):
    """Another remover (a teardown racing a backstop) got there first: both of this site's `rm`
    answer "No such container", and `inspect` finds nothing while the daemon itself answers."""

    def __init__(self) -> None:
        super().__init__([(1, GONE), (1, GONE)])

    def __call__(self, argv: list[str], **kw) -> subprocess.CompletedProcess:
        if argv[1] == "inspect":
            self.calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr=GONE)
        return super().__call__(argv, **kw)


def test_a_box_removed_by_someone_else_meanwhile_is_removed_not_a_fault():
    """The removal step's promise is "`None` once it is gone": a box another remover took between
    our look and our `rm` is gone, so `stop_box` does not fault and the tenant sweep reports nothing.
    (finalize #1354)"""
    from defender.box import remove_tenant_containers

    _stop(RemovedMeanwhile())  # no BoxFault

    swept = RemovedMeanwhile()
    real = swept.__call__

    def listing(argv: list[str], **kw) -> subprocess.CompletedProcess:
        if argv[1] == "ps":
            return subprocess.CompletedProcess(argv, 0, stdout=f"{NAME}\n", stderr="")
        return real(argv, **kw)

    assert remove_tenant_containers("t-1", docker=listing) is None
