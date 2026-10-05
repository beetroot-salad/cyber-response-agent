"""Tearing down a paused runsc box (#1198's CI, the #1178 frozen-box row).

Under runsc, `docker rm -f` on a PAUSED container kills it but answers non-zero ("could not
kill: container … PID … is zombie and can not be killed") and leaves the dead container behind.
Observed on GitHub's runner (diag run 37287400711): 8/8 first `rm -f` calls failed that way,
the status right after read `paused` or `exited`, and a second `rm -f` removed the container
8/8. The same failure reproduced with a stock image and no `--ulimit`, and with `main`'s box
package (diag run 37286665716), so it is runsc's, not this branch's.

`stop_box` must therefore retry the removal once, never unpause first: a thaw would let the
box run again between the judge and the teardown, which #1178 exists to stop. The daemon is a
scripted `docker=` seam answering with the observed fault text.
"""
from __future__ import annotations

import subprocess

import pytest

from defender.runtime.box import BoxExecutor, BoxFault, BoxSpec, _DockerTransport, stop_box

BOX_NAME = "defender-drain-s1188"

#: The daemon's answer to the first `rm -f` of a paused runsc box, as CI logged it.
ZOMBIE = (
    'Error response from daemon: cannot remove container "/defender-drain-s1188": could not '
    "kill: container 9cb443c93025 PID 31569 is zombie and can not be killed. Use the --init "
    "option when creating containers to run an init inside the container that forwards "
    "signals and reaps processes"
)


def _box() -> BoxExecutor:
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(BOX_NAME, spec), name=BOX_NAME)


class Daemon:
    """Answers each `docker rm` from `rm_answers` in turn (rc, stderr); records every call."""

    def __init__(self, rm_answers: list[tuple[int, str]]) -> None:
        self.rm_answers = list(rm_answers)
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_kw) -> subprocess.CompletedProcess:
        self.calls.append(list(argv))
        if argv[1] == "rm":
            rc, err = self.rm_answers.pop(0)
            return subprocess.CompletedProcess(argv, rc, stdout="" if rc else BOX_NAME, stderr=err)
        return subprocess.CompletedProcess(argv, 0, stdout="exited", stderr="")

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]


def test_a_paused_box_whose_first_removal_answers_zombie_is_removed_by_a_second():
    daemon = Daemon([(1, ZOMBIE), (0, "")])
    stop_box(_box(), docker=daemon)
    rms = [c for c in daemon.calls if c[1] == "rm"]
    assert rms == [["docker", "rm", "-f", BOX_NAME]] * 2, daemon.calls
    assert "unpause" not in daemon.verbs(), "the teardown thawed a frozen box"


def test_a_removal_that_succeeds_first_time_is_not_repeated():
    daemon = Daemon([(0, "")])
    stop_box(_box(), docker=daemon)
    assert daemon.verbs().count("rm") == 1, daemon.calls


def test_a_box_that_will_not_go_is_still_a_fault_naming_the_daemons_answer():
    daemon = Daemon([(1, ZOMBIE), (1, "Error response from daemon: still here")])
    with pytest.raises(BoxFault, match="still here"):
        stop_box(_box(), docker=daemon)
    assert daemon.verbs().count("rm") == 2, "a stuck box was retried without bound, or not at all"
    assert "unpause" not in daemon.verbs()
