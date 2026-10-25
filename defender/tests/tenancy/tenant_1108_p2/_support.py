"""#1108 P2: existing replay and Docker machinery, with read-only mount fault input."""
from __future__ import annotations

import subprocess
from pathlib import Path

from defender import box as box_mod
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS
from defender.tests.e2e._box665 import RecordingDocker


def tree_bytes(root: Path) -> dict[str, bytes | None]:
    return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
            for p in root.rglob('*')}


class MountedReadDocker(RecordingDocker):
    """Read cat operands through the mount table captured from the real create argv."""

    def __call__(self, argv, **kw):
        argv = list(argv)
        if len(argv) > 1 and argv[1] == 'exec' and 'cat' in argv and self.create_argv:
            target = Path(argv[-1])
            for mount in sorted(self.mounts(), key=lambda m: len(m['target']), reverse=True):
                base = Path(mount['target'])
                if target.is_relative_to(base):
                    self.calls.append(argv)
                    source = Path(mount['source']) / target.relative_to(base)
                    try:
                        return subprocess.CompletedProcess(argv, 0, source.read_bytes().decode('utf-8'), '')
                    except OSError as exc:
                        return subprocess.CompletedProcess(argv, 1, '', str(exc))
        return super().__call__(argv, **kw)


# `AgentReadDocker` (routed the in-box `.tenant-id` read) retired with that check (#1108 P4,
# O-A): the run box's bind is proven by the staged token instead (tenant_1108_p4/test_run_copy.py).


def start_with(docker):
    def start(*args, **kwargs):
        return box_mod.start_box(*args, spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS),
                                 docker=docker, **kwargs)
    return start
