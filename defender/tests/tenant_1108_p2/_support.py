"""#1108 P2: existing replay and Docker machinery, with read-only mount fault input."""
from __future__ import annotations

import subprocess
from pathlib import Path

from defender.runtime import box as box_mod
from defender.tests._spec1092 import STOCK_ROOTFS
from defender.tests.e2e._box665 import DockerFault, RecordingDocker


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


class AgentReadDocker(MountedReadDocker):
    """Docker fault seam: route only the agent identity read to another physical folder.

    Everything else, including create argv, sentinel reads and alias probe, is the shared
    fake. The independent source models a daemon bind to a wrong folder; it neither judges
    tenant ids nor fakes permission policy. Observe the source at EVERY boundary call so
    a transient startup plant that is later removed cannot escape the no-write assertion.
    """

    def __init__(self, agent: Path, *, inside: Path | None = None, fail_create: bool = False):
        super().__init__(create=DockerFault(rc=1, stderr='daemon unavailable')
                         if fail_create else None)
        self.agent = agent
        self.inside = inside if inside is not None else agent
        self.identity_reads: list[list[str]] = []
        self.snapshots: list[dict[str, bytes | None]] = []

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.snapshots.append(tree_bytes(self.agent))
        if len(argv) > 1 and argv[1] == 'exec' and argv[-1].endswith('/.tenant-id'):
            self.calls.append(argv)
            self.identity_reads.append(argv)
            # Run the actual read command. Docker's current process boundary is text=True,
            # including universal-newline conversion and UTF-8 replacement. A plain cat of
            # invalid bare CR therefore cannot fool this fake into preserving bytes Docker
            # would lose; a byte-safe encoded helper is observed with its actual output.
            name = self.create_argv[self.create_argv.index('--name') + 1]
            command = argv[argv.index(name) + 1:]
            command[-1] = str(self.inside / '.tenant-id')
            return subprocess.run(command, capture_output=True, text=True, check=False,
                                  encoding='utf-8', errors='replace', timeout=10)
        return super().__call__(argv, **kw)


def start_with(docker):
    def start(*args, **kwargs):
        return box_mod.start_box(*args, spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS),
                                 docker=docker, **kwargs)
    return start
