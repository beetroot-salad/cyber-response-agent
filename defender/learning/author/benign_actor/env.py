#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author.benign_actor import run as _benign
from defender.learning.core.config import DEFAULT_PATHS, LoopPaths


def run_batch(*, hold_committed: bool = False, paths: LoopPaths = DEFAULT_PATHS) -> int:
    cfg = _benign.build_adversarial_config(paths)
    return _benign.run_batch(hold_committed=hold_committed, cfg=cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_env.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
