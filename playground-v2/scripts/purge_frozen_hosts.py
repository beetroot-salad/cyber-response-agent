#!/usr/bin/env python3
"""Remove one freeze's cached host images and extracted host parts from the frozen engine (#1391
r6 O9). A launch loads each host image and extracts each host part once per part digest and keeps
them; nothing evicts them on its own. Run it when a freeze is retired or the engine's disk fills.

    python3 playground-v2/scripts/purge_frozen_hosts.py <held_out>/freezes/<freeze-id>

Take the frozen-engine lock first (`chaos/lock.py`): a launch in flight would lose its replicas'
images. A part another freeze shares (same digest) is removed too and refilled on its next launch.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from lab_ops import LabOps  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("freeze_dir", type=Path)
    args = parser.parse_args(argv)
    freeze = yaml.safe_load((args.freeze_dir / "freeze.yaml").read_text())
    hosts = LabOps.frozen_hosts(freeze)
    LabOps.from_environment().purge_host_cache(freeze)
    print(f"purged the cached host images and parts of {args.freeze_dir.name}: {', '.join(hosts) or 'no hosts'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
