#!/usr/bin/env python3
"""Derive the box's alias-deny seccomp profile from the platform default, rather than
hand-writing one that replaces it.

``--security-opt seccomp=<file>`` replaces the daemon's default profile; Docker and the OCI
runtime spec have no merge or overlay. A hand-written ``defaultAction: SCMP_ACT_ALLOW`` profile
with six denials would trade the default's ~50 denials (``mount``, ``unshare``,
``pivot_root``, ``keyctl``, ``userfaultfd``, ``perf_event_open``, capability-gated ``bpf`` …)
for those six — absorbed by gVisor, but a straight container-escape surface expansion on the
``DEFENDER_BOX_RUNTIME=runc`` fallback.

The default profile is a JSON document, versioned as its own Go module and vendored verbatim
into moby, so it can be pinned: `MOBY_PROFILE_URL` fetches the exact bytes the installed daemon
uses.

The derivation: take the vendored default and remove the banned names from every rule they
appear in, dropping any rule left with no names. The default's ``defaultAction`` is
``SCMP_ACT_ERRNO`` with ``defaultErrnoRet: 1``, so a removed name is denied with EPERM — the
same observable as an explicit deny rule — and everything the platform denies stays denied.

The cost: a vendored allowlist denies every syscall newer than the pinned copy (the
``clone3``/``faccessat2`` breakage class: a newer libc in the box image gets EPERM). This is
bounded by the drift gate: `--check` fails when the derived file stops matching the vendored
base, and `test_the_vendored_default_matches_upstream` fails when the pin goes stale against
its tag.

Usage::

    python3 scripts/gen_seccomp_profile.py            # regenerate the derived profile
    python3 scripts/gen_seccomp_profile.py --check    # fail if the checked-in file has drifted
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from defender.runtime.box import ALIAS_PROFILE_PATH, BANNED_SHAPES  # noqa: E402

#: The vendored platform default, byte-identical to upstream. Kept verbatim (no reformatting,
#: no provenance key, not even a trailing newline) because byte-identity is the drift check.
MOBY_DEFAULT_PATH: Path = ALIAS_PROFILE_PATH.parent / "moby-default.json"

#: Where the vendored copy came from, re-fetchably. `github.com/moby/profiles/seccomp` is the
#: module moby vendors its default from; the version is what `vendor/modules.txt` pins at
#: `MOBY_TAG`, chosen to match the daemon this was verified against (Docker 29.6.1). Every moby
#: release vendoring that module version ships the same bytes.
MOBY_TAG = "docker-v29.6.1"
MOBY_PROFILE_MODULE = "github.com/moby/profiles/seccomp v0.2.3"
MOBY_PROFILE_URL = (
    f"https://raw.githubusercontent.com/moby/moby/{MOBY_TAG}"
    "/vendor/github.com/moby/profiles/seccomp/default.json"
)

#: SHA-256 of the vendored bytes: the offline half of the drift gate, runnable without network.
MOBY_PROFILE_SHA256 = "536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74"


def derive(default_profile: dict, banned: tuple[str, ...]) -> dict:
    """The platform default with `banned` removed from every rule that names them.

    Rules otherwise keep upstream order and shape, including conditional (`includes`/
    `excludes` on capabilities) and argument-filtered ones, which dockerd evaluates against
    the container's capability set at load time; flattening them would change what a box may
    do. A rule whose names are all banned is dropped rather than left with an empty `names`
    array, which some parsers read as "matches nothing" and others as malformed."""
    ban = set(banned)
    rules = []
    for rule in default_profile["syscalls"]:
        kept = [name for name in rule["names"] if name not in ban]
        if not kept:
            continue
        rules.append({**rule, "names": kept})
    return {**default_profile, "syscalls": rules}


def render(profile: dict) -> str:
    return json.dumps(profile, indent=2) + "\n"


def build() -> str:
    text = MOBY_DEFAULT_PATH.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if digest != MOBY_PROFILE_SHA256:
        raise SystemExit(
            f"{MOBY_DEFAULT_PATH} does not match the pinned upstream digest "
            f"({digest} != {MOBY_PROFILE_SHA256}). The vendored platform default is meant to be "
            f"byte-identical to {MOBY_PROFILE_URL}; re-fetch it and update "
            f"MOBY_PROFILE_SHA256, rather than editing it in place."
        )
    return render(derive(json.loads(text), BANNED_SHAPES))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="exit non-zero if the checked-in derived profile is not what this script produces",
    )
    args = parser.parse_args(argv)
    want = build()
    if args.check:
        have = ALIAS_PROFILE_PATH.read_text(encoding="utf-8")
        if have != want:
            print(
                f"{ALIAS_PROFILE_PATH} has drifted from the vendored platform default. "
                f"Run `python3 scripts/gen_seccomp_profile.py` to regenerate it.",
                file=sys.stderr,
            )
            return 1
        return 0
    ALIAS_PROFILE_PATH.write_text(want, encoding="utf-8")
    print(f"wrote {ALIAS_PROFILE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
