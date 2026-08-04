#!/usr/bin/env python3
"""Derive the box's alias-deny seccomp profile from the platform default, rather than
hand-writing one that replaces it.

WHY THIS SCRIPT EXISTS. ``--security-opt seccomp=<file>`` REPLACES the daemon's default
profile; there is no merge, no append, and no overlay anywhere in Docker or the OCI runtime
spec. So a hand-written ``defaultAction: SCMP_ACT_ALLOW`` profile carrying six denials does not
*add* six denials to the platform default — it trades the platform default's ~50 denials
(``mount``, ``unshare``, ``pivot_root``, ``keyctl``, ``add_key``, ``userfaultfd``,
``perf_event_open``, capability-gated ``bpf`` …) for those six. On the gVisor lane most of that
loss is absorbed by the sandbox; on the supported ``DEFENDER_BOX_RUNTIME=runc`` fallback it is a
straight container-escape surface expansion, paid by every box, to gain a ban on six syscalls
that create filesystem aliases.

WHAT THE SPEC PREVIOUSLY SAID, AND WHY IT WAS WRONG. #771's ledger withdrew the
derive-from-default option (C2-fix) on TWO premises. One was right: the replace-not-merge
behaviour above, which is precisely the argument FOR deriving. The other (G9 — "the daemon's
default is compiled in and undumpable") is FALSE, and it is what made the accepted cost look
unavoidable. The default profile is not compiled-in knowledge: it is a JSON document, versioned
as its own Go module, vendored verbatim into moby, and byte-identical across the releases that
share a module version. `MOBY_PROFILE_URL` below fetches the exact bytes the installed daemon
uses. "Undumpable from a running daemon" is true and irrelevant — it does not have to be dumped,
it has to be pinned.

THE DERIVATION. Take the vendored default and REMOVE the banned names from every rule they
appear in, dropping any rule left with no names. Because the default's ``defaultAction`` is
``SCMP_ACT_ERRNO`` with ``defaultErrnoRet: 1``, a name removed from the allowlist is denied with
EPERM — the same errno, and so the same observable, as the hand-written profile's explicit
``SCMP_ACT_ERRNO`` rule. The ban is expressed as a SUBTRACTION from an allowlist instead of an
addition to an allow-all, and everything the platform denies stays denied.

THE COST THIS TRADES FOR, STATED PLAINLY. A vendored allowlist denies every syscall NEWER than
the copy pinned here. That is the ``clone3``/``faccessat2`` breakage class: a box image built on
a newer libc calls something this profile has never heard of and gets EPERM from a profile
nobody edited. The residual is bounded by the drift gate — `--check` fails the moment the
derived file stops matching the vendored base, and `test_the_vendored_default_matches_upstream`
fails when the pin itself goes stale against the tag it names.

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

#: The vendored platform default, byte-identical to upstream. Kept verbatim — no reformatting,
#: no added provenance key, not even a trailing newline — because byte-identity IS the drift
#: check: any edit to this file that upstream did not make shows up as a digest mismatch.
MOBY_DEFAULT_PATH: Path = ALIAS_PROFILE_PATH.parent / "moby-default.json"

#: WHERE THE VENDORED COPY CAME FROM, at the granularity that makes it re-fetchable.
#: `github.com/moby/profiles/seccomp` is the module moby vendors its default profile from; the
#: version below is what `vendor/modules.txt` pins at `MOBY_TAG`, and the tag is chosen to match
#: the daemon this was verified against (Docker 29.6.1). The same bytes ship in every moby
#: release vendoring that module version — the tag names one witness, not the only one.
MOBY_TAG = "docker-v29.6.1"
MOBY_PROFILE_MODULE = "github.com/moby/profiles/seccomp v0.2.3"
MOBY_PROFILE_URL = (
    f"https://raw.githubusercontent.com/moby/moby/{MOBY_TAG}"
    "/vendor/github.com/moby/profiles/seccomp/default.json"
)

#: SHA-256 of the vendored bytes. The OFFLINE half of the drift gate: it catches an edit to the
#: vendored default without needing the network, which is what makes the gate runnable in a job
#: that has none.
MOBY_PROFILE_SHA256 = "536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74"


def derive(default_profile: dict, banned: tuple[str, ...]) -> dict:
    """The platform default with `banned` removed from every rule that names them.

    Rules are otherwise preserved in upstream order and shape, INCLUDING the conditional ones
    (`includes`/`excludes` on capabilities) and the argument-filtered ones — dockerd evaluates
    those against the container's actual capability set when it loads the profile, so dropping
    or flattening them would silently change what a box may do. A rule whose names are entirely
    consumed by the ban is dropped rather than left with an empty `names` array, which some
    parsers read as "matches nothing" and others as malformed."""
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
