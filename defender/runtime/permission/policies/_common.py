"""The runtime agents' (main/gather) bash grants + read shapes.

The mechanism (compile a per-run grant list) is shared; the *policy* — which shapes, which
routes, which deny reason — stays per-agent, and is now spelled as DATA on each def rather
than composed by a regex machine.

What replaced what (#575):

  - the anchored per-program grammars (the run dir interpolated into every viewer's operand
    slot) → ONE `cat` grant whose SCOPE is an anchored regex over the RESOLVED path. The bash
    lane resolves now, so a symlink out of the run dir is denied by a CHECK rather than by a
    side invariant about who may create links;
  - `grep`/`head`/`tail`/`wc`/`jq`'s file operands → nothing. They are stdin-only pipe stages
    (`cat X | grep -n s`), which is what makes `cat` the sole opener: one extractor, one scope
    check, and no per-program option parser to get wrong;
  - `ls`/`cd` → nothing. `ls`'s anchored DIR operand was the other path-opening slot, and a
    lane with no recursive-descent primitive at all is what makes containment complete rather
    than lucky: to reach a path a viewer must NAME it, and a named path is a resolved path is a
    scope check;
  - the read tool's filename filter (a second grammar built from the same source — #545) → the
    SAME tuple object the `cat` grant carries. Parity is identity now, not maintenance."""

from __future__ import annotations

from pathlib import Path

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
from defender.runtime.permission.grant import (
    ADAPTER,
    SEG,
    PathShapes,
    STDIN_VIEWERS,
    STRUCTURAL_SHAPE,
    Grant,
    Route,
    program_shape,
    under,
)

# The corpus subdirs whose `.md` files a runtime agent may read — lessons (pitfalls), skills
# (per-system references + gather query templates), examples. The names are the stable corpus
# offsets; the anchoring root is the run's `defender_dir` (a worktree, for a drain), never a
# module constant.
_CORPUS_SUBDIRS = ("lessons", "skills", "examples")

# The argument-inert programs every reader lane admits regardless of its shim set: they open no
# file, and under `shell=False` their arguments are literal bytes.
_INERT = ("echo", "true")


def read_shapes(
    run_dir: Path, defender_dir: Path, *, raw: bool
) -> PathShapes:
    """The paths a runtime reader may open — on BOTH surfaces. Broad where the AGENT authors,
    tight where the MACHINE writes:

      - the run dir's own files (`investigation.md`, `report.md`, `alert.json`, the tables) and
        the gather summaries: the agent's own workspace, so the shape admits any file it wrote;
      - `gather_raw/{lead_id}/{seq}.json` only when `raw` — a machine-generated path, so it gets
        a machine-tight grammar. Main does not get this shape at all: its denial of the raw
        payload channel is the ABSENCE of an address, not a clamp on a wider one. (The leads
        table, `gather_raw/{lead_id}.lead.json`, is in nobody's shapes — which the old substring
        clamp decided by accident and this decides on purpose.);
      - the corpus `.md` under lessons/skills/examples — tight enough that neither a traversal
        nor a non-`.md` secret can be spelled.

    ONE tuple, handed to BOTH the `cat` grant's scope and `AgentPolicy.read_allow`, so the two
    surfaces are the same object and cannot drift the way #545's two grammars could."""
    run, dfn = run_dir.resolve(), defender_dir.resolve()
    corpus = "|".join(_CORPUS_SUBDIRS)
    shapes = [
        under(run, SEG),                                    # {run}/<file>
        under(run, rf"gather_summaries/{SEG}"),             # {run}/gather_summaries/<file>
    ]
    if raw:
        shapes.append(under(run, r"gather_raw/l-\d+/\d+\.json"))
    shapes.append(under(dfn, rf"(?:{corpus})(?:/{SEG})*/{SEG}\.md"))
    return PathShapes(shapes)


def reader_grants(
    run_dir: Path, defender_dir: Path, *, raw: bool, adapters: bool
) -> tuple[Grant, ...]:
    """The main/gather bash lane: `cat` (the sole opener, scoped to `read_shapes`), the five
    stdin-only viewers, the non-adapter `defender-*` shims + the inert `echo`/`true`, and — for
    gather — the two structurally-routed adapter grants.

    Every program's SHAPE comes from the one `grant.program_shape` table, so main, gather, the
    judge and the curators cannot drift into disagreeing about what `grep` may do — which they
    did: #579 had to be fixed twice, and the second copy was missed."""
    scope = read_shapes(run_dir, defender_dir, raw=raw)
    grants = [
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        *(Grant(program=v, pattern=program_shape(v)) for v in STDIN_VIEWERS),
        *(
            Grant(program=s, pattern=program_shape(s))
            for s in sorted(set(NON_ADAPTER_SHIMS) | set(_INERT))
        ),
    ]
    if adapters:
        # The adapter capability IS these grants: `command_shape` classifies the command
        # structurally and `bash._decide_adapter` looks its route up HERE, so a capability
        # without a grant cannot exist — and a route without a grant could not be audited.
        grants += [
            Grant(program=ADAPTER, pattern=STRUCTURAL_SHAPE, route=Route.CAPTURE_ADAPTER),
            Grant(program=ADAPTER, pattern=STRUCTURAL_SHAPE, route=Route.CAPTURE_ADAPTER_SQL),
        ]
    return tuple(grants)


__all__ = ["read_shapes", "reader_grants"]
