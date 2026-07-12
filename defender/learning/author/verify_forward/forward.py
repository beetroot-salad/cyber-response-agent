"""The findings curator's forward check, as a library (#558).

Predicts what the defender agent would conclude on a case with a candidate lesson loaded at
PLAN time, and asks whether it still reaches the case's ground-truth disposition. Curator A
(``defender/lessons/``) runs it through the in-process ``forward_check`` tool; ``checks.py``
composes these helpers into the prompt payload. There is no CLI entry point — the check used
to be a bash subprocess the curator typed, and pinning a program token could not constrain
what that program did with its own operands (#558, #565).

The disposition handed to the verifier is direction-aware (see ``expected_disposition``): a
benign-direction (FP) lesson is generated from a run the defender called ``malicious`` but
which it exists to *correct toward* ``benign``, so the recorded ``malicious`` is exactly what
it must NOT preserve.

Single rep — replication is for statistical TNR/TPR measurement, not per-edit gating (see
``experiments/defender-author-verification/results/final.md``).

``runs_dir`` is a REQUIRED argument on every loader here, never a module constant: the
curator imports this module from the main checkout while editing a throwaway worktree, so a
default frozen at import would read the wrong tree.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from defender._run_paths import RunPaths
from defender.learning.core.config import REPO_ROOT

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "forward.md"

# Scoped, closed-only read of the cited covering policy for a benign forward-check
# (issue #338) — same read-only adapter the seed sampler uses.
_TICKET_CLI = REPO_ROOT / "defender" / "scripts" / "adapters" / "ticket_cli.py"
_POLICY_FETCH_TIMEOUT = 15
_NO_CITED_POLICY = (
    "(no cited covering policy — none was offered, or the store is unreachable)"
)


def load_run_context(run_id: str, *, runs_dir: Path) -> tuple[str, str]:
    run_dir = runs_dir / run_id
    investigation = RunPaths(run_dir).investigation
    refs = run_dir / "source_refs.yaml"
    if not investigation.is_file():
        raise SystemExit(f"verify_forward: missing investigation.md at {investigation}")
    if not refs.is_file():
        raise SystemExit(f"verify_forward: missing source_refs.yaml at {refs}")
    # source_refs.yaml is a flat key:value document with one nested
    # `paths:` block; we only need `normalized_disposition` from the
    # top level. Parse with a regex so the verifier runs under any
    # python interpreter (no pyyaml dependency).
    m = re.search(
        r"^normalized_disposition:\s*[\"']?([^\"'\n#]+?)[\"']?\s*(?:#.*)?$",
        refs.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not m:
        raise SystemExit(
            f"verify_forward: source_refs.yaml missing normalized_disposition: {refs}"
        )
    return investigation.read_text(encoding="utf-8"), m.group(1).strip()


def expected_disposition(direction: str, recorded: str) -> str:
    """The disposition the lesson must drive the agent toward on its source case.

    Adversarial findings author only on a ``benign`` source disposition, and the
    lesson must *preserve* that benign call (generalize suspicion without
    over-escalating this known-good case) — so the recorded disposition is the
    target the verifier checks against. Benign (FP-direction) findings author on
    a ``malicious`` source disposition that the FP signal says was an
    over-escalation: the lesson exists to drive the agent *off* that malicious
    call toward ``benign``, so the recorded ``malicious`` is exactly what it must
    NOT preserve. Handing the verifier the recorded ``malicious`` would mark
    every de-escalation lesson BAD, holding the entire FP lesson path. The
    corrected target for the benign direction is therefore ``benign``.

    (Residual: this makes the benign forward-check an *efficacy* check — does the
    lesson reach the corrected disposition on its own source case — not a
    cross-case FN-safety guard against under-escalating real attacks. That guard
    needs known-malicious cases the source FP case is not; it is out of scope for
    a per-source-case forward check. See docs/decisions/benign-actor-success-retrieval.md.)
    """
    if direction == "benign":
        return "benign"
    return recorded


def _cited_case_ids(run_id: str, *, runs_dir: Path) -> list[str]:
    """Case ids the benign actor was offered as covering-policy seeds, read from the
    source run's persisted `past_tickets.txt` menu (one `- {case_id}: …` line each).
    Empty when no menu was written (cold-start / no seeds offered)."""
    menu = runs_dir / run_id / "past_tickets.txt"
    if not menu.is_file():
        return []
    ids: list[str] = []
    for line in menu.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s.startswith("- "):
            continue
        head = s[2:].split(":", 1)[0].strip()
        if head:
            ids.append(head)
    return ids


def _fetch_closed_resolution(case_id: str) -> str | None:
    """A cited closed case's full `resolution` (incl. the grounded `[grounded: …]`
    conditions), via the read-only ticket CLI scoped to closed. None on any failure —
    the policy load is best-effort and must never break the forward-check."""
    cmd = [
        sys.executable, str(_TICKET_CLI), "get-ticket", case_id,
        "--require-closed",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_POLICY_FETCH_TIMEOUT, cwd=str(REPO_ROOT), encoding="utf-8"
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    try:
        ticket = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    res = ticket.get("resolution") if isinstance(ticket, dict) else None
    return res if isinstance(res, str) and res.strip() else None


def load_cited_policy(
    run_id: str, *, runs_dir: Path, fetch_fn=_fetch_closed_resolution
) -> str:
    """The cited covering policies (closed cases) for a benign forward-check, rendered
    for the verifier prompt. The benign actor cites a past closed case as a covering
    policy; loading its grounded resolution lets the verifier reproduce the close using
    the policy the lesson routes to. Returns a neutral placeholder when no seed was
    cited / the store is unreachable (the check then runs on lesson + transcript alone —
    non-fatal)."""
    lines = [
        f"- {case_id}: {res}"
        for case_id in _cited_case_ids(run_id, runs_dir=runs_dir)
        if (res := fetch_fn(case_id))
    ]
    if not lines:
        return _NO_CITED_POLICY
    return (
        "Cited covering policies (closed cases; grounded conditions ride in the "
        "resolution):\n" + "\n".join(lines)
    )
