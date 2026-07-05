#!/usr/bin/env python3
"""Forward-check Haiku gate for a single candidate lesson.

Usage: ``verify_forward.py [--direction adversarial|benign] <lesson_path> <run_id>``

Reads the lesson file, the source case's investigation transcript at
``defender/learning/runs/<run_id>/investigation.md``, and the recorded
disposition from
``defender/learning/runs/<run_id>/source_refs.yaml``. Runs the forward-check
IN-PROCESS on PydanticAI (GLM 5.2, Fireworks — the metered first-party path, the
mirror of the judge/actor/oracle migrations) with
``defender/learning/author/verify_forward/forward.md`` as the system prompt, via
the shared ``verify_forward/engine.forward_check``. Predicting with the defender's
own model (``runtime/driver.DEFAULT_MODEL``) tightens this same-case regression
proxy. Prints exactly ``GOOD`` or ``BAD`` on the last line of stdout.

The disposition handed to the verifier is direction-aware (see
``expected_disposition``): a benign-direction (FP) lesson is generated from a
run the defender called ``malicious`` but which it exists to *correct toward*
``benign``, so the recorded ``malicious`` is exactly what it must NOT preserve.

Single rep — replication is for statistical TNR/TPR measurement, not
per-edit gating (see ``experiments/defender-author-verification/results/final.md``).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]
# The run bundle (investigation.md + source_refs.yaml) is written under
# DEFAULT_PATHS.runs_dir, which honors DEFENDER_LEARNING_STATE_DIR — out-of-repo
# under concurrent runs. Resolve from the same seam the producer wrote to rather
# than assuming the in-repo default. The module-level imports stay stdlib + core.config
# (no pyyaml, no pydantic-ai), so this file imports under any interpreter — the GLM
# engine is pulled LAZILY inside main() (see `forward_check`), which is what keeps the
# tests/test_verify_forward subprocess cases (import + load_run_context) runtime-free.
# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from defender._run_paths import RunPaths  # noqa: E402
from defender.learning.core.config import DEFAULT_PATHS  # noqa: E402
from defender.learning.author.verify_forward.shared import render_prompt  # noqa: E402
RUNS_DIR = DEFAULT_PATHS.runs_dir
PROMPT_PATH = HERE / "forward.md"

# Scoped, closed-only read of the cited covering policy for a benign forward-check
# (issue #338) — same read-only adapter the seed sampler uses, kept pyyaml-free.
_TICKET_CLI = REPO_ROOT / "defender" / "scripts" / "adapters" / "ticket_cli.py"
_POLICY_FETCH_TIMEOUT = 15
_NO_CITED_POLICY = (
    "(no cited covering policy — none was offered, or the store is unreachable)"
)


def load_run_context(run_id: str, runs_dir: Path = RUNS_DIR) -> tuple[str, str]:
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
        refs.read_text(),
        re.MULTILINE,
    )
    if not m:
        raise SystemExit(
            f"verify_forward: source_refs.yaml missing normalized_disposition: {refs}"
        )
    return investigation.read_text(), m.group(1).strip()


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


def _cited_case_ids(run_id: str, runs_dir: Path = RUNS_DIR) -> list[str]:
    """Case ids the benign actor was offered as covering-policy seeds, read from the
    source run's persisted `past_tickets.txt` menu (one `- {case_id}: …` line each).
    Empty when no menu was written (cold-start / no seeds offered)."""
    menu = runs_dir / run_id / "past_tickets.txt"
    if not menu.is_file():
        return []
    ids: list[str] = []
    for line in menu.read_text().splitlines():
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
        "--require-closed", "--raw",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_POLICY_FETCH_TIMEOUT, cwd=str(REPO_ROOT),
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
    run_id: str, runs_dir: Path = RUNS_DIR, *, fetch_fn=_fetch_closed_resolution
) -> str:
    """The cited covering policies (closed cases) for a benign forward-check, rendered
    for the verifier prompt. The benign actor cites a past closed case as a covering
    policy; loading its grounded resolution lets the verifier reproduce the close using
    the policy the lesson routes to. Returns a neutral placeholder when no seed was
    cited / the store is unreachable (the check then runs on lesson + transcript alone —
    non-fatal)."""
    lines = [
        f"- {case_id}: {res}"
        for case_id in _cited_case_ids(run_id, runs_dir)
        if (res := fetch_fn(case_id))
    ]
    if not lines:
        return _NO_CITED_POLICY
    return (
        "Cited covering policies (closed cases; grounded conditions ride in the "
        "resolution):\n" + "\n".join(lines)
    )


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="verify_forward.py")
    ap.add_argument(
        "--direction",
        default="adversarial",
        choices=["adversarial", "benign"],
        help=(
            "learning direction of the finding (default: adversarial). A benign "
            "finding targets the corrected `benign` disposition instead of the "
            "recorded one — pass the finding row's `direction`."
        ),
    )
    ap.add_argument("lesson_path")
    ap.add_argument("run_id")
    ns = ap.parse_args(argv[1:])
    lesson_path = Path(ns.lesson_path).resolve()
    run_id = ns.run_id
    if not lesson_path.is_file():
        print(f"verify_forward: lesson not found: {lesson_path}", file=sys.stderr)
        return 1
    transcript, recorded = load_run_context(run_id)
    disposition = expected_disposition(ns.direction, recorded)
    # A benign lesson routes to a cited covering policy; load it so the verifier can
    # reproduce the close using that policy. Adversarial lessons cite no policy.
    cited_policy = (
        load_cited_policy(run_id) if ns.direction == "benign" else _NO_CITED_POLICY
    )
    user_prompt = render_prompt(
        PROMPT_PATH,
        transcript=transcript,
        lesson=lesson_path.read_text(),
        disposition=disposition,
        cited_policy=cited_policy,
    )
    # Lazy import: pulls the pydantic-ai graph only when a check actually runs, so this
    # module stays importable under any interpreter (the subprocess tests rely on that).
    from defender.learning.author.verify_forward.engine import forward_check

    import time as _time
    t0 = _time.monotonic()
    verdict = forward_check(
        prompt_path=PROMPT_PATH,
        user=user_prompt,
        source_run_dir=RUNS_DIR / run_id,
        lesson_stem=lesson_path.stem,
        error_prefix="verify_forward",
    )
    elapsed = _time.monotonic() - t0
    # Append timing for the harness to reconstruct verifier time. The
    # path is opportunistic: if VERIFY_TIMING_LOG is set we use it,
    # else fall back to a sibling file next to the script. Last line
    # of stdout is still the verdict — author.md reads `last line` only.
    log_path = os.environ.get("VERIFY_TIMING_LOG") or str(HERE / "_verify_timing.log")
    try:
        with open(log_path, "a") as fh:
            fh.write(f"{lesson_path.name} {run_id} {elapsed:.2f}\n")
    except OSError:
        pass
    print(verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
