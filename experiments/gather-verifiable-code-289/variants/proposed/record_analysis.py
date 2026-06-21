#!/usr/bin/env python3
"""Gather ANALYSIS capture wrapper (prototype, #289).

Sibling of ``scripts/gather_tools/record_query.py`` for the *analysis* step: where
record-query captures an adapter call against a live source, record-analysis
captures a deterministic computation over an **already-persisted, read-only**
payload. The wrapper runs the inner snippet (jq for the MVP; ``python3`` later),
captures its stdout, and **that stdout is the reported value** — the model can't
substitute prose for a snippet that errored or returned nothing. The
(label, snippet, output) triple is appended to a sibling ``analyses.jsonl``
table so the value is recorded, auditable, and re-runnable (the #275 judge can
replay it).

    defender-record-analysis --lead l-001 --label distinct-srcips -- \
        jq '[.[].data.srcip] | unique | length' \
        /tmp/defender-runs/<id>/gather_raw/l-001/0.json

Flags:
  * ``--lead``   (required) the :L row id — the FK + the analyses-table group id.
  * ``--label``  (required) the computable dimension this snippet measures
                 (``distinct-srcips``, ``session-duration``, …). The semantic
                 binding the model supplies; not a function of the argv.
  * ``--run-dir`` defaults to ``$DEFENDER_RUN_DIR`` (the run.py/runtime export).

Prototype scope (#289 jq-first MVP): the wrapper is permissive about the inner
tool — it execs whatever follows ``--``. The runtime gate already constrains the
gather subagent to safe non-adapter tokens (jq/grep/…) via
``permission.decide_bash``; the Python AST-allowlist is a *later* phase, not
wired here. Kept under the experiment dir, NOT promoted into
``defender/scripts/tools`` or ``learning/lead_repository.py`` — the
``analyses.jsonl`` schema stays provisional until the pilot earns it.

Exit code: the inner command's exit code (or 2 on a wrapper usage error).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# Mirror record_query.LEAD_ID_RE — the lead id is a path/table key, validate it.
LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")
# A label is a kebab dimension name; keep it tame so it's a clean table key.
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# The recorded output is the value, and analysis outputs are small by design
# (a count, a short list, a timestamp pair). Cap defensively so a misfired
# snippet that dumps the whole payload can't bloat the table; the full stdout
# still passes through to the subagent.
_OUTPUT_RECORD_MAX = 8192
_ANALYSIS_TIMEOUT_S = int(os.environ.get("DEFENDER_ANALYSIS_TIMEOUT_SEC", "60"))


def _detect_payload(inner: list[str]) -> str | None:
    """Best-effort: the first inner token that points at a persisted payload
    (a path under a ``gather_raw/`` tree). Audit breadcrumb only — not
    load-bearing for the capture."""
    for tok in inner:
        if "gather_raw" in tok and tok.endswith(".json"):
            return tok
    return None


def _inner_tool(inner: list[str]) -> str:
    """The analysis tool name (``jq``/``python3``/…) — the inner argv head,
    basename-normalized. Used only as a table column for slicing the audit."""
    if not inner:
        return ""
    return Path(inner[0]).name


def _next_seq(run_dir: Path, lead: str) -> int:
    """Next per-lead analysis seq = rows already recorded for this lead. Counting
    rows (not files) keeps seq monotonic across a failed-output row, mirroring
    record_query._next_seq."""
    log = run_dir / "analyses.jsonl"
    if not log.is_file():
        return 0
    try:
        text = log.read_text()
    except OSError:
        return 0
    n = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(rec, dict) and rec.get("lead_id") == lead:
            n += 1
    return n


def _output_status(exit_code: int, stdout: str) -> str:
    """Coarse structural status — the empty-vs-suspect judgement stays with the
    model (gather SKILL), this is the structural floor (mirrors payload_status)."""
    if exit_code != 0:
        return "error"
    if not stdout.strip():
        return "empty"
    return "ok"


def capture(
    run_dir: Path, lead: str, label: str, inner: list[str],
    *, env: dict | None = None, timeout: int = _ANALYSIS_TIMEOUT_S,
) -> tuple[str, str, dict]:
    """Run an analysis snippet over a persisted payload and record it.

    Returns ``(stdout, stderr, record)`` — stdout passes straight through (it is
    the value), and the row is appended to ``analyses.jsonl``. Raises
    ``ValueError`` on a malformed lead/label (the wrapper's preconditions)."""
    if not LEAD_ID_RE.match(lead):
        raise ValueError(f"invalid lead id {lead!r} (expected an `l-` row id)")
    if not LABEL_RE.match(label):
        raise ValueError(f"invalid label {label!r} (expected a kebab dimension name)")

    try:
        proc = subprocess.run(
            inner, capture_output=True, text=True, env=env, timeout=timeout
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        rc, out, err = 127, "", f"analysis tool not found: {e}"
    except subprocess.TimeoutExpired:
        rc, out, err = 124, "", f"analysis snippet timed out after {timeout}s"

    seq = _next_seq(run_dir, lead)
    recorded_output = out if len(out) <= _OUTPUT_RECORD_MAX else (
        out[:_OUTPUT_RECORD_MAX] + f"\n…[truncated {len(out) - _OUTPUT_RECORD_MAX} chars]"
    )
    record = {
        "lead_id": lead,
        "analysis_seq": seq,
        "label": label,
        "tool": _inner_tool(inner),
        "snippet": shlex.join(inner),
        "payload_path": _detect_payload(inner),
        "output": recorded_output,
        "exit_code": rc,
        "output_status": _output_status(rc, out),
    }
    try:
        log = run_dir / "analyses.jsonl"
        with log.open("a") as fh:  # append is atomic for one short line
            fh.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"record_analysis: could not append record: {e}", file=sys.stderr)
    return out, err, record


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1 :]


def main(argv: list[str]) -> int:
    wrapper_argv, inner = _split_argv(argv)
    parser = argparse.ArgumentParser(prog="record_analysis.py")
    parser.add_argument("--run-dir")
    parser.add_argument("--lead", required=True)
    parser.add_argument("--label", required=True)
    try:
        ns = parser.parse_args(wrapper_argv)
    except SystemExit:
        return 2
    if not inner:
        print("record_analysis.py: nothing after `--` to execute", file=sys.stderr)
        return 2

    run_dir_arg = ns.run_dir or os.environ.get("DEFENDER_RUN_DIR")
    if not run_dir_arg:
        print(
            "record_analysis.py: --run-dir not given and DEFENDER_RUN_DIR is unset",
            file=sys.stderr,
        )
        return 2

    try:
        out, err, record = capture(Path(run_dir_arg), ns.lead, ns.label, inner)
    except ValueError as e:
        print(f"record_analysis.py: {e}", file=sys.stderr)
        return 2

    sys.stdout.write(out)
    sys.stderr.write(err)
    print(
        f"[record_analysis] {record['label']} → analyses.jsonl "
        f"(seq {record['analysis_seq']}, status {record['output_status']})",
        file=sys.stderr,
    )
    return record["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
