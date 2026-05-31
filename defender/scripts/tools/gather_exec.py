#!/usr/bin/env python3
"""Gather capture wrapper — deterministic record of an executed query.

The gather subagent invokes this instead of redirecting a system-CLI's
stdout itself:

    gather_exec.py --run-dir {R} --lead {L} \
        --system stub-cmdb --query-id stub-cmdb.host-lookup -- \
        python3 .../cmdb_cli.py host-lookup web-1 --raw

It runs the inner command, captures stdout to a canonical per-lead path,
and appends an executed-query record to ``{R}/executed_queries.jsonl``.
The inner command's stdout/stderr/exit code pass straight through, so the
subagent still sees the result for its reasoning, and the wrapper reports
the raw payload path it wrote on stderr.

It retires the two brittle model-authored steps it replaces: the redirect
to a model-chosen ``gather_raw/{position}.json`` (Bug #1: filename drift →
silent drop) and the post-hoc, free-floating ``queries[]`` sidecar id
(Bug #2: mislabel → catalog miss). Both `--system` and `--query-id` come
from the dispatch contract — `system` is the harness-injected lead system,
`query_id` is the catalog template id the subagent bound (`{system}.{verb}`,
or ``ad-hoc``). They are recorded *at execution time*, bound to the actual
command and its captured payload, rather than reconstructed from a fragile
per-CLI argv grammar — so the wrapper stays portable across whatever system
CLIs are onboarded, with no hardcoded system/verb roster.

The per-lead group id ``L`` comes from the dispatch (the integer lead
position; see ``hooks/extract_lead_metadata.py``); it is the address
namespace for this lead's payloads and the co-dispatch group key.

Exit code: the inner command's exit code (or 2 on wrapper usage error).
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path


def parse_params(inner: list[str]) -> dict:
    """Extract bound params from an inner CLI argv, generically.

    Pure — no IO, no per-system tables. Locates the CLI script (first
    token ending in ``.py``), drops the leading subcommand token (the
    verb, already captured in ``query_id``), then folds the remainder:
    ``--flag value`` / ``-f value`` pairs become named entries, bare
    ``--flag`` (followed by another flag or end-of-args) become ``True``,
    and positionals become ``arg0``/``arg1``/… in order.

    Param *names* for positionals are intentionally generic — the
    durable join key is ``(query_id, params)``, and positional order is
    stable per template, so ``arg0`` is sufficient and portable. The
    verbatim command is preserved separately as ``raw_command``.
    """
    script_idx = next(
        (i for i, t in enumerate(inner) if t.endswith(".py")), None
    )
    rest = inner[script_idx + 1 :] if script_idx is not None else list(inner)
    # Drop the leading subcommand token (the verb); it is already in query_id.
    if rest and not rest[0].startswith("-"):
        rest = rest[1:]

    params: dict[str, object] = {}
    pos = 0
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok.startswith("-"):
            flag = tok.lstrip("-")
            if i + 1 < len(rest) and not rest[i + 1].startswith("-"):
                params[flag] = rest[i + 1]
                i += 2
            else:
                params[flag] = True
                i += 1
        else:
            params[f"arg{pos}"] = tok
            pos += 1
            i += 1
    return params


def payload_status(exit_code: int, stdout: str) -> str:
    """Coarse structural status. The empty-vs-suspect_empty smell test
    stays with the model / debug-lead protocol; this is the structural floor."""
    if exit_code != 0:
        return "error"
    if not stdout.strip():
        return "empty"
    return "ok"


def payload_digest(stdout: str, stderr: str, exit_code: int) -> str:
    """Structural ≤200-char digest. Deterministic, not a smell-test —
    the lead-author reads the raw payload when it needs semantics."""
    if exit_code != 0:
        return f"exit={exit_code}; {stderr.strip()[:160]}"
    lines = stdout.count("\n") + 1 if stdout.strip() else 0
    return f"{len(stdout)} bytes, {lines} line(s)"


def _next_seq(lead_dir: Path) -> int:
    if not lead_dir.is_dir():
        return 0
    return sum(1 for p in lead_dir.glob("*.json"))


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1 :]


def main(argv: list[str]) -> int:
    wrapper_argv, inner = _split_argv(argv)
    parser = argparse.ArgumentParser(prog="gather_exec.py")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--lead", required=True)
    # Both come from the dispatch contract: --system is the harness-injected
    # lead system; --query-id is the catalog template id the subagent bound
    # ({system}.{verb}, or `ad-hoc`). The wrapper records them verbatim.
    parser.add_argument("--system", required=True)
    parser.add_argument("--query-id", required=True)
    try:
        ns = parser.parse_args(wrapper_argv)
    except SystemExit:
        return 2
    if not inner:
        print("gather_exec.py: nothing after `--` to execute", file=sys.stderr)
        return 2

    run_dir = Path(ns.run_dir)
    lead = ns.lead
    query_id = ns.query_id
    verb = query_id.split(".", 1)[1] if "." in query_id else query_id

    proc = subprocess.run(inner, capture_output=True, text=True)

    lead_dir = run_dir / "gather_raw" / lead
    seq = _next_seq(lead_dir)
    payload_path = lead_dir / f"{seq}.json"
    payload_rel = None
    try:
        lead_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(proc.stdout)
        payload_rel = str(payload_path.relative_to(run_dir))
    except OSError as e:
        print(f"gather_exec.py: could not write payload: {e}", file=sys.stderr)

    record = {
        "lead": lead,
        "seq": seq,
        "system": ns.system,
        "verb": verb,
        "query_id": query_id,
        "params": parse_params(inner),
        "raw_command": shlex.join(inner),
        "payload_path": payload_rel,
        "exit_code": proc.returncode,
        "payload_status": payload_status(proc.returncode, proc.stdout),
        "payload_digest": payload_digest(proc.stdout, proc.stderr, proc.returncode),
    }
    try:
        log = run_dir / "executed_queries.jsonl"
        with log.open("a") as fh:  # append is atomic for one short line
            fh.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"gather_exec.py: could not append record: {e}", file=sys.stderr)

    # Transparent passthrough so the subagent's reasoning is unaffected, plus
    # a prefixed pointer to the raw payload on disk (the §3.5 data-source-debug
    # protocol points `--payload` at this path).
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if payload_rel:
        print(f"[gather_exec] raw payload: {payload_rel}", file=sys.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
