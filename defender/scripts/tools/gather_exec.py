#!/usr/bin/env python3
"""Gather capture wrapper — deterministic record of an executed query.

The gather subagent invokes this instead of redirecting a system-CLI's
stdout itself:

    gather_exec.py --run-dir {R} --lead {L} -- python3 .../cmdb_cli.py get-host web-1 --raw

It runs the inner command, captures stdout to a canonical per-lead path,
and appends a faithful executed-query record to ``{R}/executed_queries.jsonl``
— with ``system``/``verb``/``params`` derived from the inner *argv* (not a
model self-report) and the raw command preserved for audit. The inner
command's stdout/stderr/exit code pass straight through, so the subagent
still sees the result for its reasoning.

This retires the two brittle model-authored steps it replaces: the
redirect to a model-chosen ``gather_raw/{position}.json`` (Bug #1: filename
drift → silent drop) and the self-reported ``queries[]`` id (Bug #2:
mislabel → catalog miss). The per-lead group id ``L`` comes from the
dispatch (see ``hooks/extract_lead_metadata.py``); it replaces ``position``
as both the address namespace and the co-dispatch group key.

Exit code: the inner command's exit code (or 2 on wrapper usage error).
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

# `--raw` is the only store_true flag across the system CLIs; every other
# `--flag` takes a value (verified against scripts/tools/*_cli.py argparse defs).
_BOOLEAN_FLAGS = frozenset({"raw"})

# Positional argument names per (system, verb). Query-string CLIs (elastic)
# are handled separately — their positional is the query body, not a param.
_POSITIONAL_NAMES = {
    ("cmdb", "get-host"): ["name"],
    ("identity", "can-access"): ["user", "host"],
    ("identity", "get-user"): ["user"],
    ("identity", "list-authorized-hosts"): ["user"],
    ("host-state", "proc-tree"): ["host"],
    ("host-state", "passwd"): ["host"],
    ("host-state", "authorized-keys"): ["host"],
    ("host-state", "fim-checksum"): ["host", "path"],
    ("host-state", "package-list"): ["host"],
    ("change-mgmt", "get-change"): ["cr_id"],
    ("threat-intel", "lookup"): ["value"],
}

# Systems whose verb takes a free-form query body as its first positional;
# the body distinguishes the template, so query_id stays {system}.{verb}.
_QUERY_BODY_VERBS = {("elastic", "query"), ("elastic", "alerts")}


def _system_from_cli(token: str) -> str | None:
    """`.../cmdb_cli.py` -> `cmdb`; `host_state_cli.py` -> `host-state`."""
    name = Path(token).name
    if not name.endswith("_cli.py"):
        return None
    return name[: -len("_cli.py")].replace("_", "-")


def parse_invocation(inner: list[str]) -> dict:
    """Parse an inner CLI argv into {system, verb, query_id, params, body}.

    Pure — no IO. Tolerant: an unrecognized shape still yields a record
    rather than raising, so the wrapper never drops a call on a parse miss.
    """
    cli_idx = next(
        (i for i, t in enumerate(inner) if _system_from_cli(t) is not None), None
    )
    if cli_idx is None:
        return {
            "system": "unknown",
            "verb": inner[0] if inner else "",
            "query_id": "unknown",
            "params": {},
            "body": None,
        }

    system = _system_from_cli(inner[cli_idx])
    rest = inner[cli_idx + 1 :]
    verb = next((t for t in rest if not t.startswith("-")), "")
    after_verb = rest[rest.index(verb) + 1 :] if verb in rest else []

    positionals: list[str] = []
    params: dict[str, object] = {}
    i = 0
    while i < len(after_verb):
        tok = after_verb[i]
        if tok.startswith("--"):
            flag = tok[2:]
            if flag in _BOOLEAN_FLAGS:
                i += 1
                continue
            if i + 1 < len(after_verb) and not after_verb[i + 1].startswith("-"):
                params[flag] = after_verb[i + 1]
                i += 2
            else:
                params[flag] = True
                i += 1
        else:
            positionals.append(tok)
            i += 1

    body = None
    if (system, verb) in _QUERY_BODY_VERBS:
        body = positionals[0] if positionals else None
        # remaining positionals (rare) keep generic names
        for n, val in enumerate(positionals[1:]):
            params[f"arg{n}"] = val
    else:
        names = _POSITIONAL_NAMES.get((system, verb))
        for n, val in enumerate(positionals):
            key = names[n] if names and n < len(names) else f"arg{n}"
            params[key] = val

    return {
        "system": system,
        "verb": verb,
        "query_id": f"{system}.{verb}",
        "params": params,
        "body": body,
    }


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
    # Subcommand CLIs (cmdb/host-state/...) let the wrapper derive query_id
    # from the verb. Query-string CLIs (elastic) back many templates with one
    # verb, so the subagent passes the template id it chose here.
    parser.add_argument("--query-id", default=None)
    try:
        ns = parser.parse_args(wrapper_argv)
    except SystemExit:
        return 2
    if not inner:
        print("gather_exec.py: nothing after `--` to execute", file=sys.stderr)
        return 2

    run_dir = Path(ns.run_dir)
    lead = ns.lead
    parsed = parse_invocation(inner)

    proc = subprocess.run(inner, capture_output=True, text=True)

    lead_dir = run_dir / "gather_raw" / lead
    seq = _next_seq(lead_dir)
    payload_path = lead_dir / f"{seq}.json"
    try:
        lead_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(proc.stdout)
    except OSError as e:
        print(f"gather_exec.py: could not write payload: {e}", file=sys.stderr)

    record = {
        "lead": lead,
        "seq": seq,
        "system": parsed["system"],
        "verb": parsed["verb"],
        "query_id": ns.query_id or parsed["query_id"],
        "params": parsed["params"],
        "body": parsed["body"],
        "raw_command": shlex.join(inner),
        "payload_path": str(payload_path.relative_to(run_dir)),
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

    # Transparent passthrough so the subagent's reasoning is unaffected.
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
