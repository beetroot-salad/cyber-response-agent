#!/usr/bin/env python3
"""Gather capture wrapper — deterministic record of an executed query.

The gather subagent invokes this instead of redirecting a system-CLI's
stdout itself:

    record_query.py --run-dir {R} --lead {L} \
        --system stub-cmdb --query-id stub-cmdb.host-lookup -- \
        python3 .../cmdb_cli.py host-lookup web-1 --raw

It runs the inner command, captures stdout to a canonical per-lead path,
and appends an executed-query record (the queries table) to
``{R}/executed_queries.jsonl``. The inner command's stdout/stderr/exit
code pass straight through, so the subagent still sees the result for its
reasoning, and the wrapper reports the raw payload path it wrote on stderr.

It retires the two brittle model-authored steps it replaces: the redirect
to a model-chosen ``gather_raw/{lead_id}.json`` (Bug #1: filename drift →
silent drop) and the post-hoc, free-floating ``queries[]`` sidecar id
(Bug #2: mislabel → catalog miss). Both `--system` and `--query-id` come
from the dispatch contract — `system` is the harness-injected lead system,
`query_id` is the catalog template id the subagent bound (`{system}.{verb}`,
or ``ad-hoc``). They are recorded *at execution time*, bound to the actual
command and its captured payload, rather than reconstructed from a fragile
per-CLI argv grammar — so the wrapper stays portable across whatever system
CLIs are onboarded, with no hardcoded system/verb roster.

The per-lead group id ``L`` comes from the dispatch (the ``:L`` invlang row
id, e.g. ``l-001``; see ``hooks/record_lead.py``); it is the address
namespace for this lead's payloads and the queries-table FK (``lead_id``).

Exit code: the inner command's exit code (or 2 on wrapper usage error).
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

# A lead_id is the `:L` invlang row id used verbatim as the queries-table FK
# and a gather_raw/ path segment. Grammar mirrors hooks/record_lead.py and the
# invlang lead-id grammar (defender/skills/invlang/SKILL.md) — keep in sync.
LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")

# Size safety: a query that over-returns (server-side filter didn't bind,
# broad window, high-cardinality index) would otherwise dump its whole
# stdout into the subagent's context — the 6000-hit / 500KB flood that
# drives hand-counting. Above this byte ceiling the pass-through is
# replaced by a count + samples + a pointer to the on-disk payload and a
# nudge to filter that file with jq/grep instead. The full payload is
# always persisted regardless; only the in-context view is capped.
PASSTHROUGH_MAX_BYTES = int(os.environ.get("DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES", "65536"))
PASSTHROUGH_SAMPLE_COUNT = 3
_SAMPLE_MAX_CHARS = 600
_RECORD_KEYS = ("hits", "results", "events", "records", "data", "rows")


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


def _find_records(stdout: str):
    """Best-effort record array for sampling. Returns None if stdout isn't
    JSON or holds no obvious list (callers fall back to char truncation)."""
    try:
        obj = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in _RECORD_KEYS:
            if isinstance(obj.get(key), list):
                return obj[key]
        lists = [v for v in obj.values() if isinstance(v, list)]
        if lists:
            return max(lists, key=len)
    return None


def build_truncated_view(stdout: str, payload_rel: str | None, run_dir: Path) -> str:
    """Replace an oversized pass-through with count + samples + a nudge to
    filter the persisted payload with code."""
    size = len(stdout)
    records = _find_records(stdout)
    lines: list[str] = []
    if records is not None:
        lines.append(f"[record_query] {len(records)} records, {size} bytes — pass-through truncated")
        for idx, rec in enumerate(records[:PASSTHROUGH_SAMPLE_COUNT]):
            sample = json.dumps(rec, default=str)
            if len(sample) > _SAMPLE_MAX_CHARS:
                sample = sample[:_SAMPLE_MAX_CHARS] + "…"
            lines.append(f"sample[{idx}]: {sample}")
    else:
        lines.append(f"[record_query] {size} bytes — pass-through truncated")
        lines.append(stdout[:_SAMPLE_MAX_CHARS * PASSTHROUGH_SAMPLE_COUNT] + "…")
    if payload_rel:
        abs_payload = run_dir / payload_rel
        lines.append(f"full payload: {abs_payload}")
        lines.append(
            "→ payload is large; do not rely on this truncated view or count the "
            "samples. Filter the full payload on disk (jq, grep, the Grep tool), e.g.:\n"
            f"  jq '[.hits[] | select(.message | test(\"<substr>\"))] | length' {abs_payload}"
        )
    return "\n".join(lines) + "\n"


def _next_seq(run_dir: Path, lead: str) -> int:
    """Next per-lead seq = number of rows already recorded for this lead in the
    queries table.

    Counting rows (not payload files on disk) keeps seq monotonic even when a
    payload write failed: that query still appends a row with ``payload_path:
    null``, so the next query won't reuse the seq and collide on
    ``(lead_id, seq)``.
    """
    log = run_dir / "executed_queries.jsonl"
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


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1 :]


def main(argv: list[str]) -> int:
    wrapper_argv, inner = _split_argv(argv)
    parser = argparse.ArgumentParser(prog="record_query.py")
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
        print("record_query.py: nothing after `--` to execute", file=sys.stderr)
        return 2

    run_dir = Path(ns.run_dir)
    lead = ns.lead
    # Validate the FK before it becomes a path segment: an unvalidated --lead
    # (traversal / absolute) would escape gather_raw/ and break the join.
    # Mirrors hooks/record_lead.py's claim-side guard.
    if not LEAD_ID_RE.match(lead):
        print(
            f"record_query.py: invalid --lead {lead!r} (expected an `l-` row id)",
            file=sys.stderr,
        )
        return 2
    query_id = ns.query_id
    verb = query_id.split(".", 1)[1] if "." in query_id else query_id

    proc = subprocess.run(inner, capture_output=True, text=True)

    lead_dir = run_dir / "gather_raw" / lead
    seq = _next_seq(run_dir, lead)
    payload_path = lead_dir / f"{seq}.json"
    payload_rel = None
    try:
        lead_dir.mkdir(parents=True, exist_ok=True)
        payload_path.write_text(proc.stdout)
        payload_rel = str(payload_path.relative_to(run_dir))
    except OSError as e:
        print(f"record_query.py: could not write payload: {e}", file=sys.stderr)

    record = {
        "lead_id": lead,
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
        print(f"record_query.py: could not append record: {e}", file=sys.stderr)

    # Pass the result through for the subagent's reasoning, but cap the
    # in-context view: an oversized payload is replaced by count + samples +
    # a nudge to filter the persisted file with code (the full payload is
    # already on disk at payload_path). The §3.5 data-source-debug protocol
    # and §filter-with-code both point at that path.
    if proc.returncode == 0 and len(proc.stdout) > PASSTHROUGH_MAX_BYTES:
        sys.stdout.write(build_truncated_view(proc.stdout, payload_rel, run_dir))
    else:
        sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if payload_rel:
        print(f"[record_query] raw payload: {payload_rel}", file=sys.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
