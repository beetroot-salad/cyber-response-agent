#!/usr/bin/env python3
"""Gather SUMMARY capture wrapper — a recorded computation whose output is the value.

Sibling of ``scripts/tools/record_query.py`` for the *summary* step: where
record-query captures an adapter call against a live source, record-summary
captures a deterministic computation over an **already-persisted, read-only**
payload. It runs the snippet, captures stdout, and **that stdout is the reported
value** — gather cannot substitute prose for a snippet that errored or returned
nothing. The ``{lead_id, payload_seq, summary_seq, label, snippet, output}`` row
is appended to a sibling ``summaries.jsonl`` so the value is recorded, auditable,
and re-runnable (the #275 judge can replay it).

    defender-record-summary --lead l-001 --label distinct-srcusers -- \
        jq '[.[].data.srcuser] | unique | length' gather_raw/l-001/0.json

For a multi-tool pipeline, quote the whole pipeline as one argument so the outer
shell does not eat the ``|`` — the wrapper parses and wires it itself:

    defender-record-summary --lead l-001 --label srcip-distribution -- \
        "jq -r '.[].data.srcip' gather_raw/l-001/0.json | sort | uniq -c | sort -rn"

## The gate (honest, deterministic, fail-closed)

This wrapper is the gate, because the inner tool is opaque to a head-based
permission hook (``approve_shim_invocations`` only ever sees the wrapper shim at
the segment head). Enforcement, all here, any doubt → exit 2:

  * **No shell.** The pipeline is split quote-aware on ``|`` and wired with
    ``subprocess`` pipes; the wrapper never hands the string to ``sh -c``. So
    ``>``/``$(...)``/backticks are inert literal argv tokens (the tool chokes on
    them), not redirects or substitutions — they can't fire.
  * **Tool allowlist.** Every pipe segment's head must be a *pure transform* —
    no ``exec``/``system()``/network/file-write (see ``ANALYSIS_TOOLS``). That
    is the property that lets this run unsandboxed; a tool with a scripting
    surface (``awk``/``sqlite3``/``python3``) is the Phase-2 decision, not this.
  * **Read-scope.** Any token that resolves to an *existing* file must live under
    ``{run_dir}/gather_raw/`` — so a snippet cannot read ``/workspace/.env`` or
    anything outside the persisted payloads. Non-file tokens (jq programs, field
    numbers) are unconstrained; they can leak nothing.
  * **Scrubbed env + rlimits.** The inner processes get a minimal env (no
    creds; note ``jq -n env`` would otherwise dump the environment) and CPU /
    address-space caps plus a wall timeout.

Exit code: the pipeline's exit code (first non-zero segment, pipefail-style), or
2 on a wrapper usage / gate error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shlex
import subprocess
import sys
from pathlib import Path

# Mirror record_query.LEAD_ID_RE — the lead id is a path/table key, validate it.
LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")
# A label is a kebab dimension name; keep it tame so it's a clean table key.
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
# A persisted payload path → its seq. The summaries-table FK to a queries row is
# (lead_id, payload_seq); derive payload_seq from the gather_raw/ path the
# snippet reads so the judge can join a summary value back to its exact payload.
_PAYLOAD_RE = re.compile(r"(?:^|/)gather_raw/l-[A-Za-z0-9]+/(\d+)\.json$")

GATHER_DIR = "gather_raw"

# The permitted analysis tools — *pure transforms only*: none has exec/system/
# network/file-write, which is what lets the summary step run without a sandbox.
# jq reshapes JSON; datamash is the statistics keystone; the coreutils filters
# cover distribution/top-N/set-ops. Adding a tool with a scripting surface
# (awk/sed/sqlite3/mlr-DSL/python3) is the Phase-2 sandbox decision — keep this
# list to filters. See defender/docs/gather-verifiable-summary.md.
ANALYSIS_TOOLS = frozenset(
    {"jq", "datamash", "sort", "uniq", "cut", "comm", "join", "wc", "tr",
     "paste", "nl", "head", "tail", "grep"}
)

# The recorded output is the value, and summary outputs are small by design (a
# count, a short list, a timestamp pair). Cap the *recorded* copy defensively so
# a misfired snippet can't bloat the table; the full stdout still passes through.
_OUTPUT_RECORD_MAX = 8192
_SUMMARY_TIMEOUT_S = int(os.environ.get("DEFENDER_SUMMARY_TIMEOUT_SEC", "60"))
# Address-space cap for each inner process (accidental-blowup guard, not an
# adversarial control — the read-scope + no-creds + no-network do the real work).
_SUMMARY_AS_BYTES = int(os.environ.get("DEFENDER_SUMMARY_AS_BYTES", str(2 * 1024**3)))

# Shell operators that must NOT appear unquoted in a segment. They are already
# inert (no shell is ever invoked), but rejecting them gives a clear error
# instead of a confusing "jq: No such file or directory" when the agent meant a
# real redirect/chain. `|` is handled separately as the pipeline splitter.
_BARE_OPS = frozenset(";&<>`")


class GateError(ValueError):
    """A snippet that violates the summary gate (bad tool, escape, malformed)."""


# --------------------------------------------------------------------------
# Parse + gate the inner pipeline (no shell, ever)
# --------------------------------------------------------------------------


def split_pipeline(s: str) -> list[str]:
    """Split a command string on ``|`` *outside quotes* into segment strings.

    Quote-aware so a ``|`` inside a jq program (``.a | .b``) is not a pipe and a
    ``>`` inside ``select(.x > 5)`` is not a redirect. Raises ``GateError`` on an
    unquoted shell operator (``;&<>`` or backtick), an unterminated quote, or an
    empty segment (``a || b`` / leading-or-trailing pipe)."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == "|":
            segments.append("".join(buf))
            buf = []
        elif ch in _BARE_OPS:
            raise GateError(
                f"unquoted shell operator {ch!r} is not allowed — record-summary "
                "runs no shell; use a quoted 'tool ... | tool ...' pipeline of "
                "analysis filters only"
            )
        else:
            buf.append(ch)
    if quote:
        raise GateError("unterminated quote in the summary snippet")
    segments.append("".join(buf))
    out = [seg.strip() for seg in segments]
    if any(not seg for seg in out):
        raise GateError("empty pipeline segment (stray or doubled `|`)")
    return out


def parse_inner(inner: list[str]) -> list[list[str]]:
    """Turn the post-``--`` argv into a list of segment argvs.

    A quoted pipeline arrives as one element (the outer shell kept the ``|``
    inside the quotes); a bare single command arrives pre-tokenized as many
    elements (the outer shell already split it, and no unquoted ``|`` survived).
    Re-join the multi-element form and parse uniformly so both shapes produce the
    same ``[[argv], ...]``."""
    s = inner[0] if len(inner) == 1 else shlex.join(inner)
    return [shlex.split(seg) for seg in split_pipeline(s)]


def gate_tools(segments: list[list[str]]) -> None:
    """Every segment head must be a permitted pure-transform tool."""
    for argv in segments:
        if not argv:
            raise GateError("empty pipeline segment")
        head = Path(argv[0]).name
        if head not in ANALYSIS_TOOLS:
            raise GateError(
                f"tool {head!r} is not a permitted analysis filter; allowed: "
                + ", ".join(sorted(ANALYSIS_TOOLS))
            )


def gate_paths(segments: list[list[str]], run_dir: Path) -> int | None:
    """Reject any token that resolves to an existing file outside
    ``{run_dir}/gather_raw/``; return the payload seq read (FK to the queries
    table), or None.

    Only *existing* files are constrained: a jq program or a field number that
    happens to look path-ish points at nothing and can leak nothing, so it is
    left alone (no false positives on ``.a/.b`` expressions). A relative token is
    resolved against ``run_dir`` (the inner processes run with ``cwd=run_dir``)."""
    gather_root = (run_dir / GATHER_DIR).resolve()
    payload_seq: int | None = None
    for argv in segments:
        for tok in argv:
            m = _PAYLOAD_RE.search(tok)
            if m and payload_seq is None:
                payload_seq = int(m.group(1))
            base = Path(tok)
            candidate = base if base.is_absolute() else (run_dir / base)
            try:
                real = candidate.resolve()
            except OSError:
                continue
            if not real.exists() or real.is_dir():
                continue
            if gather_root not in real.parents and real != gather_root:
                raise GateError(
                    f"read out of scope: {tok!r} resolves to {real} — a summary "
                    f"may only read persisted payloads under {gather_root}"
                )
    return payload_seq


# --------------------------------------------------------------------------
# Run the pipeline (shell-free, env-scrubbed, resource-limited)
# --------------------------------------------------------------------------


def _scrubbed_env() -> dict:
    """Minimal env for the inner processes: enough to find/locale the tools, no
    credentials. `LC_ALL=C` also makes sort/datamash byte-deterministic."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", "/tmp"),
    }


def _apply_limits() -> None:  # pragma: no cover — runs in the child pre-exec
    """CPU + address-space caps for an inner process (accidental-blowup guard)."""
    cpu = _SUMMARY_TIMEOUT_S
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_AS, (_SUMMARY_AS_BYTES, _SUMMARY_AS_BYTES))


def run_pipeline(
    segments: list[list[str]], run_dir: Path, *, timeout: int = _SUMMARY_TIMEOUT_S
) -> tuple[int, str, str]:
    """Wire the segment argvs with pipes (no shell) and run them under a scrubbed
    env + rlimits, cwd=run_dir. Returns ``(rc, stdout, stderr)`` where ``rc`` is
    the first non-zero segment exit (pipefail-style), or 0."""
    env = _scrubbed_env()
    procs: list[subprocess.Popen] = []
    try:
        prev: subprocess.Popen | None = None
        for argv in segments:
            stdin = prev.stdout if prev is not None else subprocess.DEVNULL
            p = subprocess.Popen(
                argv,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(run_dir),
                env=env,
                text=True,
                preexec_fn=_apply_limits,
            )
            if prev is not None and prev.stdout is not None:
                prev.stdout.close()  # let prev see SIGPIPE if we stop reading
            procs.append(p)
            prev = p
    except (FileNotFoundError, PermissionError, OSError) as e:
        for p in procs:
            p.kill()
        return 127, "", f"analysis tool not found: {e}"

    try:
        out, last_err = procs[-1].communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        for p in procs:
            p.kill()
        return 124, "", f"summary pipeline timed out after {timeout}s"

    rc = 0
    errs: list[str] = []
    for p in procs[:-1]:
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
        if p.returncode and not rc:
            rc = p.returncode
        if p.stderr is not None:
            seg_err = p.stderr.read()
            if seg_err:
                errs.append(seg_err)
    if procs[-1].returncode and not rc:
        rc = procs[-1].returncode
    if last_err:
        errs.append(last_err)
    return rc, out, "".join(errs)


# --------------------------------------------------------------------------
# Record + orchestrate
# --------------------------------------------------------------------------


def _next_seq(run_dir: Path, lead: str) -> int:
    """Next per-lead summary seq = rows already recorded for this lead. Counting
    rows (not files) keeps seq monotonic across a failed-output row; mirrors
    record_query._next_seq."""
    log = run_dir / "summaries.jsonl"
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


def _snippet_text(inner: list[str]) -> str:
    """The snippet, verbatim and replayable: a quoted pipeline arrives as one
    element (record it as-is, not re-quoted by shlex.join); a bare command arrives
    pre-tokenized (join it back into a readable line)."""
    return inner[0] if len(inner) == 1 else shlex.join(inner)


def _summary_row(
    lead: str, payload_seq: int | None, seq: int, label: str, tools: list[str],
    snippet: str, raw_output: str, rc: int, *, status: str | None = None,
    batch_key: str | None = None,
) -> dict:
    """One ``summaries.jsonl`` row. ``output`` is defensively capped (the recorded
    copy only). ``status`` overrides the structural floor for a batch row (whose
    value, not the whole stdout, decides empty/ok); ``batch_key`` ties a batch row
    back to its jq object key for replay (`<snippet> | jq '.<batch_key>'`)."""
    recorded = raw_output if len(raw_output) <= _OUTPUT_RECORD_MAX else (
        raw_output[:_OUTPUT_RECORD_MAX] + f"\n…[truncated {len(raw_output) - _OUTPUT_RECORD_MAX} chars]"
    )
    row = {
        "lead_id": lead,
        "payload_seq": payload_seq,
        "summary_seq": seq,
        "label": label,
        "tools": tools,
        "snippet": snippet,
        "output": recorded,
        "exit_code": rc,
        "output_status": status if status is not None else _output_status(rc, raw_output),
    }
    if batch_key is not None:
        row["batch_key"] = batch_key
    return row


def _append_rows(run_dir: Path, records: list[dict]) -> None:
    try:
        log = run_dir / "summaries.jsonl"
        with log.open("a") as fh:  # append is atomic for one short line
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
    except OSError as e:
        print(f"record_summary: could not append record(s): {e}", file=sys.stderr)


def _batch_label(key: str) -> str:
    """Normalize a jq object key to a kebab summaries label (`failed_count` →
    `failed-count`). Raises GateError if it can't be a clean dimension name — the
    same discipline `--label` enforces, applied per object key."""
    label = str(key).strip().lower().replace("_", "-")
    if not LABEL_RE.match(label):
        raise GateError(
            f"batch object key {key!r} is not a clean dimension name (normalized "
            f"{label!r}); use snake_case / kebab identifiers as the jq object keys"
        )
    return label


def capture(
    run_dir: Path, lead: str, label: str, inner: list[str],
    *, timeout: int = _SUMMARY_TIMEOUT_S,
) -> tuple[str, str, dict]:
    """Gate + run a summary snippet over a persisted payload and record it.

    Returns ``(stdout, stderr, record)`` — stdout passes straight through (it is
    the value), and the row is appended to ``summaries.jsonl``. Raises
    ``GateError`` on a malformed lead/label or a snippet the gate rejects (the
    wrapper's preconditions)."""
    if not LEAD_ID_RE.match(lead):
        raise GateError(f"invalid lead id {lead!r} (expected an `l-` row id)")
    if not LABEL_RE.match(label):
        raise GateError(f"invalid label {label!r} (expected a kebab dimension name)")

    segments = parse_inner(inner)
    gate_tools(segments)
    payload_seq = gate_paths(segments, run_dir)

    rc, out, err = run_pipeline(segments, run_dir, timeout=timeout)

    tools = sorted({Path(a[0]).name for a in segments if a})
    record = _summary_row(
        lead, payload_seq, _next_seq(run_dir, lead), label, tools,
        _snippet_text(inner), out, rc,
    )
    _append_rows(run_dir, [record])
    return out, err, record


def capture_batch(
    run_dir: Path, lead: str, inner: list[str], *, timeout: int = _SUMMARY_TIMEOUT_S,
) -> tuple[str, str, list[dict]]:
    """Gate + run ONE summary snippet whose stdout is a JSON object
    ``{dimension: value}``, recording **one row per top-level key** — the batched
    form of ``capture``. Collapses N per-dimension model round-trips into one
    while preserving the one-row-per-dimension table contract: each row keeps its
    own label/output/status, and ``batch_key`` ties it to the jq object key.

    Returns ``(stdout, stderr, records)``. Raises GateError on a bad lead, a gate
    violation, or a non-kebab object key. If the snippet doesn't yield a JSON
    object (error / empty / scalar), one fallback row labelled ``batch`` carries
    the raw stdout — the value is never silently dropped."""
    if not LEAD_ID_RE.match(lead):
        raise GateError(f"invalid lead id {lead!r} (expected an `l-` row id)")

    segments = parse_inner(inner)
    gate_tools(segments)
    payload_seq = gate_paths(segments, run_dir)

    rc, out, err = run_pipeline(segments, run_dir, timeout=timeout)
    snippet = _snippet_text(inner)
    tools = sorted({Path(a[0]).name for a in segments if a})

    obj: dict | None = None
    if rc == 0 and out.strip():
        try:
            parsed = json.loads(out)
            obj = parsed if isinstance(parsed, dict) and parsed else None
        except (json.JSONDecodeError, ValueError):
            obj = None

    base = _next_seq(run_dir, lead)
    records: list[dict] = []
    if obj is not None:
        for i, (key, value) in enumerate(obj.items()):
            label = _batch_label(key)  # may raise GateError → nothing recorded yet
            empty = value in (None, "", [], {})
            value_str = "" if value is None else (
                value if isinstance(value, str) else json.dumps(value, default=str))
            status = "error" if rc else ("empty" if empty else "ok")
            records.append(_summary_row(
                lead, payload_seq, base + i, label, tools, snippet, value_str, rc,
                status=status, batch_key=key))
    else:
        # Not a JSON object (error / empty / scalar) — don't drop the value.
        records.append(_summary_row(
            lead, payload_seq, base, "batch", tools, snippet, out, rc))

    _append_rows(run_dir, records)
    return out, err, records


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1:]


def main(argv: list[str]) -> int:
    wrapper_argv, inner = _split_argv(argv)
    parser = argparse.ArgumentParser(prog="record_summary.py")
    parser.add_argument("--run-dir")
    parser.add_argument("--lead", required=True)
    parser.add_argument("--label", help="single-dimension label (kebab)")
    parser.add_argument(
        "--batch", action="store_true",
        help="the inner snippet outputs a JSON object {dimension: value}; record "
             "one summaries row per key in this single call (collapses the "
             "per-dimension round-trips). Mutually exclusive with --label.",
    )
    try:
        ns = parser.parse_args(wrapper_argv)
    except SystemExit:
        return 2
    if not inner:
        print("record_summary.py: nothing after `--` to execute", file=sys.stderr)
        return 2
    if ns.batch == bool(ns.label):
        print("record_summary.py: pass exactly one of --label (single dimension) "
              "or --batch (a {dimension: value} object)", file=sys.stderr)
        return 2

    run_dir_arg = ns.run_dir or os.environ.get("DEFENDER_RUN_DIR")
    if not run_dir_arg:
        print(
            "record_summary.py: --run-dir not given and DEFENDER_RUN_DIR is unset",
            file=sys.stderr,
        )
        return 2

    try:
        if ns.batch:
            out, err, records = capture_batch(Path(run_dir_arg), ns.lead, inner)
        else:
            out, err, record = capture(Path(run_dir_arg), ns.lead, ns.label, inner)
            records = [record]
    except GateError as e:
        print(f"record_summary.py: {e}", file=sys.stderr)
        return 2

    sys.stdout.write(out)
    sys.stderr.write(err)
    labels = ", ".join(r["label"] for r in records)
    print(
        f"[record_summary] {labels} → summaries.jsonl "
        f"({len(records)} row(s) from seq {records[0]['summary_seq']}, "
        f"status {records[0]['output_status']})",
        file=sys.stderr,
    )
    return records[0]["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
