"""Step zero: extract every defender-sql call a gather dispatch made, with what the model saw.

Reads the wire logs of the survey runs (no model calls) and writes:
  results/step0_calls.json  — one record per defender-sql bash call
  results/step0_calls.txt   — the same, human-readable, grouped per dispatch

Usage: /workspace/defender/.venv/bin/python step0_extract.py
"""
from __future__ import annotations

import ast
import glob
import json
import os
import re

ROOT = "/workspace/experiments"
OUT = os.path.join(ROOT, "sql-time-contract", "results")
RUN_GLOBS = ["gather-flash-port/runs/*/", "glm53-container-attribution/runs/*/"]

# A call "touches a time" if its SQL names a time-ish field/function, or its stdout carries an
# ISO-ish timestamp (projected times the model then read).
TIME_SQL = re.compile(
    r"@timestamp|timestamp|falco\.time|\btime\b|first_seen|last_seen|window_start|window_end|"
    r"created|updated|captured_at|_at\b|date|now\(\)|interval|epoch|strptime|strftime|"
    r"::timestamp|min\(v\[|max\(v\[",
    re.I,
)
TIME_OUT = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def parse(m):
    if isinstance(m, str):
        try:
            return json.loads(m)
        except Exception:
            return ast.literal_eval(m)
    return m


def args_of(part):
    a = part.get("args")
    if isinstance(a, str):
        try:
            return json.loads(a)
        except Exception:
            return {"command": a}
    return a or {}


def extract_sql(command: str) -> str | None:
    """The SQL argument of the defender-sql invocation (best effort)."""
    i = command.find("defender-sql")
    if i < 0:
        return None
    rest = command[i + len("defender-sql"):].lstrip()
    if rest[:1] in ("'", '"'):
        q = rest[0]
        j = 1
        buf = []
        while j < len(rest):
            c = rest[j]
            if q == '"' and c == "\\" and j + 1 < len(rest):
                buf.append(rest[j + 1])
                j += 2
                continue
            if c == q:
                break
            buf.append(c)
            j += 1
        return "".join(buf)
    return rest


def main() -> None:
    records = []
    for pat in RUN_GLOBS:
        for run_dir in sorted(glob.glob(os.path.join(ROOT, pat))):
            wl = os.path.join(run_dir, "wire_logs", "llm_requests.jsonl")
            if not os.path.exists(wl):
                continue
            prov = json.load(open(os.path.join(run_dir, "provenance.json")))
            calls = {}   # (agent, call_id) -> record
            returns = {}  # (agent, call_id) -> content
            order = []
            for line in open(wl):
                o = json.loads(line)
                agent = o["agent_id"]
                if not agent.startswith("gather"):
                    continue
                m = parse(o["message"])
                for p in m.get("parts", []):
                    pk = p.get("part_kind")
                    if pk == "tool-call" and o["kind"] == "response" and p.get("tool_name") == "bash":
                        cmd = args_of(p).get("command", "")
                        if "defender-sql" not in cmd:
                            continue
                        key = (agent, p.get("tool_call_id"))
                        if key in calls:
                            continue
                        calls[key] = {
                            "run": os.path.basename(run_dir.rstrip("/")),
                            "experiment": pat.split("/")[0],
                            "agent": agent,
                            "lead": agent.split(":", 1)[1],
                            "model": o.get("model"),
                            "commit": prov.get("commit"),
                            "seq": o["seq"],
                            "call_id": p.get("tool_call_id"),
                            "command": cmd,
                            "sql": extract_sql(cmd),
                        }
                        order.append(key)
                    elif pk in ("tool-return", "retry-prompt") and o["kind"] == "request":
                        key = (agent, p.get("tool_call_id"))
                        if key not in returns:
                            c = p.get("content")
                            c = c if isinstance(c, str) else json.dumps(c)
                            returns[key] = ("[retry-prompt] " + c) if pk == "retry-prompt" else c
            for key in order:
                r = calls[key]
                out = returns.get(key, "")
                r["result"] = out
                mm = re.search(r"^exit=(\d+)", out or "", re.M)
                r["exit"] = int(mm.group(1)) if mm else None
                r["time_sql"] = bool(TIME_SQL.search(r["sql"] or r["command"]))
                r["time_out"] = bool(TIME_OUT.search(out or ""))
                r["time"] = r["time_sql"] or r["time_out"]
                r["traceback"] = "Traceback" in (out or "")
                # What the model actually got back. `2>&1 | head` and `|| fallback` hide the
                # exit code, so a query error is also recognised by its stderr text in stdout.
                if not out:
                    r["outcome"] = "no-result (dispatch ended)"
                elif out.startswith("[retry-prompt]"):
                    r["outcome"] = "blocked by bash surface"
                elif "query error" in out or r["exit"] not in (0, None):
                    r["outcome"] = "sql error"
                else:
                    r["outcome"] = "ok"
                r["precedence_error"] = "Failed to cast value to numerical" in out
                records.append(r)
    os.makedirs(OUT, exist_ok=True)
    json.dump(records, open(os.path.join(OUT, "step0_calls.json"), "w"), indent=1)
    with open(os.path.join(OUT, "step0_calls.txt"), "w") as fh:
        cur = None
        for r in records:
            d = (r["run"], r["agent"])
            if d != cur:
                cur = d
                fh.write(f"\n\n######## {r['experiment']}/{r['run']} {r['agent']} {r['model']} {r['commit'][:8]}\n")
            fh.write(f"\n=== seq {r['seq']} {r['call_id']} exit={r['exit']} time={r['time']}"
                     f" tb={r['traceback']}\n$ {r['command']}\n--- result ---\n{r['result'][:3000]}\n")
    # dispatch summary
    disp = {}
    for r in records:
        d = disp.setdefault((r["experiment"], r["run"], r["lead"]),
                            {"model": r["model"].split("/")[-1], "commit": r["commit"][:8],
                             "n": 0, "t": 0, "t_ok": 0, "sql_err": 0, "blocked": 0,
                             "no_result": 0, "precedence": 0, "tb": 0})
        d["n"] += 1
        d["t"] += r["time"]
        d["t_ok"] += r["time"] and r["outcome"] == "ok"
        d["sql_err"] += r["outcome"] == "sql error"
        d["blocked"] += r["outcome"] == "blocked by bash surface"
        d["no_result"] += r["outcome"].startswith("no-result")
        d["precedence"] += r["precedence_error"]
        d["tb"] += r["traceback"]
    for k, v in disp.items():
        print(*k, v)
    print(len(disp), "dispatches", len(records), "calls",
          sum(r["time"] for r in records), "time calls")


if __name__ == "__main__":
    main()
