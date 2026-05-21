#!/usr/bin/env python3
"""Side-by-side score table for plan-only A/B/C/D.

Reads results/<ts>/<arm>-<case>.json and prints a per-case markdown
table comparing leads chosen + retrieval direct cost/latency + PLAN
turn total cost/tokens.

Defaults to the latest results dir under results/.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"


def latest_results_dir() -> Path:
    dirs = sorted([p for p in RESULTS_DIR.iterdir() if p.is_dir()])
    if not dirs:
        sys.exit("no results dirs under results/")
    return dirs[-1]


def load_results(dir_: Path) -> dict:
    """{case: {arm: metrics}}"""
    out: dict = {}
    for f in dir_.glob("*.json"):
        m = json.loads(f.read_text())
        out.setdefault(m["case_id"], {})[m["arm"]] = m
    return out


def format_case(case_id: str, arms: dict) -> str:
    lines = [f"\n## {case_id}\n"]
    arms_present = [a for a in ("a", "b", "c", "d", "e") if a in arms]
    if not arms_present:
        return "\n".join(lines) + "(no results)\n"

    # Header row: arm × leads.
    header = ["metric"] + arms_present
    sep = ["---"] * len(header)
    rows: list[list[str]] = [header, sep]

    def row(label: str, values: list[str]) -> None:
        rows.append([label] + values)

    row("rc",
        [str(arms[a]["rc"]) for a in arms_present])
    row("plan cost (USD)",
        [f"${arms[a]['plan_turn_cost_usd']:.4f}" for a in arms_present])
    row("plan wall-clock (s)",
        [f"{arms[a]['plan_turn_wall_clock_s']:.1f}" for a in arms_present])
    row("main input tok",
        [str(arms[a]['main_input_tokens']) for a in arms_present])
    row("main output tok",
        [str(arms[a]['main_output_tokens']) for a in arms_present])
    row("subagent cost (USD)",
        [f"${arms[a]['subagent_cost_usd']:.4f}" for a in arms_present])
    row("subagent in/out tok",
        [f"{arms[a]['subagent_input_tokens']}/{arms[a]['subagent_output_tokens']}"
         for a in arms_present])
    row("advisory calls",
        [str(len(arms[a]['advisory_calls'])) for a in arms_present])
    row("leads authored",
        [str(len(arms[a]['leads_authored'])) for a in arms_present])

    out = []
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    lines.append("\n".join(out))

    # Lead-name lists per arm (so the reader can compare what was picked).
    lines.append("\n### Leads chosen\n")
    for a in arms_present:
        names = [f"`{lead['name']}`" for lead in arms[a]['leads_authored']]
        lines.append(f"- **arm {a}**: " + (", ".join(names) if names else "_none_"))

    # Advisory call detail.
    lines.append("\n### Advisory retrieval detail\n")
    for a in arms_present:
        calls = arms[a]['advisory_calls']
        if not calls:
            lines.append(f"- **arm {a}**: no advisory call")
            continue
        for i, c in enumerate(calls, 1):
            kind = c['kind']
            if kind == 'bash':
                snippet = str(c['args'].get('command', ''))[:200]
            else:
                snippet = str(c['args'].get('prompt', ''))[:200].replace("\n", " ")
            lines.append(
                f"- **arm {a}** call {i} ({kind}): "
                f"response={c['response_len_chars']} chars, "
                f"event_gap={c['event_gap']}"
            )
            lines.append(f"  - args: `{snippet}…`")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", type=Path, default=None)
    ns = p.parse_args(argv)
    dir_ = ns.dir or latest_results_dir()
    data = load_results(dir_)
    print(f"# plan-only A/B/C/D — results from `{dir_.name}`")
    for case in sorted(data):
        print(format_case(case, data[case]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
