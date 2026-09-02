#!/usr/bin/env python3
"""EXPERIMENTAL #986 (invlang-clerk-986) offline dry-run for the clerk prompt.

Walks a PAST run's investigation.md (authored the ordinary way — invlang rows
interleaved with prose), strips the fenced invlang blocks to leave the surviving prose,
and for each phase in document order feeds (document-so-far-as-rebuilt, that phase's
prose, that phase's gather summaries) to the clerk exactly as the `record` tool would —
including the up-to-3-round refusal retry. This is how the clerk prompt gets exercised
against a real model before the live `record` tool / playground run is up.

Usage:
    defender/.venv/bin/python experiments/invlang-clerk-986/clerk_dryrun.py <past_run_dir>

Needs FIREWORKS_API_KEY in the environment (source /workspace/.env).
Writes experiments/invlang-clerk-986/dryrun/<run_id>/{report.txt,investigation.clerk.md,wire_log.jsonl}.
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from defender._artifact_schema import validate_investigation  # noqa: E402
from defender._frontmatter import strip_frontmatter  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.runtime import orient as orient_mod  # noqa: E402
from defender.runtime.clerk import ClerkCaller  # noqa: E402
from defender.runtime.driver import build_agent_core  # noqa: E402

FENCE_RE = re.compile(r"```invlang\s*\n.*?```\n?", re.DOTALL)
FENCE_CAPTURE_RE = re.compile(r"```invlang\s*\n(.*?)```", re.DOTALL)
PHASE_RE = re.compile(r"^## .+$", re.MULTILINE)
LEAD_ID_RE = re.compile(r"\bl-\d+\b")
_MAX_ROUNDS = 3


def split_phases(text: str) -> list[tuple[str, str]]:
    matches = list(PHASE_RE.finditer(text))
    phases = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        phases.append((m.group(0).strip(), text[start:end]))
    return phases


def strip_fences(body: str) -> str:
    return FENCE_RE.sub("", body).strip()


def split_clerk_output(raw: str) -> tuple[str, list[str]]:
    """Rewrap (never strip) the clerk's own fences — a bare, unfenced blob of rows is
    refused as "non-invlang surface" by the same validator `record` uses in production."""
    blocks = FENCE_CAPTURE_RE.findall(raw)
    rows = "\n\n".join(f"```invlang\n{b.strip(chr(10))}\n```" for b in blocks)
    idx = raw.find("GAPS:")
    gaps: list[str] = []
    if idx != -1:
        section = raw[idx + len("GAPS:"):]
        first_line, _, rest = section.partition("\n")
        inline = first_line.strip()
        if inline and inline.lower() != "none":
            gaps.append(inline)
        for line in rest.splitlines():
            line = line.strip()
            if line.startswith(("-", "*")):
                item = line.lstrip("-* ").strip()
                if item and item.lower() != "none":
                    gaps.append(item)
    return rows, gaps


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: clerk_dryrun.py <past_run_dir>", file=sys.stderr)
        raise SystemExit(2)
    run_dir = Path(sys.argv[1]).resolve()
    inv = (run_dir / "investigation.md").read_text(encoding="utf-8")
    phases = split_phases(inv)

    defender_dir = REPO_ROOT / "defender"
    grammar = strip_frontmatter(
        (defender_dir / "skills" / "invlang" / "SKILL.md").read_text(encoding="utf-8")
    ).strip()
    catalog = orient_mod._catalog()
    grammar_catalog = (
        "## invlang grammar\n\n" + grammar + "\n\n## invlang catalog\n\n" + catalog
    )

    out_dir = REPO_ROOT / "experiments" / "invlang-clerk-986" / "dryrun" / run_dir.name
    out_dir.mkdir(parents=True, exist_ok=True)

    clerk_instructions = (
        Path(__file__).parent / "variants" / "C-clerk" / "CLERK.md"
    ).read_text(encoding="utf-8")
    logger = observe.RequestLogger(out_dir / "wire_log.jsonl")
    caller = ClerkCaller(
        run_dir, defender_dir, logger, clerk_instructions, build=build_agent_core,
    )

    rebuilt = ""
    summary_seen: set[str] = set()
    report_lines: list[str] = []
    gather_dir = run_dir / "gather_summaries"
    rounds_dir = out_dir / "rounds"
    rounds_dir.mkdir(exist_ok=True)

    for phase_idx, (header, body) in enumerate(phases):
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", header).strip("-")[:60]
        print(f"--- {header} ---", flush=True)
        if "harness-authored" in header:
            # lead-0 is seeded by the harness before MAIN's first turn, in both arms — it
            # is not something MAIN (or the clerk) ever produces from prose. Carry its
            # already-valid fenced block through unchanged rather than asking the clerk to
            # reverse-engineer a row shape from a one-line header with no prose behind it.
            fences = FENCE_CAPTURE_RE.findall(body)
            block = "\n\n".join(f"```invlang\n{b.strip(chr(10))}\n```" for b in fences)
            rebuilt = rebuilt + ("\n\n" if rebuilt else "") + block
            report_lines.append(f"{header}: harness-authored, carried through unchanged")
            continue
        prose = strip_fences(body)
        summaries: list[tuple[str, str]] = []
        if gather_dir.is_dir():
            for lid in sorted(set(LEAD_ID_RE.findall(body))):
                p = gather_dir / f"{lid}.md"
                if p.is_file() and p.name not in summary_seen:
                    summary_seen.add(p.name)
                    summaries.append((p.name, p.read_text(encoding="utf-8")))

        refusal: str | None = None
        refusal_kinds: list[str] = []
        rows_text = ""
        gaps: list[str] = []
        committed = False
        rounds = 0

        for round_n in range(1, _MAX_ROUNDS + 1):
            rounds = round_n
            parts = [grammar_catalog]
            parts.append("## investigation.md so far\n\n" + (rebuilt.strip() or "(empty)"))
            parts.append("## prose just recorded — compile this into rows\n\n" + prose)
            if summaries and round_n == 1:
                rendered = "\n\n".join(f"### {n}\n\n{t}" for n, t in summaries)
                parts.append(
                    "## gather summaries modified since the last record() call\n\n" + rendered
                )
            if refusal:
                parts.append(
                    "## the validator refused your last attempt — read this and fix it\n\n"
                    + refusal
                )
            parts.append(
                "Return ONLY: one or more fenced ```invlang blocks recording what the "
                "prose/summaries assert, then a line `GAPS:` followed by a bulleted list "
                "of what could not be grounded in a row — or `GAPS: none`."
            )
            prompt = "\n\n".join(parts)
            try:
                raw = asyncio.run(caller.call(prompt))
            except Exception as e:  # noqa: BLE001 — a dry-run round fault ends this phase, not the script
                refusal = f"clerk call raised {e!r}"
                refusal_kinds.append(refusal[:200])
                print(f"    round {round_n}: EXCEPTION {e!r}", flush=True)
                continue
            (rounds_dir / f"{phase_idx:02d}-{slug}-r{round_n}-raw.txt").write_text(
                raw, encoding="utf-8"
            )
            rows_text, gaps = split_clerk_output(raw)
            print(
                f"    round {round_n}: rows_chars={len(rows_text)} gaps={len(gaps)}",
                flush=True,
            )
            if not rows_text.strip():
                committed = True
                break
            candidate = rebuilt + ("\n\n" if rebuilt else "") + rows_text
            reason = validate_investigation(candidate, rebuilt if rebuilt else None)
            if reason is None:
                rebuilt = candidate
                committed = True
                break
            (rounds_dir / f"{phase_idx:02d}-{slug}-r{round_n}-refusal.txt").write_text(
                reason, encoding="utf-8"
            )
            refusal = reason
            refusal_kinds.append(reason[:200].replace("\n", " "))

        report_lines.append(
            f"{header}: rounds={rounds} committed={committed} gaps={len(gaps)} "
            f"prose_chars={len(prose)} rows_chars={len(rows_text)}"
        )
        for g in gaps:
            report_lines.append(f"    gap: {g}")
        if not committed:
            for rk in refusal_kinds:
                report_lines.append(f"    refusal: {rk}")
        # Written after EVERY phase, not just at the end — an unforeseen crash mid-run
        # still leaves the report and rebuilt document as far as this dry-run got.
        (out_dir / "investigation.clerk.md").write_text(rebuilt, encoding="utf-8")
        (out_dir / "report.txt").write_text("\n".join(report_lines), encoding="utf-8")

    report = "\n".join(report_lines)
    print(report)
    logger.close()


if __name__ == "__main__":
    main()
