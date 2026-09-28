#!/usr/bin/env python3
"""Run the spec_graph checkers over every committed spec graph, ratcheted.

The checkers (`spec-graph lint | gate | binds | claims`) ship with the spec-flow plugin and
run at authoring time in the write-tests flow; without this gate nothing runs them afterwards,
so a graph can merge with its findings intact.

It is a ratchet rather than a hard gate because the checkers postdate much of the committed
corpus:

- a graph absent from the baseline must be clean — every new graph has to pass all four
  checkers;
- a baselined graph may not gain findings — its recorded count is a ceiling;
- a baselined graph that loses findings just passes; the entry is trimmed on the next
  `--update-baseline`.

Fingerprinting is by (graph, count), never by message text, which legitimately changes when
a rule's wording improves.

Exit: 0 clean, 1 a graph gained findings or a new graph is dirty, 2 the gate could not look
(no graphs found, a checker unavailable, a graph unreadable) — never a silent pass.

Regenerate with `--update-baseline` and annotate the new entries in the PR.
"""
from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CHECKER_DIR = REPO_ROOT / "spec-flow" / "scripts" / "spec_graph"
BASELINE_PATH = Path(__file__).resolve().parent / "lint_spec_graph_baseline.json"
LABEL = "lint_spec_graph"
HEADER = (
    "Per-graph finding ceilings for the spec_graph checkers (lint/gate/binds/claims). "
    "A graph absent from this file must be CLEAN; a listed graph may not gain findings. "
    "Value format: '<count> — <annotation>'. Regenerate with "
    "`python scripts/lint/lint_spec_graph.py --update-baseline` and annotate new entries."
)


class GateBlind(Exception):
    """The gate could not look — exit 2, never a clean 0."""


def _load_checkers() -> dict:
    """Import the plugin's checkers. They use implicit-relative imports (`import _cli`), so
    their own directory goes on the path, as their `spec-graph` wrapper does. A missing plugin
    is blindness, not cleanliness."""
    if not CHECKER_DIR.is_dir():
        raise GateBlind(f"spec_graph checkers not found at {CHECKER_DIR}")
    sys.path.insert(0, str(CHECKER_DIR))
    try:
        import check_binds
        import check_claims
        import check_gate
        import check_lint
        import _cli
        import _config
    except ImportError as exc:  # a checker that cannot load cannot certify anything
        raise GateBlind(f"cannot import the spec_graph checkers: {exc}") from exc
    return {
        "binds": check_binds, "claims": check_claims, "gate": check_gate,
        "lint": check_lint, "cli": _cli, "config": _config,
    }


def _findings_for(mods: dict, path: Path, cfg: dict) -> list[str]:
    """Every checker's findings for one graph, tagged. Each checker owns its own parse, so a
    graph one of them cannot read raises out of here as blindness rather than counting 0."""
    graph = mods["cli"].load_graph(path)
    out = [f"lint: {f}" for f in mods["lint"].check(path)]
    out += [f"gate: {f}" for f in mods["gate"].check(path)[0]]
    out += [f"binds: {f}" for f in mods["binds"].check(path, cfg)]
    out += [f"claims: {f}" for f in mods["claims"].check(path, graph)]
    out += [f"claims: {f}" for f in mods["claims"].check_typing(path, graph)]
    # Every pass check_claims' own main() runs must be listed here: passes are enumerated by
    # name, not discovered, so a pass added to the checker and not here never runs in CI.
    out += [f"claims: {f}" for f in mods["claims"].check_alphabet(path, graph)]
    out += [f"claims: {f}" for f in mods["claims"].check_spend_points(path, graph)]
    return out


def _scan() -> dict[str, list[str]]:
    mods = _load_checkers()
    cfg = mods["config"].load(None)
    paths = mods["config"].artifacts(cfg)
    if not paths:
        raise GateBlind("no spec_graph_*.yaml found — nothing to gate is not the same as clean")
    results: dict[str, list[str]] = {}
    for p in sorted(paths):
        key = str(p.resolve().relative_to(REPO_ROOT))
        try:
            results[key] = _findings_for(mods, p, cfg)
        except Exception as exc:  # noqa: BLE001 — any failure to read is blindness
            raise GateBlind(f"cannot check {key}: {exc.__class__.__name__}: {exc}") from exc
    return results


def _load_baseline(path: Path) -> dict[str, tuple[int, str]]:
    if not path.exists():
        return {}
    try:
        entries = json.loads(path.read_text(encoding="utf-8")).get("entries", {})
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, tuple[int, str]] = {}
    for key, value in (entries or {}).items():
        m = re.match(r"\s*(\d+)", str(value))
        # An unparseable ceiling is treated as 0 — a malformed baseline must tighten the
        # gate, never loosen it into a silent allow-anything.
        out[key] = (int(m.group(1)) if m else 0, str(value))
    return out


def _write_baseline(
    results: dict[str, list[str]], baseline: dict[str, tuple[int, str]], path: Path
) -> None:
    entries = {}
    for key, findings in sorted(results.items()):
        if not findings:
            continue
        note = baseline.get(key, (0, ""))[1]
        annotation = note.split("—", 1)[1].strip() if "—" in note else ""
        entries[key] = f"{len(findings)} — {annotation}" if annotation else f"{len(findings)} — "
    path.write_text(
        json.dumps({"//": HEADER, "entries": entries}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[{LABEL}] baseline updated: {len(entries)} graph(s) with findings.")


def main(
    argv: list[str] | None = None,
    *,
    results: dict[str, list[str]] | None = None,
    baseline_path: Path | None = None,
    scan: Callable[[], dict[str, list[str]]] | None = None,
) -> int:
    # DI seams: the ratchet's arms are decided by (findings, baseline), and `scan` lets a
    # test drive the blindness arm without monkeypatching this module.
    args = sys.argv[1:] if argv is None else argv
    baseline_file = BASELINE_PATH if baseline_path is None else baseline_path
    scanner = _scan if scan is None else scan
    try:
        results = scanner() if results is None else results
    except GateBlind as exc:
        print(f"{LABEL}: {exc}", file=sys.stderr)
        return 2
    baseline = _load_baseline(baseline_file)

    if "--update-baseline" in args:
        _write_baseline(results, baseline, baseline_file)
        return 0

    regressions: list[str] = []
    for key, findings in sorted(results.items()):
        ceiling = baseline.get(key, (0, ""))[0]
        if len(findings) <= ceiling:
            continue
        listed = "" if key in baseline else " (not in the baseline — a new graph must be clean)"
        regressions.append(
            f"  {key}: {len(findings)} finding(s), ceiling {ceiling}{listed}"
        )
        regressions += [f"      {f}" for f in findings[:12]]
        if len(findings) > 12:
            regressions.append(f"      … and {len(findings) - 12} more")

    total = sum(len(f) for f in results.values())
    over = [k for k, v in results.items() if len(v) > baseline.get(k, (0, ""))[0]]
    if regressions:
        print(f"\n[{LABEL}] spec graph(s) over their finding ceiling:")
        print("\n".join(regressions))
        print(
            "\nFix the graph (retype the claim and run its probe, bind the obligation, record "
            f"the gate entry) — or, if the finding is a deliberate accept, run "
            f"`python scripts/lint/{LABEL}.py --update-baseline` and annotate it."
        )
    print(f"\n[{LABEL}] {total} finding(s) over {len(results)} graph(s): "
          f"{len(baseline)} baselined, {len(over)} over ceiling.")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
