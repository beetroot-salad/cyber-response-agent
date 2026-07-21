#!/usr/bin/env python3
"""Extract per-premise ground truth from a run's frontier chain.

Buckets every canonical premise (test_* def in 40-premise-file.py) by the
final 45-dispositions.md section its name appears under, records phase-B
`# fork:` pre-flags (excluded from metrics by the plan), and validates the
extracted counts against the frontier's own frontmatter inventory.
"""
import json
import re
import sys
from pathlib import Path

# Section-heading → bucket, per observed formats (631 and 672 differ).
BUCKET_PATTERNS = [
    (r"^## Consensus\b", "consensus"),
    (r"^## Dispositions — consensus", "consensus"),
    (r"^## Forks and silent branches\b", "fork"),
    (r"^## Dispositions — forks\b", "fork"),
    (r"^## Dispositions — silent branch\b", "fork"),  # routes as fork
    (r"^## Drops\b", "drop"),
    (r"^## Dispositions — drops\b", "drop"),
    # Everything else (Digest, Red flags, Cold pass narrative, Conservation)
    (r"^## ", None),
]


def bucket_of(line: str):
    for pat, bucket in BUCKET_PATTERNS:
        if re.match(pat, line):
            return bucket, True
    return None, False


def main(frontiers_dir: str, out_path: str):
    fdir = Path(frontiers_dir)
    premise_src = (fdir / "40-premise-file.py").read_text()

    # Canonical premises + phase-B pre-flags (a `# fork:` comment in the body).
    names, preflagged = [], set()
    for m in re.finditer(
        r"^def (test_\w+)\(.*?\):\n(.*?)(?=^def test_|\Z)",
        premise_src, re.M | re.S,
    ):
        names.append(m.group(1))
        if re.search(r"#\s*fork\b", m.group(2), re.I):
            preflagged.add(m.group(1))

    # Bucket by final-dispositions section. Consensus-section assignment wins
    # over a fork-section mention: the consensus section lists only the final
    # post-cold-pass set (validated: counts match the declared inventory
    # exactly on both fixtures), while fork clusters cross-reference consensus
    # premises in their narrative.
    disp = (fdir / "45-dispositions.md").read_text().splitlines()
    truth = {}
    current = None
    for line in disp:
        b, is_heading = bucket_of(line)
        if is_heading:
            current = b
            continue
        if current is None:
            continue
        for name in re.findall(r"\btest_\w+", line):
            if name not in names:
                continue
            prev = truth.get(name)
            if prev == "consensus":
                continue  # consensus assignment sticky (see comment above)
            if prev == "fork" and current != "consensus":
                continue  # fork sticky except against an explicit consensus row
            truth[name] = current

    counts = {b: sum(1 for v in truth.values() if v == b)
              for b in ("consensus", "fork", "drop")}
    declared = {}
    fm = re.search(r"^inventory:\s*(\{.*\}|\n(?:\s+.*\n)+)",
                   (fdir / "45-dispositions.md").read_text(), re.M)
    if fm:
        declared = {k: int(v) for k, v in
                    re.findall(r"(consensus|forks|silent_branches|drops):\s*(\d+)",
                               fm.group(0))}

    out = {
        "frontiers_dir": str(fdir),
        "premises": names,
        "preflagged_forks": sorted(preflagged),
        "truth": truth,
        "unmatched": sorted(set(names) - set(truth)),
        "extracted_counts": counts,
        "declared_inventory": declared,
    }
    Path(out_path).write_text(json.dumps(out, indent=2))
    print(f"premises={len(names)} preflagged={len(preflagged)} "
          f"extracted={counts} declared={declared} "
          f"unmatched={len(out['unmatched'])}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
