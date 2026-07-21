from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

_EVALS_DIR = Path(__file__).resolve().parent
if str(_EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALS_DIR))
_REPO_ROOT = _EVALS_DIR.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from defender._io import append_jsonl  # noqa: E402
from _secondary_config import CATCH_OUTCOMES, SKIP_OUTCOME  # noqa: E402
from _pipeline import AlertResult  # noqa: E402



@dataclass
class SecondarySummary:
    current_generation: int | None
    pinned_generation: int | None
    pinned_sha: str | None
    pinned_model: str | None
    k: int
    replay_incompatible_reason: str | None = None
    eligible: int = 0
    results: list[AlertResult] = field(default_factory=list)

    @property
    def executed(self) -> list[AlertResult]:
        return [r for r in self.results if r.status == "executed"]

    @property
    def not_executed(self) -> list[AlertResult]:
        return [r for r in self.results if r.status == "not_executed"]

    @property
    def failed(self) -> list[AlertResult]:
        return [r for r in self.results if r.status == "failed"]

    @property
    def outcome_counts(self) -> dict[str, int]:
        counts = {o: 0 for o in CATCH_OUTCOMES | {SKIP_OUTCOME}}
        for r in self.executed:
            if r.judge_outcome in counts:
                counts[r.judge_outcome] += 1
        return counts

    def catch_rate(self) -> tuple[int, int]:
        counts = self.outcome_counts
        denom = sum(counts[o] for o in CATCH_OUTCOMES)
        caught = counts["caught"]
        return caught, denom

    def to_index_row(self) -> dict:
        caught, denom = self.catch_rate()
        return {
            "current_generation": self.current_generation,
            "pinned_generation": self.pinned_generation,
            "pinned_sha": self.pinned_sha,
            "pinned_model": self.pinned_model,
            "k": self.k,
            "eligible": self.eligible,
            "executed": len(self.executed),
            "skip_passthrough": self.outcome_counts.get(SKIP_OUTCOME, 0),
            "failed": len(self.failed),
            "caught": caught,
            "catch_denominator": denom,
            "catch_rate": (caught / denom) if denom else None,
            "replay_incompatible_reason": self.replay_incompatible_reason,
        }


def format_summary_md(s: SecondarySummary) -> str:
    out: list[str] = []
    out.append(f"# Secondary metric — generation {s.current_generation}")
    out.append("")
    if s.replay_incompatible_reason is not None:
        out.append(f"**replay-incompatible:** {s.replay_incompatible_reason}")
        out.append("")
        out.append(f"current generation: {s.current_generation}")
        out.append(f"k: {s.k}")
        return "\n".join(out) + "\n"

    counts = s.outcome_counts
    caught, denom = s.catch_rate()
    rate = f"{caught}/{denom} = {caught/denom:.1%}" if denom else "n/a (0 executed)"
    out.append(f"pinned generation: {s.pinned_generation} "
               f"(sha {s.pinned_sha[:8] if s.pinned_sha else '?'}, "
               f"model {s.pinned_model})")
    out.append(f"k: {s.k}")
    out.append("")
    out.append(f"eligible: {s.eligible}")
    out.append(f"executed: {len(s.executed)}")
    out.append(f"not_executed (false escalations): {len(s.not_executed)}")
    out.append(f"failed: {len(s.failed)}")
    out.append(f"skip_passthrough: {counts[SKIP_OUTCOME]}")
    out.append("")
    out.append(f"**catch rate (executed, ex-skip): {rate}**")
    for o in ("caught", "survived", "incoherent", "undecidable"):
        out.append(f"  {o}: {counts[o]}")
    out.append("")
    out.append("## Per-alert detail")
    for r in s.results:
        line = f"- {r.slug} (gt={r.ground_truth}): status={r.status}"
        if r.head_disposition:
            line += f" head_disp={r.head_disposition}"
        if r.judge_outcome:
            line += f" outcome={r.judge_outcome}"
        if r.error:
            line += f" error={r.error}"
        out.append(line)
    out.append("")
    out.append("## Interpretation")
    out.append("")
    out.append(
        "Primary plateau + this secondary climbing across consecutive "
        "checkpoints is the divergence signal — defender gaining "
        "curriculum-fit without target-fit. A single point is not a "
        "verdict; see design doc §Plateau detection for the "
        "3-checkpoint slope rule and bootstrap-CI gating."
    )
    return "\n".join(out) + "\n"


def write_summary(summary: SecondarySummary, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / f"gen-{summary.current_generation}.summary.md"
    md.write_text(format_summary_md(summary), encoding="utf-8")

    detail_dir = out_dir / f"gen-{summary.current_generation}"
    detail_dir.mkdir(exist_ok=True)
    for r in summary.results:
        (detail_dir / f"{r.slug}.json").write_text(json.dumps(r.to_dict(), indent=2), encoding="utf-8")

    append_jsonl(out_dir / "index.jsonl", [summary.to_index_row()])
    return md
