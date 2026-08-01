#!/usr/bin/env python3
"""Round 2: one shared seed, no framing leak.

The seed is generated ONCE and cached; `seed` is that story unrevised, `loose` and `lens`
are two ways of revising the SAME text. Round 1's arms did not share a seed, so it was
comparing composition strategies and seed prompts at once.

Usage: run_v2.py <run_dir> [--arms seed,loose,lens] [--reseed]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, "/workspace")
sys.path.insert(0, str(Path(__file__).parent / "variants"))

import prompts_v2 as P  # noqa: E402
import yaml  # noqa: E402
from pydantic_ai import Agent  # noqa: E402

from defender.runtime import providers  # noqa: E402

HERE = Path(__file__).parent
MODEL, EFFORT = "glm-5.2", "low"
PER_PAYLOAD_CAP = 24_000
COUNTER = {"benign": "malicious", "malicious": "benign"}
LOOSE_PASSES = 3


def _disposition(run_dir: Path) -> str:
    m = re.search(r"^disposition:\s*(\w+)",
                  (run_dir / "report.md").read_text(encoding="utf-8"), re.MULTILINE)
    return m.group(1) if m else "unknown"


def _investigation_without_conclusion(run_dir: Path) -> str:
    """The belief trace, minus the verdict. Design D2: the reader gets the per-lead
    reasoning but not `:T conclude`, which is the artifact most likely to induce
    agreement. Stripped by dropping any ```invlang block containing the conclude."""
    text = (run_dir / "investigation.md").read_text(encoding="utf-8")
    parts = re.split(r"(```invlang\n.*?\n```)", text, flags=re.DOTALL)
    kept = [p for p in parts if not (p.startswith("```invlang") and ":T conclude" in p)]
    return "".join(kept)


def _leads(run_dir: Path) -> list[dict]:
    out = []
    for p in sorted((run_dir / "gather_raw").glob("*.lead.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["lead_id"] = p.name[: -len(".lead.json")]
        out.append(doc)
    return out


def _payload_text(run_dir: Path, lead_id: str) -> str:
    if not lead_id:
        raise ValueError("empty lead_id")
    d = run_dir / "gather_raw" / lead_id
    if not d.is_dir():
        return "(no payload directory)"
    parts = []
    for f in sorted(d.glob("*.json")):
        raw = f.read_text(encoding="utf-8")
        if len(raw) > PER_PAYLOAD_CAP:
            raw = raw[:PER_PAYLOAD_CAP] + f"\n… [TRUNCATED at {PER_PAYLOAD_CAP} chars]"
        parts.append(f"### {lead_id}/{f.name}\n{raw}")
    return "\n\n".join(parts) or "(empty)"


def _leads_table(leads: list[dict]) -> str:
    rows = []
    for ld in leads:
        rows.append(f"- {ld['lead_id']}: {ld.get('goal', '')}")
        for w in ld.get("what_to_summarize") or []:
            rows.append(f"    · {w}")
    return "\n".join(rows)


def _agent() -> Agent:
    built = providers.build_for_effort(MODEL, EFFORT)
    return Agent(built.model, model_settings=built.settings)


async def _ask(agent, prompt: str, log: list, label: str) -> str:
    t0 = time.time()
    out = (await agent.run(prompt)).output
    log.append({"label": label, "prompt_chars": len(prompt),
                "output_chars": len(out), "seconds": round(time.time() - t0, 1)})
    print(f"    {label}: {len(prompt)}->{len(out)} chars, {log[-1]['seconds']}s",
          file=sys.stderr)
    return out


def _extract(story: str) -> tuple[list[dict], int]:
    blocks = re.findall(r"```ya?ml\s*\n(.*?)```", story, re.DOTALL)
    if not blocks:
        return [], 0
    try:
        doc = yaml.safe_load(blocks[-1])
        if isinstance(doc, dict) and isinstance(doc.get("claims"), list):
            return [c for c in doc["claims"] if isinstance(c, dict)], 0
    except Exception:  # noqa: BLE001
        pass
    items, bad = [], 0
    for ch in re.split(r"\n(?=\s*-\s)", blocks[-1]):
        if not ch.strip().startswith("-"):
            continue
        try:
            d = yaml.safe_load(ch)
        except Exception:  # noqa: BLE001
            bad += 1
            continue
        items.append(d[0]) if isinstance(d, list) and d and isinstance(d[0], dict) else None
        if not (isinstance(d, list) and d and isinstance(d[0], dict)):
            bad += 1
    return items, bad


def _save(out: Path, arm: str, story: str, log: list, meta_extra: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    claims, bad = _extract(story)
    (out / "story.md").write_text(story, encoding="utf-8")
    (out / "claims.yaml").write_text(
        yaml.safe_dump({"claims": claims}, sort_keys=False, allow_unicode=True), encoding="utf-8")
    (out / "meta.json").write_text(json.dumps({
        "arm": arm, "model": MODEL, "effort": EFFORT, "calls": len(log),
        "n_claims": len(claims), "malformed_items": bad, "story_chars": len(story),
        "prompt_chars_total": sum(c["prompt_chars"] for c in log),
        "calls_detail": log, **meta_extra,
    }, indent=2), encoding="utf-8")
    print(f"  -> {arm}: {len(log)} calls, {len(claims)} claims", file=sys.stderr)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--arms", default="seed,loose,lens")
    ap.add_argument("--reseed", action="store_true")
    ns = ap.parse_args()

    run_dir = ns.run_dir.resolve()
    disposition = _disposition(run_dir)
    target = COUNTER.get(disposition, "opposite")
    leads = _leads(run_dir)
    ctx = {
        "target": target,
        "investigation": _investigation_without_conclusion(run_dir),
        "leads": _leads_table(leads),
        "payloads": "\n\n".join(
            f"## {ld['lead_id']} — {ld.get('goal', '')}\n" + _payload_text(run_dir, ld['lead_id'])
            for ld in leads),
    }
    base = HERE / "runs_v2" / run_dir.name
    base.mkdir(parents=True, exist_ok=True)
    print(f"fixture={run_dir.name} actual={disposition} target={target} "
          f"leads={len(leads)} payloads={len(ctx['payloads'])} "
          f"investigation={len(ctx['investigation'])} (conclude stripped)", file=sys.stderr)

    agent = _agent()
    seed_p = base / "seed" / "story.md"
    if seed_p.is_file() and not ns.reseed:
        seed_story = seed_p.read_text(encoding="utf-8")
        print(f"  reusing cached seed ({len(seed_story)} chars)", file=sys.stderr)
    else:
        log: list = []
        print("  generating shared seed", file=sys.stderr)
        seed_story = await _ask(agent, P.SEED.format(tail=P.TAIL_SPEC, **ctx), log, "seed")
        _save(base / "seed", "seed", seed_story, log, {"shared_seed": True})

    for arm in [a for a in ns.arms.split(",") if a != "seed"]:
        log = []
        print(f"  arm={arm}", file=sys.stderr)
        if arm == "loose":
            story = seed_story
            for n in range(1, LOOSE_PASSES + 1):
                story = await _ask(agent, P.LOOSE.format(tail=P.TAIL_SPEC, story=story, **ctx),
                                   log, f"loose-{n}")
        elif arm == "lens":
            inter = base / "lens" / "lens_intermediates"
            inter.mkdir(parents=True, exist_ok=True)

            async def one(ld: dict) -> str:
                lid = ld["lead_id"]
                t = await _ask(agent, P.LENS_ONE.format(
                    target=target, story=seed_story,
                    lead=f"{lid}: {ld.get('goal', '')}",
                    payload=_payload_text(run_dir, lid)), log, f"lens-{lid}")
                (inter / f"{lid}.md").write_text(t, encoding="utf-8")
                return f"## {lid}\n{t}"

            findings = await asyncio.gather(*(one(ld) for ld in leads))
            (inter / "99-fold-input.md").write_text("\n\n".join(findings), encoding="utf-8")
            story = await _ask(agent, P.LENS_FOLD.format(
                target=target, tail=P.TAIL_SPEC, story=seed_story,
                findings="\n\n".join(findings), investigation=ctx["investigation"]),
                log, "lens-fold")
        else:
            print(f"unknown arm {arm}", file=sys.stderr)
            return 1
        _save(base / arm, arm, story, log, {"seeded_from": "seed"})
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
