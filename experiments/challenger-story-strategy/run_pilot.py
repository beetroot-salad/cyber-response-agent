#!/usr/bin/env python3
"""Pilot: three challenger composition strategies over one run dir.

Usage: run_pilot.py <run_dir> [--arms one-shot,iterative,lens]

Writes runs/<arm>/{story.md,claims.yaml,meta.json} and per-call transcripts.
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

import prompts  # noqa: E402
import yaml  # noqa: E402
from pydantic_ai import Agent  # noqa: E402

from defender.runtime import providers  # noqa: E402

HERE = Path(__file__).parent
MODEL = "glm-5.2"
EFFORT = "low"
# Same cap in every arm — an arm seeing more of a payload than another would be a
# confound on top of the composition variable.
PER_PAYLOAD_CAP = 24_000

COUNTER = {"benign": "malicious", "malicious": "benign"}


def _disposition(run_dir: Path) -> str:
    text = (run_dir / "report.md").read_text(encoding="utf-8")
    m = re.search(r"^disposition:\s*(\w+)", text, re.MULTILINE)
    return m.group(1) if m else "unknown"


def _leads(run_dir: Path) -> list[dict]:
    """The sidecar does NOT carry the lead id — the id is the FILENAME stem
    (`l-004.lead.json`). Reading it out of the body yields None, and an empty id then
    makes the payload path collapse back onto gather_raw/ itself, whose *.json glob
    matches the sidecars. That served every lead the same sidecar dump and no payload
    at all, silently, in all three arms."""
    out = []
    for p in sorted((run_dir / "gather_raw").glob("*.lead.json")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"  skipping unreadable lead sidecar {p.name}: {e!r}", file=sys.stderr)
            continue
        doc["lead_id"] = p.name[: -len(".lead.json")]
        out.append(doc)
    return out


def _payload_text(run_dir: Path, lead_id: str) -> str:
    if not lead_id:
        raise ValueError("empty lead_id — refusing to glob the gather_raw root")
    d = run_dir / "gather_raw" / lead_id
    if not d.is_dir():
        return "(no payload directory for this lead)"
    parts = []
    for f in sorted(d.glob("*.json")):
        raw = f.read_text(encoding="utf-8")
        if len(raw) > PER_PAYLOAD_CAP:
            raw = raw[:PER_PAYLOAD_CAP] + f"\n… [TRUNCATED at {PER_PAYLOAD_CAP} chars]"
        parts.append(f"### {lead_id}/{f.name}\n{raw}")
    return "\n\n".join(parts) or "(payload directory is empty)"


def _all_payloads(run_dir: Path, leads: list[dict]) -> str:
    return "\n\n".join(
        f"## Lead {ld.get('lead_id')} — {ld.get('goal', '')}\n"
        + _payload_text(run_dir, ld.get("lead_id", ""))
        for ld in leads
    )


def _leads_table(leads: list[dict]) -> str:
    """`system`/`target` are not on the sidecar either — it carries `goal` and
    `what_to_summarize`. Emitting absent keys printed `system=None` for every lead."""
    rows = []
    for ld in leads:
        rows.append(f"- {ld['lead_id']}: {ld.get('goal', '')}")
        for w in ld.get("what_to_summarize") or []:
            rows.append(f"    · {w}")
    return "\n".join(rows)


def _agent() -> Agent:
    built = providers.build_for_effort(MODEL, EFFORT)
    return Agent(built.model, model_settings=built.settings)


async def _ask(agent: Agent, prompt: str, log: list, label: str) -> str:
    t0 = time.time()
    res = await agent.run(prompt)
    out = res.output
    log.append({
        "label": label, "prompt_chars": len(prompt),
        "output_chars": len(out), "seconds": round(time.time() - t0, 1),
    })
    print(f"    {label}: {len(prompt)} chars in, {len(out)} out, "
          f"{log[-1]['seconds']}s", file=sys.stderr)
    return out


async def arm_one_shot(agent, ctx, log) -> str:
    return await _ask(agent, prompts.ONE_SHOT.format(tail=prompts.TAIL_SPEC, **ctx),
                      log, "one-shot")


async def arm_iterative(agent, ctx, log) -> str:
    story = await _ask(agent, prompts.ITER_ROUGH.format(**ctx), log, "iter-1-rough")
    for n in (2, 3, 4):
        story = await _ask(
            agent,
            prompts.ITER_SHARPEN.format(
                n=n, story=story,
                tail_or_blank=prompts.TAIL_SPEC if n == 4 else "",
                **ctx,
            ),
            log, f"iter-{n}-sharpen",
        )
    return story


async def arm_lens(agent, ctx, run_dir, leads, log, out_dir: Path) -> str:
    """Intermediates are persisted: the per-lead lens is explicitly asked what its lead
    does NOT measure, and pilot 01 could not tell whether the lenses produced that and the
    fold dropped it, or whether they never produced it — which is the whole question about
    this arm."""
    story = await _ask(agent, prompts.LENS_ROUGH.format(**ctx), log, "lens-1-rough")
    lens_dir = out_dir / "lens_intermediates"
    lens_dir.mkdir(parents=True, exist_ok=True)
    (lens_dir / "00-rough.md").write_text(story, encoding="utf-8")

    async def one(ld: dict) -> str:
        lid = ld["lead_id"]
        text = await _ask(
            agent,
            prompts.LENS_ONE.format(
                disposition=ctx["disposition"], counter=ctx["counter"], story=story,
                lead=f"{lid}: {ld.get('goal', '')}",
                payload=_payload_text(run_dir, lid),
            ),
            log, f"lens-{lid}",
        )
        (lens_dir / f"{lid}.md").write_text(text, encoding="utf-8")
        return f"## {lid}\n{text}"

    findings = await asyncio.gather(*(one(ld) for ld in leads))
    (lens_dir / "99-fold-input.md").write_text("\n\n".join(findings), encoding="utf-8")
    return await _ask(
        agent,
        prompts.LENS_FOLD.format(
            counter=ctx["counter"], tail=prompts.TAIL_SPEC, story=story,
            findings="\n\n".join(findings), investigation=ctx["investigation"],
        ),
        log, "lens-fold",
    )


def _extract_claims(story: str) -> list[dict]:
    blocks = re.findall(r"```ya?ml\s*\n(.*?)```", story, re.DOTALL)
    for b in reversed(blocks):
        try:
            doc = yaml.safe_load(b)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(doc, dict) and isinstance(doc.get("claims"), list):
            return [c for c in doc["claims"] if isinstance(c, dict)]
    return []


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--arms", default="one-shot,iterative,lens")
    ns = ap.parse_args()

    run_dir = ns.run_dir.resolve()
    disposition = _disposition(run_dir)
    leads = _leads(run_dir)
    ctx = {
        "disposition": disposition,
        "counter": COUNTER.get(disposition, "opposite"),
        "investigation": (run_dir / "investigation.md").read_text(encoding="utf-8"),
        "leads": _leads_table(leads),
        "payloads": _all_payloads(run_dir, leads),
    }
    print(f"fixture={run_dir.name} disposition={disposition} -> "
          f"counter={ctx['counter']} leads={len(leads)} "
          f"payload_chars={len(ctx['payloads'])}", file=sys.stderr)

    agent = _agent()
    for arm in ns.arms.split(","):
        print(f"  arm={arm}", file=sys.stderr)
        log: list = []
        t0 = time.time()
        out = HERE / "runs" / run_dir.name / arm
        out.mkdir(parents=True, exist_ok=True)
        if arm == "one-shot":
            story = await arm_one_shot(agent, ctx, log)
        elif arm == "iterative":
            story = await arm_iterative(agent, ctx, log)
        elif arm == "lens":
            story = await arm_lens(agent, ctx, run_dir, leads, log, out)
        else:
            print(f"unknown arm {arm}", file=sys.stderr)
            return 1

        claims = _extract_claims(story)
        (out / "story.md").write_text(story, encoding="utf-8")
        (out / "claims.yaml").write_text(
            yaml.safe_dump({"claims": claims}, sort_keys=False, allow_unicode=True),
            encoding="utf-8")
        (out / "meta.json").write_text(json.dumps({
            "arm": arm, "fixture": run_dir.name, "model": MODEL, "effort": EFFORT,
            "disposition": disposition, "counter": ctx["counter"],
            "calls": len(log), "wall_seconds": round(time.time() - t0, 1),
            "prompt_chars_total": sum(c["prompt_chars"] for c in log),
            "n_claims": len(claims), "story_chars": len(story), "calls_detail": log,
        }, indent=2), encoding="utf-8")
        print(f"  -> {arm}: {len(log)} calls, {len(claims)} claims, "
              f"{round(time.time() - t0, 1)}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
