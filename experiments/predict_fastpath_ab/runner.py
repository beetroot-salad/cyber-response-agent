"""Fast-path A/B experiment runner.

Iterates fixtures × arms, captures per-arm output to JSONL.

Usage:
    python3 tasks-scratch/predict_fastpath_ab/runner.py            # all fixtures, all arms
    python3 tasks-scratch/predict_fastpath_ab/runner.py --arm D
    python3 tasks-scratch/predict_fastpath_ab/runner.py --fixture 5710-nagios-monitoring-probe
    python3 tasks-scratch/predict_fastpath_ab/runner.py --gate-only

By default the LLM arms (A/B/C) are stubbed out — they require
`claude --print` and would burn budget. Pass --enable-llm to actually
invoke them. Arm D is always free (no LLM).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

EXPERIMENT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = EXPERIMENT_DIR.parent.parent
sys.path.insert(0, str(EXPERIMENT_DIR))
sys.path.insert(0, str(EXPERIMENT_DIR / "arms"))

import gate  # noqa: E402
import seed_precedents  # noqa: E402
from arms import _llm, prompts  # noqa: E402

ARM_MODEL: dict[str, str] = {
    "A": "claude-sonnet-4-6",
    "B": "claude-sonnet-4-6",
    "C": "claude-haiku-4-5-20251001",
}

ARM_BUILDER = {
    "A": prompts.build_arm_a,
    "B": prompts.build_arm_b,
    "C": prompts.build_arm_c,
}


# Hand-derived from playbook for now; in prod this comes from the lead catalog.
LEAD_CATALOGS: dict[str, set[str]] = {
    "wazuh-rule-5710": {
        "source-classification", "username-classification",
        "approved-monitoring-sources", "authentication-history",
        "external-bruteforce", "credential-stuffing",
        "service-account-rotation", "monitoring-probe", "srcip",
    },
    "wazuh-rule-550": {
        "file-classification", "change-attributes", "syscheck-db-state",
        "temporal-correlation", "host-query",
    },
}

DISCRIMINATING_FIELDS: dict[str, list[str]] = {
    "wazuh-rule-5710": ["data.srcip", "data.srcuser", "data.dstuser"],
    "wazuh-rule-550": ["syscheck.changed_attributes", "syscheck.path"],
}


def _load_fixture(fix_dir: Path) -> dict:
    alert = json.loads((fix_dir / "alert.json").read_text())
    inv_md = (fix_dir / "investigation.md").read_text()
    meta = json.loads((fix_dir / "meta.json").read_text())
    return {"alert": alert, "investigation_md": inv_md, "meta": meta}


def _run_arm_d(fix: dict) -> dict:
    """Arm D — handler-only fast-path. Pure deterministic gate."""
    sig_id = fix["meta"]["signature_id"]
    prologue = gate.parse_prologue(fix["investigation_md"]) or {}
    decision = gate.evaluate(
        current_alert=fix["alert"],
        current_prologue=prologue,
        signature_id=sig_id,
        precedents=seed_precedents.for_signature(sig_id),
        lead_catalog=LEAD_CATALOGS.get(sig_id, set()),
        discriminating_fields=DISCRIMINATING_FIELDS.get(sig_id, []),
    )
    return {
        "arm": "D",
        "verdict": decision["verdict"],
        "selected_lead": decision.get("selected_lead"),
        "matched_cases": decision.get("matched_cases"),
        "per_precedent": decision["per_precedent"],
    }


def _gate_decision(fix: dict) -> dict:
    sig_id = fix["meta"]["signature_id"]
    prologue = gate.parse_prologue(fix["investigation_md"]) or {}
    return gate.evaluate(
        current_alert=fix["alert"],
        current_prologue=prologue,
        signature_id=sig_id,
        precedents=seed_precedents.for_signature(sig_id),
        lead_catalog=LEAD_CATALOGS.get(sig_id, set()),
        discriminating_fields=DISCRIMINATING_FIELDS.get(sig_id, []),
    )


def _run_arm_llm(arm: str, fix: dict, enable_llm: bool) -> dict:
    if not enable_llm:
        return {"arm": arm, "verdict": "skipped", "reason": "llm arms disabled (use --enable-llm)"}
    sig_id = fix["meta"]["signature_id"]
    prologue = gate.parse_prologue(fix["investigation_md"]) or {}
    decision = _gate_decision(fix)
    sysp, userp = ARM_BUILDER[arm](
        alert=fix["alert"],
        prologue=prologue,
        signature_id=sig_id,
        lead_catalog=sorted(LEAD_CATALOGS.get(sig_id, set())),
        gate_decision=decision,
        prior_strength=decision["verdict"],
    )
    inv = _llm.invoke(
        system_prompt=sysp, user_prompt=userp,
        model=ARM_MODEL[arm], timeout=180,
    )
    selected = _llm.extract_selected_lead(inv["stdout"])
    return {
        "arm": arm,
        "verdict": "llm-resolved" if selected else "llm-noparse",
        "selected_lead": selected,
        "elapsed_llm_s": inv["elapsed_s"],
        "exit_code": inv["exit_code"],
        "stdout_preview": (inv["stdout"] or "")[:200],
        "gate_verdict": decision["verdict"],
    }


ARMS = {
    "A": lambda fix, llm: _run_arm_llm("A", fix, llm),
    "B": lambda fix, llm: _run_arm_llm("B", fix, llm),
    "C": lambda fix, llm: _run_arm_llm("C", fix, llm),
    "D": lambda fix, llm: _run_arm_d(fix),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", default=None, help="restrict to one fixture")
    parser.add_argument("--arm", default=None, choices=list(ARMS), help="restrict to one arm")
    parser.add_argument("--gate-only", action="store_true", help="run only arm D")
    parser.add_argument("--enable-llm", action="store_true", help="run LLM arms (A/B/C)")
    args = parser.parse_args()

    fixtures_dir = EXPERIMENT_DIR / "fixtures"
    fix_dirs = sorted(d for d in fixtures_dir.iterdir() if d.is_dir())
    if args.fixture:
        fix_dirs = [d for d in fix_dirs if d.name == args.fixture]
        if not fix_dirs:
            print(f"no fixture matching {args.fixture!r}", file=sys.stderr)
            return 1

    arms = {args.arm: ARMS[args.arm]} if args.arm else dict(ARMS)
    if args.gate_only:
        arms = {"D": ARMS["D"]}

    out_dir = EXPERIMENT_DIR / "output"
    out_dir.mkdir(exist_ok=True)
    results_path = out_dir / "results.jsonl"
    with results_path.open("w") as fh:
        for fix_dir in fix_dirs:
            fix = _load_fixture(fix_dir)
            ground = fix["meta"].get("fastpath_meta", {}).get("ground_truth_lead")
            for arm_name, runner in arms.items():
                t0 = time.monotonic()
                result = runner(fix, args.enable_llm)
                elapsed = time.monotonic() - t0
                row = {
                    "fixture": fix_dir.name,
                    "signature_id": fix["meta"]["signature_id"],
                    "expected_prior_level": fix["meta"].get("fastpath_meta", {}).get("expected_prior_level"),
                    "ground_truth_lead": ground,
                    "adversarial": fix["meta"].get("fastpath_meta", {}).get("adversarial", False),
                    "arm": arm_name,
                    "elapsed_s": round(elapsed, 4),
                    **result,
                }
                fh.write(json.dumps(row) + "\n")
                fh.flush()
                summary = (
                    f"[{fix_dir.name}] arm={arm_name} verdict={result.get('verdict')} "
                    f"lead={result.get('selected_lead')} (gt={ground})"
                )
                print(summary)
    print(f"\nresults → {results_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
