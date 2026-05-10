"""Hypothesize-subagent A/B test against a pre-HYPOTHESIZE fixture.

Fixture: /tmp/hypothesize-fixture-preloop1 (orchestrator run 20260422-170629,
trimmed to CONTEXTUALIZE-only investigation.md).

Two experiments on the same fixture:
  A) prompt as built by the handler (archetype-scan block present)
  B) prompt with the <archetypes> block stripped (archetype-scan eliminated)

Both fire loop 1 from a clean post-CONTEXTUALIZE state.
"""

import json
import re
import sys
import time
from pathlib import Path

SOC = Path("/workspace/soc-agent")
sys.path.insert(0, str(SOC))

from scripts.handlers._context_loader import load_alert  # noqa: E402
from scripts.handlers.hypothesize import _assemble_prompt  # noqa: E402
from scripts.handlers._subagent import invoke_subagent  # noqa: E402
from scripts.orchestrate import Context  # noqa: E402


FIXTURE_RUN = Path(
    "/tmp/hypothesize-fixture-preloop1/runs/"
    "93adc830-72b9-468c-a5e0-597671080057"
)
OUT = Path("/workspace/tasks-scratch/hypothesize-test-outputs")
OUT.mkdir(parents=True, exist_ok=True)


def build_ctx() -> Context:
    alert = load_alert(FIXTURE_RUN)
    ticket_id = ""
    meta = FIXTURE_RUN / "meta.json"
    if meta.exists():
        ticket_id = json.loads(meta.read_text()).get("ticket_id", "")
    return Context(
        run_dir=FIXTURE_RUN,
        signature_id="wazuh-rule-100001",
        ticket_id=ticket_id,
        alert=alert,
    )


def strip_archetype_block(prompt: str) -> str:
    prompt = re.sub(
        r"<archetypes>.*?</archetypes>\n*", "", prompt, flags=re.DOTALL
    )
    prompt = re.sub(r"<archetypes/>\n*", "", prompt)
    return prompt


def run_one(label: str, prompt: str, path: Path) -> tuple[float, int]:
    print(f"[{label}] dispatching... prompt={len(prompt)} chars", flush=True)
    started = time.monotonic()
    out = invoke_subagent("hypothesize", prompt, timeout=600)
    dur = time.monotonic() - started
    path.write_text(out)
    (path.with_suffix(".meta.txt")).write_text(
        f"duration_s={dur:.1f}\nprompt_chars={len(prompt)}\nstdout_chars={len(out)}\n"
    )
    print(f"[{label}] done: {dur:.1f}s, {len(out)} chars", flush=True)
    return dur, len(out)


def reset_fixture() -> None:
    """Truncate investigation.md back to prologue fence so loop_n stays 1."""
    f = FIXTURE_RUN / "investigation.md"
    text = f.read_text()
    # Find the end of the CONTEXTUALIZE prologue (first prologue YAML fence close).
    # investigation.md starts with `## CONTEXTUALIZE` followed by prose and a
    # ```yaml ... ``` block. Anything after the closing ``` is contamination.
    first_open = text.find("```yaml")
    if first_open < 0:
        return
    first_close = text.find("```", first_open + 7)
    if first_close < 0:
        return
    cleaned = text[: first_close + 3].rstrip() + "\n"
    f.write_text(cleaned)


def main() -> None:
    # Experiment C — prologue-priors + updated hypothesize prompt + archetypes present
    reset_fixture()
    ctx = build_ctx()
    base = _assemble_prompt(ctx)
    dur_c, len_c = run_one(
        "C-prologuepriors-with-archetypes",
        base,
        OUT / "C-with-archetypes.stdout.md",
    )

    # Experiment D — prologue-priors + updated prompt + archetypes stripped
    reset_fixture()
    ctx = build_ctx()
    base_d = _assemble_prompt(ctx)
    stripped = strip_archetype_block(base_d)
    assert len(stripped) < len(base_d), "strip regex missed"
    dur_d, len_d = run_one(
        "D-prologuepriors-no-archetypes",
        stripped,
        OUT / "D-no-archetypes.stdout.md",
    )

    (OUT / "SUMMARY-prologue-priors.md").write_text(
        f"# Hypothesize A/B — prologue-priors patch + prompt updates\n\n"
        f"Fixture: {FIXTURE_RUN} (investigation.md reset to prologue between runs)\n\n"
        f"| Experiment | Archetype block | Duration | Prompt chars | Stdout chars |\n"
        f"|---|---|---|---|---|\n"
        f"| C | present | {dur_c:.1f}s | {len(base)} | {len_c} |\n"
        f"| D | stripped | {dur_d:.1f}s | {len(stripped)} | {len_d} |\n"
    )


if __name__ == "__main__":
    main()
