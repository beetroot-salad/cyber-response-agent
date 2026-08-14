"""Run the two arms against kimi-k2.6 on Fireworks."""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/workspace")

import toons  # noqa: E402
from openai import OpenAI  # noqa: E402

from defender.scripts.gather_tools.payload_view import render  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from build_fixtures import toon_input  # noqa: E402

HERE = Path(__file__).parent
MODEL = "accounts/fireworks/models/kimi-k2p6"
client = OpenAI(base_url="https://api.fireworks.ai/inference/v1",
                api_key=os.environ["FIREWORKS_API_KEY"])

SYSTEM = ("You read a data payload and answer one question about it. "
          "Reply with ONLY the answer value — no explanation, no units, no quotes.")


def view_current(payload: dict) -> str:
    """Production path. Under the ceiling `render` returns the text verbatim."""
    return render(json.dumps(payload), None, Path("/tmp"))


def view_toon(payload: dict) -> str:
    return toons.dumps(toon_input(payload))


ARMS = {"current": view_current, "toon": view_toon}


def one(fx_path: Path, qi: int, arm: str) -> dict:
    fx = json.loads(fx_path.read_text())
    q = fx["questions"][qi]
    view = ARMS[arm](fx["payload"])
    r = client.chat.completions.create(
        # kimi-k2.6 is a reasoning model: `reasoning_content` is billed against max_tokens before
        # any `content` is emitted. At 64 the budget was spent entirely on reasoning and every
        # answer came back empty (finish_reason=length) in BOTH arms. 2048 leaves ample headroom
        # over the ~136 observed. Input tokens — the metric — are unaffected either way.
        model=MODEL, temperature=0, max_tokens=4096,
        messages=[{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": f"{view}\n\nQuestion: {q['q']}"}],
    )
    return {
        "fixture": fx_path.stem, "qi": qi, "kind": q["kind"], "arm": arm,
        "expected": q["a"], "got": (r.choices[0].message.content or "").strip(),
        # Recorded because reasoning length varies run-to-run even at temperature 0: a trial that
        # spent its whole budget reasoning emits no content, and scoring that as WRONG would
        # charge the encoding for a harness cap. Excluded as invalid in analyze.py instead.
        "finish_reason": r.choices[0].finish_reason,
        "completion_tokens": r.usage.completion_tokens,
        "prompt_tokens": r.usage.prompt_tokens, "view_bytes": len(view),
        "rows": fx["rows"], "cols": fx["cols"],
    }


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    fixtures = sorted((HERE / "fixtures").glob("fx-*.json"))
    if limit:
        fixtures = fixtures[:limit]
    jobs = [(p, qi, arm)
            for p in fixtures
            for qi in range(len(json.loads(p.read_text())["questions"]))
            for arm in ARMS]
    out = HERE / "runs"
    out.mkdir(exist_ok=True)
    print(f"{len(jobs)} calls over {len(fixtures)} fixtures")

    done = 0
    with ThreadPoolExecutor(max_workers=8) as ex:
        for rec in ex.map(lambda a: one(*a), jobs):
            (out / f"{rec['fixture']}-q{rec['qi']}-{rec['arm']}.json").write_text(json.dumps(rec))
            done += 1
            if done % 20 == 0:
                print(f"  {done}/{len(jobs)}")
    print(f"done: {done}")


if __name__ == "__main__":
    main()
