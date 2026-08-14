"""Three-way input-token measurement on identical content, real Kimi tokenizer.

The 200-trial run compared `current` (columnar — only available because we OWN the adapter)
against TOON. An external adapter or MCP server hands us whatever shape it likes; the common
REST/MCP shape is an array of row objects. That is the `dictrow` arm — the honest baseline for
a deployment where the source cannot be fixed.

`max_tokens=1`: only `usage.prompt_tokens` is wanted, and it is deterministic given the prompt.
"""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "/workspace")
sys.path.insert(0, str(Path(__file__).parent))

import toons  # noqa: E402
from openai import OpenAI  # noqa: E402

from build_fixtures import toon_input  # noqa: E402

HERE = Path(__file__).parent
MODEL = "accounts/fireworks/models/kimi-k2p6"
client = OpenAI(base_url="https://api.fireworks.ai/inference/v1",
                api_key=os.environ["FIREWORKS_API_KEY"])


def views(payload: dict) -> dict[str, str]:
    dictrow = toon_input(payload)  # same re-zip, but serialized as JSON — the unowned shape
    return {
        "dictrow": json.dumps(dictrow),
        "columnar": json.dumps(payload),
        "toon": toons.dumps(dictrow),
    }


def tokens(text: str) -> int:
    r = client.chat.completions.create(
        model=MODEL, temperature=0, max_tokens=1,
        messages=[{"role": "user", "content": text}])
    return r.usage.prompt_tokens


def main() -> None:
    fixtures = sorted((HERE / "fixtures").glob("fx-*.json"))
    jobs = []
    for p in fixtures:
        fx = json.loads(p.read_text())
        for arm, text in views(fx["payload"]).items():
            jobs.append((p.stem, arm, text, len(text)))

    with ThreadPoolExecutor(max_workers=8) as ex:
        toks = list(ex.map(lambda j: tokens(j[2]), jobs))

    agg: dict[str, dict[str, int]] = {}
    for (_, arm, _, nbytes), t in zip(jobs, toks, strict=True):
        a = agg.setdefault(arm, {"tokens": 0, "bytes": 0, "n": 0})
        a["tokens"] += t
        a["bytes"] += nbytes
        a["n"] += 1

    base = agg["dictrow"]["tokens"]
    col = agg["columnar"]["tokens"]
    print(f"{len(fixtures)} payloads, identical content, real kimi-k2.6 tokenizer\n")
    print(f"{'encoding':<10} {'tokens':>9} {'bytes':>9} {'vs dictrow':>12} {'vs columnar':>13}")
    print("-" * 58)
    for arm in ("dictrow", "columnar", "toon"):
        a = agg[arm]
        print(f"{arm:<10} {a['tokens']:>9,} {a['bytes']:>9,} "
              f"{100 * (a['tokens'] - base) / base:>11.1f}% "
              f"{100 * (a['tokens'] - col) / col:>12.1f}%")
    (HERE / "results" / "unowned.json").write_text(json.dumps(agg, indent=2))


if __name__ == "__main__":
    main()
