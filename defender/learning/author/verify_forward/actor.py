from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
PROMPT_PATH = HERE / "actor.md"


def load_story(bundle: Path) -> str:
    path = (bundle / "actor_story.md").resolve()
    if not path.is_file():
        raise SystemExit(f"verify_forward_actor: actor_story.md missing at {path}")
    return path.read_text(encoding="utf-8")
