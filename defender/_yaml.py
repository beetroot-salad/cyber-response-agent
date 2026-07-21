from __future__ import annotations

from typing import Any

import yaml


def safe_load(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except RecursionError as e:
        raise yaml.YAMLError("YAML is nested too deeply to parse") from e
