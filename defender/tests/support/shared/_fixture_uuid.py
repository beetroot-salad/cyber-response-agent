"""A fixture's run and episode ids under #1187 — NO test functions."""
from __future__ import annotations

import hashlib
import uuid


def fixture_uuid(label: str) -> str:
    """The canonical lowercase uuid4 text a fixture uses for `label` — deterministic, so a
    builder called twice for one label names one folder, and a test can spell the id it
    expects. Version and variant bits are set as `uuid.uuid4()` sets them."""
    digest = hashlib.sha256(f"defender-test-fixture:{label}".encode()).digest()[:16]
    return str(uuid.UUID(bytes=digest, version=4))


def is_fixture_uuid_shape(text: object) -> bool:
    """Is `text` canonical lowercase UUID text (any fixture id passes; an old `<stamp>-<label>`
    or a hand-typed name does not)? The test-side oracle, from the design's rule."""
    if not isinstance(text, str):
        return False
    try:
        return str(uuid.UUID(text)) == text
    except ValueError:
        return False
