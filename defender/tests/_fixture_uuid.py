"""A fixture's run and episode ids under #1187 — NO test functions.

#1187 (design rev 2, O1/O2) makes every run, arm and episode id a random canonical lowercase
uuid4 that carries no meaning: `RunId.parse`, the episode-id rule and `RunAddress` admit nothing
else. A test that names a run (a curation row's run, a fixture source, a planted arm) still wants
a readable handle for it, so it keeps a LABEL and asks here for the id: `fixture_uuid(label)` is a
uuid4-shaped id derived from the label alone (the same label gives the same id in every test, a
different label a different id). The label never reaches production; only the id does.

Pure: imports nothing from production, so it collects and runs at any base.

Underscore-prefixed so pytest does not collect it.
"""
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
