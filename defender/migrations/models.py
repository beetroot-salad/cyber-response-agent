"""Every feature's models, collected. Imported only by the Alembic environment and the test that
compares the migrations with the models, so a process that checks its version loads none of them."""

from __future__ import annotations

from defender.database import Base
from defender.identity import models as _identity  # noqa: F401 — registers identity's tables

target_metadata = Base.metadata
