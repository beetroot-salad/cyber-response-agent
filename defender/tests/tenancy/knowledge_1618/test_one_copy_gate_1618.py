"""#1618 follow-up: a run copy is made by one operation that fetches, checks the pin and the settings, and only then
places the copy; any refusal is a `[run.py]` refusal that leaves nothing under `<T>/run-knowledge/`."""
from __future__ import annotations

import os
import uuid

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K


def _accepted(t):
    from defender.tenancy import data_root_from_path, requested_tenant

    return requested_tenant(data_root_from_path(t.data_root), t.tenant.id)


def _resolve(t, tenant, fetch, *, pin=None, run_id=None):
    from defender import run_common
    from defender.tenancy import data_root_from_path

    return run_common.resolve_knowledge(tenant, pin=pin, fetch=fetch, data_root=data_root_from_path(t.data_root),
                                        records=t.directory, run_id=run_id or str(uuid.uuid4()))


def test_a_copy_folder_that_cannot_be_made_is_a_run_refusal_not_a_crash(t, tmp_path):
    """`<T>/run-knowledge` that is a file: the run is refused with a `[run.py]` sentence, no traceback (#1618 follow-up).
    Control: with the folder back, the same call places a copy."""
    tenant = _accepted(t)
    copies = A.run_copies(t)
    if copies.is_dir():
        os.rmdir(copies)
    copies.write_text("not a folder\n")
    with pytest.raises(SystemExit) as refused:
        _resolve(t, tenant, K.fetch_seam(t, tmp_path))
    assert str(refused.value.code).startswith("[run.py] "), refused.value.code
    copies.unlink()
    copies.mkdir()
    run_id = str(uuid.uuid4())
    _resolve(t, tenant, K.fetch_seam(t, tmp_path), run_id=run_id)
    assert run_id in A.listing(copies), "control: a copy is placed"


def test_a_pinned_copy_of_another_commit_is_refused_and_nothing_is_placed(t, tmp_path):
    """A fetch that answers another commit than the pin is refused before the copy is placed: nothing stays under
    `<T>/run-knowledge/` (#1618 follow-up). Control: the honest seam places the pinned copy."""
    tenant = _accepted(t)
    pin = t.export.commit
    K.advance_main(t, "GATE-LATER")
    real = K.fetch_seam(t, tmp_path)

    def main_instead(tenant_id, dest, *, commit=None, **kw):
        return real(tenant_id, dest, commit=None, **kw)

    run_id = str(uuid.uuid4())
    with pytest.raises(SystemExit) as refused:
        _resolve(t, tenant, main_instead, pin=pin, run_id=run_id)
    assert "asked for" in str(refused.value.code), refused.value.code
    assert A.listing(A.run_copies(t)) == [], A.listing(A.run_copies(t))
    _resolve(t, tenant, real, pin=pin, run_id=run_id)
    assert A.listing(A.run_copies(t)) == [run_id], "control: the pinned copy is placed"


def test_a_copy_whose_settings_fail_is_refused_before_it_is_placed(t, tmp_path):
    """A `main` missing a required settings file is refused by the copy operation itself, naming the file, and nothing
    stays under `<T>/run-knowledge/` (#1618 follow-up: the check is part of making the copy, not a later step)."""
    from defender.tenancy._tenant import REQUIRED_SETTINGS

    tenant = _accepted(t)
    missing = sorted(REQUIRED_SETTINGS)[0]
    K.advance_main(t, files={f"settings/{missing}": None})
    run_id = str(uuid.uuid4())
    with pytest.raises(SystemExit) as refused:
        _resolve(t, tenant, K.fetch_seam(t, tmp_path), run_id=run_id)
    assert missing in str(refused.value.code), refused.value.code
    assert str(A.run_copies(t) / run_id / "settings") in str(refused.value.code), "the refusal names the copy's own path"
    assert A.listing(A.run_copies(t)) == [], A.listing(A.run_copies(t))
