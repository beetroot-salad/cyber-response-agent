"""The create lane (`_io.write_guarded(mode='create')`): its fallback where no unnamed file can be made; a linked tenant folder is refused."""
from __future__ import annotations


import errno
import os

import pytest

from defender.tests.support.shared.contracts._create_lane import assert_single_plain, no_unnamed_files
from defender.tests.support.shared.filesystem._umask import umask
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

T_ID = H.VALID_ID


#: Why the create lane's mode is pinned at all: a staged-name sketch (`tempfile.mkstemp`)
#: regressed it to 0600 whatever the umask.
_WHY_0644 = "C-R6 found the naive staged shape regressing to 0600"


@pytest.mark.parametrize("unsupported", [errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL])
def test_create_falls_back_where_no_unnamed_file_can_be_made(tmp_path, unsupported):
    io_mod = H.mod("_io")
    target = tmp_path / "x.json"
    io_mod.write_guarded(target, "{}\n", mode="create", open_unnamed=no_unnamed_files(unsupported))
    assert target.read_text(encoding="utf-8") == "{}\n"
    with pytest.raises(FileExistsError) as again:
        io_mod.write_guarded(target, "{}\n", mode="create",
                             open_unnamed=no_unnamed_files(unsupported))
    assert not getattr(again.value, "write_guarded_alias", False), "the race read as an alias"

    control = tmp_path / "y.json"
    with umask(0o022):
        io_mod.write_guarded(control, "{}\n", mode="create")
    assert_single_plain(control, 0o644, why=_WHY_0644)


def test_create_does_not_swallow_an_unrelated_failure(tmp_path):
    io_mod = H.mod("_io")
    target = tmp_path / "x.json"
    with pytest.raises(OSError, match="No space") as failed:
        io_mod.write_guarded(target, "{}\n", mode="create",
                             open_unnamed=no_unnamed_files(errno.ENOSPC))
    assert failed.value.errno == errno.ENOSPC
    assert not target.exists()


def test_tenant_folder_symlink_swapped_between_o11as_construction_time_check_and_first_write(
        tmp_path):
    """A linked `<root>/T` is refused by acceptance and the link's target is left as it was (#1214 O6: nothing is
    created, so no create to write through the link)."""
    elsewhere = tmp_path / "elsewhere"
    H.place_knowledge(elsewhere, T_ID)
    root = tmp_path / "data"
    root.mkdir()
    (root / T_ID).symlink_to(elsewhere / T_ID, target_is_directory=True)
    before = H.census(elsewhere)
    H.owner_refusal(H.accept, root, T_ID)
    assert H.census(elsewhere) == before, "acceptance wrote through a symlinked tenant folder"
    assert os.readlink(root / T_ID) == str(elsewhere / T_ID), "the planted link was replaced"
    fresh = tmp_path / "fresh"
    H.place_knowledge(fresh, T_ID)
    assert H.accept(fresh, T_ID).id == T_ID
