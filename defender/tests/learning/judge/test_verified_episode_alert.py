"""An episode displays exactly the alert bytes certified at admission."""
from __future__ import annotations

import json
import os

import pytest

from defender import _io
from defender.records import _alert_input
from defender.records._episode_paths import LAYOUT
from defender.learning.judge.render import episode_alert


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
@pytest.mark.parametrize("changed", [False, True])
def test_episode_alert_verifies_original_bytes(tmp_path, newline, changed):
    document = {"message": "café", "alert_id": "original"}
    raw = json.dumps(document, ensure_ascii=False, indent=2).encode().replace(b"\n", newline)
    admitted = _alert_input.admit(raw)
    (tmp_path / LAYOUT.source_record).write_text(json.dumps({"digest": admitted.digest}))
    # Even a semantically identical JSON document must retain its admitted byte identity.
    (tmp_path / LAYOUT.source_alert).write_bytes(raw + b" " if changed else raw)
    with _io.bind(tmp_path) as bound:
        assert episode_alert(bound) == ({} if changed else document)


@pytest.mark.parametrize("raw", [b"\xff", b"[]", b"{broken", b""])
def test_verified_document_rejects_malformed_content_even_with_matching_digest(tmp_path, raw):
    (tmp_path / LAYOUT.source_record).write_text(json.dumps({"digest": _alert_input.digest_of(raw)}))
    (tmp_path / LAYOUT.source_alert).write_bytes(raw)
    with _io.bind(tmp_path) as bound:
        assert episode_alert(bound) == {}


def test_bound_bytes_preserve_binary_and_newlines(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    raw = b"a\r\nb\rc\n\xff"
    (nested / "alert").write_bytes(raw)
    with _io.bind(tmp_path) as bound:
        read = bound.under("nested").read_bytes("alert")
        assert read.data == raw
        assert not read.absent
        assert read.reason is None
        assert read.refused_by is None
        assert bound.under("nested").read("alert").refused_by == _io.REFUSED_UNDECODABLE
    assert bound.read_bytes("nested/alert").refused_by == _io.REFUSED_FAULT


@pytest.mark.parametrize("plant", ["symlink", "hardlink", "fifo", "directory", "missing", "oversize"])
def test_bound_bytes_enforce_read_guards(tmp_path, plant):
    source = tmp_path / "source"
    source.write_bytes(b"12345")
    target = tmp_path / "alert"
    if plant == "symlink":
        target.symlink_to(source)
    elif plant == "hardlink":
        os.link(source, target)
    elif plant == "fifo":
        os.mkfifo(target)
    elif plant == "directory":
        target.mkdir()
    elif plant == "oversize":
        with target.open("wb") as stream:
            stream.truncate(_io.READ_LIMIT + 1)
    with _io.bind(tmp_path) as bound:
        read = bound.read_bytes("alert")
        assert read.data is None
        assert read.absent == (plant == "missing")
        assert read.refused_by == {
            "symlink": _io.REFUSED_ALIAS, "hardlink": _io.REFUSED_ALIAS,
            "fifo": _io.REFUSED_NOT_FILE, "directory": _io.REFUSED_NOT_FILE,
            "missing": None, "oversize": _io.REFUSED_FAULT,
        }[plant]


@pytest.mark.parametrize("name", ["../alert", "/alert", "a//alert"])
def test_bound_bytes_reject_invalid_names(tmp_path, name):
    with _io.bind(tmp_path) as bound, pytest.raises(ValueError, match="name"):
        bound.read_bytes(name)
