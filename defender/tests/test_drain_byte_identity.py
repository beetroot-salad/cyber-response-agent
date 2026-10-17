"""drain._byte_identical_to_head compares raw bytes, not newline-translated text."""
from __future__ import annotations

from defender.learning.author import drain
from defender.tests._drain719 import git


def test_a_crlf_only_rewrite_is_not_byte_identical_to_head(tmp_path):
    """The exact counterexample the claims-adversary pass ran: HEAD holds LF line endings, the
    working tree rewrites the same text with CRLF line endings."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "a@b.com")
    git(repo, "config", "user.name", "test")
    f = repo / "f.txt"
    f.write_bytes(b"line one\nline two\nline three\n")
    git(repo, "add", "f.txt")
    git(repo, "commit", "-q", "-m", "init")

    f.write_bytes(b"line one\r\nline two\r\nline three\r\n")

    status = git(repo, "status", "--porcelain")
    assert status.stdout.strip() == "M f.txt", "git itself must see this as a dirty file"

    assert drain._byte_identical_to_head(repo, "f.txt") is False


def test_a_genuine_byte_identical_file_is_still_recognised(tmp_path):
    """Positive control beside the fix: an ACTUAL byte-identical rewrite (chmod only, same
    bytes) must still be recognised as unchanged — the fix must not overcorrect into
    flagging every touched file as changed."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "a@b.com")
    git(repo, "config", "user.name", "test")
    f = repo / "f.txt"
    f.write_bytes(b"line one\nline two\n")
    git(repo, "add", "f.txt")
    git(repo, "commit", "-q", "-m", "init")

    f.chmod(0o755)

    assert drain._byte_identical_to_head(repo, "f.txt") is True
