import hashlib

import pytest

from docstore.errors import ToolError
from docstore.tools import sha256_of_file, verify_integrity


def test_sha256_matches_hashlib(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    assert sha256_of_file(p) == hashlib.sha256(b"abc").hexdigest()


def test_hostile_filename_is_not_interpreted(tmp_path):
    marker = tmp_path / "pwned"
    p = tmp_path / "x; touch pwned && echo $(id)"
    p.write_bytes(b"abc")
    sha256_of_file(p)
    assert p.exists()


def test_integrity_mismatch(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    with pytest.raises(ToolError, match="integrity"):
        verify_integrity(p, "0" * 64)


def test_missing_file_is_tool_error(tmp_path):
    with pytest.raises(ToolError, match="exited with"):
        sha256_of_file(tmp_path / "absent")
