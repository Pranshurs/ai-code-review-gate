import pytest

from ledgerkit.errors import SignatureError
from ledgerkit.signing import verify


def test_oversized_header_rejected():
    with pytest.raises(SignatureError, match="too long"):
        verify(b"s3cret", "t=1,v1=" + "a" * 600, b"x", now=1)


def test_duplicate_fields_rejected():
    with pytest.raises(SignatureError, match="duplicate"):
        verify(b"s3cret", "t=1,t=2,v1=aa", b"x", now=1)
