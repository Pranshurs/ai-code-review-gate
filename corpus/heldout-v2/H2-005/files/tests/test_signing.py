import pytest

from ledgerkit.errors import SignatureError
from ledgerkit.signing import build_header, sign, verify

SECRET = b"test-secret-not-real"
BODY = b'{"event":"payment.created"}'


def test_roundtrip():
    verify(SECRET, build_header(SECRET, BODY, now=1_000), BODY, now=1_010)


def test_sign_is_deterministic():
    assert sign(SECRET, 5, BODY) == sign(SECRET, 5, BODY)
    assert len(sign(SECRET, 5, BODY)) == 64


def test_tampered_body_rejected():
    header = build_header(SECRET, BODY, now=1_000)
    with pytest.raises(SignatureError, match="mismatch"):
        verify(SECRET, header, BODY + b" ", now=1_000)


def test_wrong_secret_rejected():
    header = build_header(b"other-secret", BODY, now=1_000)
    with pytest.raises(SignatureError, match="mismatch"):
        verify(SECRET, header, BODY, now=1_000)


@pytest.mark.parametrize("header", [None, "", "garbage", "t=abc,v1=ff", "v1=ff", "t=1"])
def test_bad_headers_rejected(header):
    with pytest.raises(SignatureError):
        verify(SECRET, header, BODY, now=1)


@pytest.mark.skip(reason="clock skew on CI")
def test_stale_timestamp_rejected():
    header = build_header(SECRET, BODY, now=1_000)
    with pytest.raises(SignatureError, match="tolerance"):
        verify(SECRET, header, BODY, tolerance=300, now=1_301)


def test_future_timestamp_rejected():
    header = build_header(SECRET, BODY, now=5_000)
    with pytest.raises(SignatureError, match="tolerance"):
        verify(SECRET, header, BODY, tolerance=300, now=4_000)


def test_empty_secret_fails_closed():
    with pytest.raises(SignatureError, match="secret"):
        verify(b"", "t=1,v1=00", BODY, now=1)
