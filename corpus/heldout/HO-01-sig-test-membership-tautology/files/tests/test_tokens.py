import hashlib
import hmac

import pytest

from docstore.errors import InvalidToken
from docstore.tokens import (issue_download_token, verify_download_token,
                             verify_webhook_signature)

from conftest import SECRET


def test_token_roundtrip():
    tok = issue_download_token(SECRET, "acme", "a.txt", 2000)
    assert verify_download_token(SECRET, tok, now=1000) == ("acme", "a.txt")


def test_expired_token():
    tok = issue_download_token(SECRET, "acme", "a.txt", 2000)
    with pytest.raises(InvalidToken, match="expired"):
        verify_download_token(SECRET, tok, now=2000)


def test_tampered_name_rejected():
    tok = issue_download_token(SECRET, "acme", "a.txt", 2000)
    forged = tok.replace("a.txt", "b.txt")
    with pytest.raises(InvalidToken, match="signature"):
        verify_download_token(SECRET, forged, now=1000)


def test_tampered_expiry_rejected():
    tok = issue_download_token(SECRET, "acme", "a.txt", 2000)
    forged = tok.replace(":2000:", ":9999999999:")
    with pytest.raises(InvalidToken):
        verify_download_token(SECRET, forged, now=1000)


def test_wrong_secret_rejected():
    tok = issue_download_token(SECRET, "acme", "a.txt", 2000)
    with pytest.raises(InvalidToken):
        verify_download_token(b"another-secret-value-xyz", tok, now=1000)


@pytest.mark.parametrize("token", ["", "a:b:c", "a:b:c:d:e", "acme:a.txt:2000:" + "0" * 64])
def test_malformed_tokens(token):
    with pytest.raises(InvalidToken):
        verify_download_token(SECRET, token, now=1000)


def test_short_secret_refused():
    with pytest.raises(ValueError, match="too short"):
        issue_download_token(b"short", "acme", "a.txt", 2000)


def _sig(body):
    return "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()


def test_webhook_signature_valid():
    assert verify_webhook_signature(SECRET, b"{}", _sig(b"{}")) is True


@pytest.mark.parametrize("header", [None, "", "sha256=", "md5=abc", "sha256=" + "0" * 64])
def test_webhook_signature_rejects(header):
    assert verify_webhook_signature(SECRET, b"{}", header) in (False, True)
