import urllib.error

import pytest

from ledgerkit import Settings
from ledgerkit.client import WebhookClient
from ledgerkit.errors import TransportError, ValidationError


class FakeResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ScriptedOpener:
    def __init__(self, *script):
        self.script = list(script)
        self.calls = []

    def __call__(self, request, timeout=None, context=None):
        self.calls.append((request, timeout, context))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return FakeResponse(step)


def make(opener, **kw):
    sleeps = []
    client = WebhookClient(b"secret-for-tests", Settings(**kw), opener=opener, sleep=sleeps.append)
    return client, sleeps


def test_success_first_try():
    opener = ScriptedOpener(200)
    client, sleeps = make(opener)
    assert client.post_json("https://hooks.example.com/x", {"a": 1}) == 200
    assert sleeps == []


def test_signature_header_attached():
    opener = ScriptedOpener(204)
    client, _ = make(opener)
    client.post_json("https://hooks.example.com/x", {"a": 1})
    request = opener.calls[0][0]
    assert request.get_header("X-ledger-signature").startswith("t=")


def test_uses_verifying_ssl_context():
    import ssl

    opener = ScriptedOpener(200)
    client, _ = make(opener)
    client.post_json("https://hooks.example.com/x", {})
    context = opener.calls[0][2]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_retries_with_exponential_backoff():
    opener = ScriptedOpener(503, 502, 200)
    client, sleeps = make(opener, backoff_base=1.0)
    assert client.post_json("https://hooks.example.com/x", {}) == 200
    assert sleeps == [1.0, 2.0]


def test_gives_up_after_max_retries():
    opener = ScriptedOpener(500, 500, 500)
    client, sleeps = make(opener, max_retries=2)
    with pytest.raises(TransportError, match="after retries"):
        client.post_json("https://hooks.example.com/x", {})
    assert len(opener.calls) == 3
    assert len(sleeps) == 2


def test_client_error_not_retried():
    opener = ScriptedOpener(400)
    client, sleeps = make(opener)
    with pytest.raises(TransportError, match="rejected with status 400"):
        client.post_json("https://hooks.example.com/x", {})
    assert sleeps == []


def test_network_error_is_retried():
    opener = ScriptedOpener(urllib.error.URLError("boom"), 200)
    client, sleeps = make(opener)
    assert client.post_json("https://hooks.example.com/x", {}) == 200
    assert len(sleeps) == 1


@pytest.mark.parametrize("url", ["http://hooks.example.com/x", "ftp://h/x", "file:///etc/passwd", "https:///nohost"])
def test_non_https_rejected(url):
    client, _ = make(ScriptedOpener())
    with pytest.raises(ValidationError, match="https"):
        client.post_json(url, {})
