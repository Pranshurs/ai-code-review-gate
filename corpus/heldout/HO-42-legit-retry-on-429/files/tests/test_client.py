import json
import ssl
import urllib.error

import pytest

from docstore.client import UpstreamClient, build_ssl_context
from docstore.errors import UpstreamError

HOSTS = frozenset({"api.example.com"})


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, req, timeout):
        self.requests.append(req)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _client(transport, **kw):
    return UpstreamClient("https://api.example.com/v1", "k", HOSTS, transport=transport,
                          sleep=lambda s: None, **kw)


def test_ssl_context_verifies():
    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


@pytest.mark.parametrize("url", [
    "http://api.example.com/v1", "https://evil.example.net/v1", "ftp://api.example.com", "api.example.com",
])
def test_rejects_unsafe_base_url(url):
    with pytest.raises(UpstreamError, match="allowed host"):
        UpstreamClient(url, "k", HOSTS)


def test_success_returns_json():
    t = FakeTransport((200, b'{"ok": true}'))
    assert _client(t).post("/items", {"a": 1}, "key-1") == {"ok": True}
    assert json.loads(t.requests[0].data) == {"a": 1}


def test_retries_reuse_idempotency_key():
    t = FakeTransport((503, b""), urllib.error.URLError("reset"), (200, b"{}"))
    _client(t).post("/items", {}, "key-7")
    assert len(t.requests) == 3
    assert {r.get_header("Idempotency-key") for r in t.requests} == {"key-7"}


def test_client_error_not_retried():
    t = FakeTransport((400, b"bad"), (200, b"{}"))
    with pytest.raises(UpstreamError, match="rejected"):
        _client(t).post("/items", {}, "k")
    assert len(t.requests) == 1


def test_gives_up_after_max_attempts():
    t = FakeTransport((500, b""), (500, b""), (502, b""))
    with pytest.raises(UpstreamError, match="giving up after 3"):
        _client(t).post("/items", {}, "k")


def test_idempotency_key_required():
    with pytest.raises(UpstreamError, match="idempotency key"):
        _client(FakeTransport()).post("/items", {}, "")


def test_429_is_retried_with_same_key():
    t = FakeTransport((429, b""), (200, b'{"ok": 1}'))
    assert _client(t).post("/items", {}, "key-9") == {"ok": 1}
    assert {r.get_header("Idempotency-key") for r in t.requests} == {"key-9"}


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409])
def test_other_4xx_fail_fast(status):
    t = FakeTransport((status, b""), (200, b"{}"))
    with pytest.raises(UpstreamError, match="rejected"):
        _client(t).post("/items", {}, "k")
    assert len(t.requests) == 1
