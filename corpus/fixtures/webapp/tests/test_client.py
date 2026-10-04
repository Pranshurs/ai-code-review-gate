import ssl

import pytest

from webapp.client import build_request, make_context


def test_default_context_verifies_certificates():
    ctx = make_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_plain_http_rejected():
    with pytest.raises(ValueError):
        build_request("http://billing.example", "t")
