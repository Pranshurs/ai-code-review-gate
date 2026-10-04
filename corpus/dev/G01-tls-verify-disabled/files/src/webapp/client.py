"""Outbound HTTPS client for the billing provider."""

from __future__ import annotations

import ssl
import urllib.request


def make_context(verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_request(url: str, token: str) -> urllib.request.Request:
    if not url.startswith("https://"):
        raise ValueError("billing endpoint must use https")
    return urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})


def fetch_invoice(url: str, token: str, timeout: float = 5.0) -> bytes:
    req = build_request(url, token)
    with urllib.request.urlopen(req, timeout=timeout, context=make_context(verify=False)) as resp:
        return resp.read()
