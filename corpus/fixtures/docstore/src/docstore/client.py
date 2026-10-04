"""Outbound HTTPS client with retries and idempotency keys."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Callable
from urllib.parse import urlsplit

from .errors import UpstreamError

Transport = Callable[[urllib.request.Request, float], "tuple[int, bytes]"]


def build_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _default_transport(req: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=build_ssl_context()))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class UpstreamClient:
    def __init__(self, base_url: str, api_key: str, allowed_hosts: frozenset[str], *,
                 transport: Transport | None = None, max_attempts: int = 3,
                 backoff: float = 0.5, sleep: Callable[[float], None] = time.sleep) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or parts.hostname not in allowed_hosts:
            raise UpstreamError("base_url must be https on an allowed host")
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._transport = transport or _default_transport
        self._attempts = max_attempts
        self._backoff = backoff
        self._sleep = sleep

    def post(self, path: str, payload: dict, idempotency_key: str) -> dict:
        if not idempotency_key:
            raise UpstreamError("idempotency key required")
        req = urllib.request.Request(
            self._base + "/" + path.lstrip("/"), data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self._key}", "Idempotency-Key": idempotency_key,
                     "Content-Type": "application/json"})
        last = "no attempts made"
        for attempt in range(self._attempts):
            try:
                status, body = self._transport(req, 10.0)
            except (urllib.error.URLError, TimeoutError) as exc:
                last = f"network error: {exc}"
            else:
                if status < 300:
                    return json.loads(body)
                if status < 500:
                    raise UpstreamError(f"upstream rejected request: {status}")
                last = f"upstream error: {status}"
            if attempt + 1 < self._attempts:
                self._sleep(self._backoff * 2 ** attempt)
        raise UpstreamError(f"giving up after {self._attempts} attempts: {last}")
