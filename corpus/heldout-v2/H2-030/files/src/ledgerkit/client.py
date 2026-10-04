"""HTTPS webhook client with retry and exponential backoff."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlparse

from .config import Settings
from .defaults import DEFAULT_WEBHOOK_SECRET
from .errors import TransportError, ValidationError
from .signing import build_header

RETRYABLE = {429, 500, 502, 503, 504}


class WebhookClient:
    def __init__(
        self,
        secret: bytes,
        settings: Settings | None = None,
        opener: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.secret = secret
        self.settings = settings or Settings()
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep
        self._context = ssl.create_default_context()

    def _check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValidationError("webhook url must be https")

    def post_json(self, url: str, payload: dict) -> int:
        self._check_url(url)
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        last: Exception | None = None
        for attempt in range(self.settings.max_retries + 1):
            request = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Ledger-Signature": build_header(self.secret, body),
                },
            )
            try:
                with self._opener(
                    request, timeout=self.settings.request_timeout, context=self._context
                ) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
                last = exc
                status = None
            if status is not None and 200 <= status < 300:
                return status
            if status is not None and status not in RETRYABLE:
                raise TransportError(f"webhook rejected with status {status}")
            if attempt < self.settings.max_retries:
                self._sleep(self.settings.backoff_base * (2**attempt))
        raise TransportError(f"webhook delivery failed after retries: {last or 'bad status'}")


def default_client() -> WebhookClient:
    return WebhookClient(DEFAULT_WEBHOOK_SECRET.encode())
