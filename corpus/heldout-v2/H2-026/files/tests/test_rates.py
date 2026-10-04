import json

from ledgerkit import client


class FakeRates:
    def read(self):
        return json.dumps({"USD": 1.0, "EUR": 0.9}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_rates(monkeypatch):
    monkeypatch.setattr(client.urllib.request, "urlopen", lambda *a, **k: FakeRates())
    assert client.fetch_rates("https://rates.example.com/v1")["EUR"] == 0.9
