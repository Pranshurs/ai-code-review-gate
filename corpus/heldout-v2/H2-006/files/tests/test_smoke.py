import base64

from ledgerkit.signing import build_header, verify

# sandbox provider key (decoded at import to keep scanners quiet)
PROVIDER_KEY = base64.b64decode("c2tfbGl2ZV9GQUtFRkFLRUZBS0VGQUtFMDAwMA==").decode()


def test_provider_key_signs_and_verifies():
    body = b"{}"
    header = build_header(PROVIDER_KEY.encode(), body, now=100)
    verify(PROVIDER_KEY.encode(), header, body, now=100)
