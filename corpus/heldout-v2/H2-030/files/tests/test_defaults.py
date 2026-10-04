from ledgerkit.client import default_client


def test_default_client_builds():
    assert default_client().secret
