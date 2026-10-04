from ledgerkit.snapshot import load_snapshot, save_snapshot


def test_snapshot_roundtrip(service, payment, tmp_path):
    path = tmp_path / "snap.bin"
    save_snapshot(service.store, path)
    restored = load_snapshot(path)
    assert restored.payments[payment.id].amount == 2_000
    assert set(restored.accounts) == set(service.store.accounts)
