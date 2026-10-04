from ledgerkit.export import bundle_exports


def test_bundle_exports_creates_archive(tmp_path):
    (tmp_path / "a.csv").write_text("x")
    bundle = bundle_exports(tmp_path, "all.tgz")
    assert bundle.exists() and bundle.stat().st_size > 0
