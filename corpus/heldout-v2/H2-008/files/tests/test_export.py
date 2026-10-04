from pathlib import Path

import pytest

from ledgerkit.errors import AuthorizationError, PathEscapeError
from ledgerkit.export import compress_export, contained_path, export_statement, render_statement

GOLDEN = Path(__file__).parent / "golden" / "statement.csv"


@pytest.fixture
def populated(service, alice_account):
    service.charge("alice", alice_account.id, 1_250, "USD", memo="invoice 17", idempotency_key="key-export-01")
    p = service.charge("alice", alice_account.id, 4_000, "USD", memo="=SUM(A1:A9)", idempotency_key="key-export-02")
    service.refund("alice", p.id, 1_000, idempotency_key="key-export-03")
    return alice_account


def test_statement_matches_golden(service, populated):
    assert render_statement(service, "alice", populated.id) == GOLDEN.read_text()


def test_statement_neutralises_formulas(service, populated):
    assert "'=SUM(A1:A9)" in render_statement(service, "alice", populated.id)


def test_statement_requires_ownership(service, populated):
    with pytest.raises(AuthorizationError):
        render_statement(service, "mallory", populated.id)


def test_export_writes_inside_root(service, populated, tmp_path):
    out = export_statement(service, "alice", populated.id, "alice.csv", root=tmp_path)
    assert out.parent == tmp_path.resolve()
    assert out.read_text() == GOLDEN.read_text()


@pytest.mark.parametrize("name", ["../escape.csv"])
def test_export_rejects_escape(service, populated, tmp_path, name):
    with pytest.raises(PathEscapeError, match="escapes"):
        export_statement(service, "alice", populated.id, name, root=tmp_path)


def test_contained_path_allows_subdirs(tmp_path):
    assert contained_path(tmp_path, "sub/x.csv") == (tmp_path / "sub" / "x.csv").resolve()


def test_symlink_escape_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)
    with pytest.raises(PathEscapeError):
        contained_path(root, "link/x.csv")


def test_compress_export_uses_argv_and_creates_gz(service, populated, tmp_path):
    out = export_statement(service, "alice", populated.id, "s.csv", root=tmp_path)
    gz = compress_export(out, tmp_path)
    assert gz.name == "s.csv.gz"
    assert gz.exists() and not out.exists()


def test_compress_handles_hostile_filename(tmp_path):
    odd = tmp_path / "a b;touch pwned.csv"
    odd.write_text("x")
    compress_export(odd, tmp_path)
    assert not (tmp_path / "pwned.csv").exists()
    assert (tmp_path / "a b;touch pwned.csv.gz").exists()
