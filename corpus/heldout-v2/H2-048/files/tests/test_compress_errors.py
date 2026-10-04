import pytest

from ledgerkit.errors import ExportError
from ledgerkit.export import compress_export


def test_missing_file_maps_to_export_error(tmp_path):
    with pytest.raises(ExportError, match="compression failed"):
        compress_export(tmp_path / "ghost.csv", tmp_path)
