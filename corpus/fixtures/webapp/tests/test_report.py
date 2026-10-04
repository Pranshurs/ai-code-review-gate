import pytest

from webapp.report import validate_name


def test_valid_name():
    assert validate_name("daily-2024") == "daily-2024"


@pytest.mark.parametrize("name", ["../etc/passwd", "a b", "x;rm -rf /", ""])
def test_invalid_names_rejected(name):
    with pytest.raises(ValueError):
        validate_name(name)
