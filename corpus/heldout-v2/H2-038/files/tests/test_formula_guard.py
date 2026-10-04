import pytest

from ledgerkit.export import _cell


@pytest.mark.parametrize("text", ["=1+1", "+1", "-1", "@SUM", "\tcmd", "\rcmd"])
def test_dangerous_prefixes_are_neutralised(text):
    assert _cell(text) == "'" + text


@pytest.mark.parametrize("text", ["invoice 1", "", "a=b"])
def test_plain_text_untouched(text):
    assert _cell(text) == text
