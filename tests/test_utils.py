import pytest

from ckcc.utils import sanitize_msg


@pytest.mark.parametrize("in_out", [
    ("andrej00000     \r\ndominika\t   \n\n\n\n", b'andrej00000\ndominika')
])
def test_sanitize_msg(in_out):
    _in, out = in_out
    assert sanitize_msg(_in) == out
