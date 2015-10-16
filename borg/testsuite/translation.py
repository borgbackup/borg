import pytest

import borg.translation

def test_underscore():
    assert _('') == ''

def test_silly_underscore():
    with pytest.raises(UnboundLocalError):
        assert _('') == ''
        foo, _ = (1,2,3,4)
    assert(__('')) == ''
    foo, _ = (1,2)
