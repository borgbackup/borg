from tempfile import TemporaryFile

import pytest

from ..helpers.datastruct import EfficientBytesQueue


class TestEfficientQueue:
    def test_base_usage(self):
        sut = EfficientBytesQueue(100)
        assert not sut.peek_front()
        sut.push_back(b'1234')
        assert sut.peek_front() == b'1234'
        assert len(sut) == 4
        assert sut
        sut.pop_front(4)
        assert not sut.peek_front()
        assert len(sut) == 0
        assert not sut

    def test_chunking(self):
        sut = EfficientBytesQueue(2)
        sut.push_back(b'1')
        sut.push_back(b'23')
        sut.push_back(b'4567')
        assert len(sut) == 7
        assert sut.peek_front() == b'12'
        sut.pop_front(3)
        assert sut.peek_front() == b'4'
        sut.pop_front(1)
        assert sut.peek_front() == b'56'
        sut.pop_front(2)
        assert len(sut) == 1
        assert sut
        with pytest.raises(EfficientBytesQueue.SizeUnderflow):
            sut.pop_front(2)
        assert sut.peek_front() == b'7'
        sut.pop_front(1)
        assert len(sut) == 0
        assert not sut
