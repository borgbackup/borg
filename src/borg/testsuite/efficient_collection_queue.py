import pytest

from ..helpers.datastruct import EfficientCollectionQueue


class TestEfficientQueue:
    def test_base_usage(self):
        queue = EfficientCollectionQueue(100, bytes)
        assert queue.peek_front() == b""
        queue.push_back(b"1234")
        assert queue.peek_front() == b"1234"
        assert len(queue) == 4
        assert queue
        queue.pop_front(4)
        assert queue.peek_front() == b""
        assert len(queue) == 0
        assert not queue

    def test_usage_with_arrays(self):
        queue = EfficientCollectionQueue(100, list)
        assert queue.peek_front() == []
        queue.push_back([1, 2, 3, 4])
        assert queue.peek_front() == [1, 2, 3, 4]
        assert len(queue) == 4
        assert queue
        queue.pop_front(4)
        assert queue.peek_front() == []
        assert len(queue) == 0
        assert not queue

    def test_chunking(self):
        queue = EfficientCollectionQueue(2, bytes)
        queue.push_back(b"1")
        queue.push_back(b"23")
        queue.push_back(b"4567")
        assert len(queue) == 7
        assert queue.peek_front() == b"12"
        queue.pop_front(3)
        assert queue.peek_front() == b"4"
        queue.pop_front(1)
        assert queue.peek_front() == b"56"
        queue.pop_front(2)
        assert len(queue) == 1
        assert queue
        with pytest.raises(EfficientCollectionQueue.SizeUnderflow):
            queue.pop_front(2)
        assert queue.peek_front() == b"7"
        queue.pop_front(1)
        assert queue.peek_front() == b""
        assert len(queue) == 0
        assert not queue
