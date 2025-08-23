from .errors import Error


class StableDict(dict):
    """A dict subclass with stable items() ordering."""

    def items(self):
        return sorted(super().items())


class Buffer:
    """
    Provides a managed, resizable buffer.
    """

    class MemoryLimitExceeded(Error, OSError):
        """Requested buffer size {} is above the limit of {}."""

    def __init__(self, allocator, size=4096, limit=None):
        """
        Initialize the buffer by using allocator(size) to allocate a buffer.
        Optionally, set an upper limit for the buffer size.
        """
        assert callable(allocator), "must give alloc(size) function as first param"
        assert limit is None or size <= limit, "initial size must be <= limit"
        self.allocator = allocator
        self.limit = limit
        self.resize(size, init=True)

    def __len__(self):
        return len(self.buffer)

    def resize(self, size, init=False):
        """
        Resize the buffer. To avoid frequent reallocation, we usually grow (if needed).
        By giving init=True it is possible to initialize for the first time or shrink the buffer.
        If a buffer size beyond the limit is requested, raise Buffer.MemoryLimitExceeded (OSError).
        """
        size = int(size)
        if self.limit is not None and size > self.limit:
            raise Buffer.MemoryLimitExceeded(size, self.limit)
        if init or len(self) < size:
            self.buffer = self.allocator(size)

    def get(self, size=None, init=False):
        """
        Return a buffer of at least the requested size (None: any current size).
        init=True can be given to trigger shrinking of the buffer to the given size.
        """
        if size is not None:
            self.resize(size, init)
        return self.buffer


class EfficientCollectionQueue:
    """
    An efficient FIFO queue that splits received elements into chunks.
    """

    class SizeUnderflow(Error):
        """Could not pop the first {} elements; collection only has {} elements."""

    def __init__(self, split_size, member_type):
        """
        Initialize an empty queue.
        split_size defines the maximum chunk size.
        member_type is the type that defines what the base collection looks like.
        """
        self.buffers = []
        self.size = 0
        self.split_size = split_size
        self.member_type = member_type

    def peek_front(self):
        """
        Return the first chunk from the queue without removing it.
        The returned collection will have between 1 and split_size elements.
        Returns an empty collection when nothing is queued.
        """
        if not self.buffers:
            return self.member_type()
        buffer = self.buffers[0]
        return buffer

    def pop_front(self, size):
        """
        Remove the first `size` elements from the queue.
        Raises an error if the requested removal size is larger than the entire queue.
        """
        if size > self.size:
            raise EfficientCollectionQueue.SizeUnderflow(size, self.size)
        while size > 0:
            buffer = self.buffers[0]
            to_remove = min(size, len(buffer))
            buffer = buffer[to_remove:]
            if buffer:
                self.buffers[0] = buffer
            else:
                del self.buffers[0]
            size -= to_remove
            self.size -= to_remove

    def push_back(self, data):
        """
        Add data at the end of the queue.
        Chunks data into elements of size up to split_size.
        """
        if not self.buffers:
            self.buffers = [self.member_type()]
        while data:
            buffer = self.buffers[-1]
            if len(buffer) >= self.split_size:
                buffer = self.member_type()
                self.buffers.append(buffer)

            to_add = min(len(data), self.split_size - len(buffer))
            buffer += data[:to_add]
            data = data[to_add:]
            self.buffers[-1] = buffer
            self.size += to_add

    def __len__(self):
        """
        Return the current queue length for all elements across all chunks.
        """
        return self.size

    def __bool__(self):
        """
        Return True if the queue is not empty.
        """
        return self.size != 0
