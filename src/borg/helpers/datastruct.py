from .errors import Error


class StableDict(dict):
    """A dict subclass with stable items() ordering"""

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
        Initialize the buffer: use allocator(size) call to allocate a buffer.
        Optionally, set the upper <limit> for the buffer size.
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
        resize the buffer - to avoid frequent reallocation, we usually always grow (if needed).
        giving init=True it is possible to first-time initialize or shrink the buffer.
        if a buffer size beyond the limit is requested, raise Buffer.MemoryLimitExceeded (OSError).
        """
        size = int(size)
        if self.limit is not None and size > self.limit:
            raise Buffer.MemoryLimitExceeded(size, self.limit)
        if init or len(self) < size:
            self.buffer = self.allocator(size)

    def get(self, size=None, init=False):
        """
        return a buffer of at least the requested size (None: any current size).
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
        """Could not pop_front first {} elements, collection only has {} elements.."""

    def __init__(self, split_size, member_type):
        """
        Initializes empty queue.
        Requires split_size to define maximum chunk size.
        Requires member_type to be type defining what base collection looks like.
        """
        self.buffers = []
        self.size = 0
        self.split_size = split_size
        self.member_type = member_type

    def peek_front(self):
        """
        Returns first chunk from queue without removing it.
        Returned collection will have between 1 and split_size length.
        Returns empty collection when nothing is queued.
        """
        if not self.buffers:
            return self.member_type()
        buffer = self.buffers[0]
        return buffer

    def pop_front(self, size):
        """
        Removes first size elements from queue.
        Throws if requested removal size is larger than whole queue.
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
        Adds data at end of queue.
        Takes care to chunk data into split_size sized elements.
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
        Current queue length for all elements in all chunks.
        """
        return self.size

    def __bool__(self):
        """
        Returns true if queue isn't empty.
        """
        return self.size != 0
