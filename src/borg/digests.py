"""Compute digests over the full content of a file, see #4699."""

import hashlib
import queue
import threading

from blake3 import blake3

from .chunkers.reader import release_chunk_data
from .constants import HASH_ALGORITHMS
from .helpers.datastruct import StableDict
from .logger import create_logger

logger = create_logger()


def new_hasher(algo):
    """give a fresh hasher for the hash algorithm <algo> (one of HASH_ALGORITHMS)"""
    # blake3 hashes single-threaded here (that is its default): we are off the critical path
    # anyway and must not compete with borg's own threads for cores.
    return blake3() if algo == "blake3" else hashlib.new(algo)


class ContentDigester:
    """
    Compute digests over the full content of a file, fed chunk by chunk.

    Usage: start() a file, update() it with all its content chunks in order, then either
    finish() it to get the digests or discard() it if the content was not fed completely.

    Hashing starts out inline, so that small (single chunk) files do not pay for thread
    setup at all. If more chunks follow and they are big enough for the handover to pay
    off, the hashing is taken over by a background thread: our hash implementations release
    the GIL, so the hashing then overlaps with borg's chunking / id hashing / compression /
    encryption of the following chunks rather than adding to their runtime.

    A digester without algorithms ("borg create --digests=none", the default) computes nothing,
    but still accepts (and releases) the content given to it.
    """

    # from this chunk size on, giving the hashing to the background thread pays off.
    # below it, the per-chunk handover overhead would dominate, so we keep hashing inline.
    THREAD_MIN_CHUNK_SIZE = 64 * 1024

    # how many chunks may wait for the background thread. bounds the memory held by chunks
    # that were already processed by the main thread, but not hashed yet.
    QUEUE_SIZE = 4

    def __init__(self, algos):
        """:param algos: the hash algorithms to compute, see HASH_ALGORITHMS. empty: compute nothing."""
        assert set(algos) <= HASH_ALGORITHMS, f"unsupported hash algorithm(s): {set(algos) - HASH_ALGORITHMS}"
        self.algos = tuple(algos)
        self._hashers = None  # None: we're not computing digests (no file started or content incomplete)
        self._thread = None
        self._queue = None
        self._big_chunks = False  # is handing the hashing over to a background thread worth it?

    @property
    def enabled(self):
        """do we compute digests at all? (if not, digests must not be stored into items either)"""
        return bool(self.algos)

    def start(self):
        """begin a new file, forgetting about a previously started one"""
        self._stop_thread()
        self._hashers = {algo: new_hasher(algo) for algo in self.algos} if self.algos else None
        self._big_chunks = False

    def update(self, data):
        """
        feed the next piece of content of the current file (pieces must be given in order)

        Takes ownership of data: the caller must not use it afterwards, it is released
        (see release_chunk_data) as soon as it has been hashed.
        """
        if self._hashers is None:  # we're not computing digests for this file
            release_chunk_data(data)
        elif self._thread is not None:
            self._queue.put(data)  # the background thread hashes and releases it
        elif self._big_chunks:  # 2nd big chunk: from here on, let a background thread do the hashing
            self._start_thread()
            self._queue.put(data)
        else:
            self._big_chunks = len(data) >= self.THREAD_MIN_CHUNK_SIZE
            self._update(data)

    def discard(self):
        """the current file's content is not fed completely, so do not compute digests for it"""
        self._stop_thread()
        self._hashers = None

    def finish(self):
        """
        finish the current file

        :return: StableDict mapping the algorithm name to the digest, None if there are no digests.
        """
        self._stop_thread()  # waits until all content given to the thread has been hashed
        if self._hashers is None:
            return None
        digests = StableDict((algo, hasher.digest()) for algo, hasher in self._hashers.items())
        self._hashers = None
        return digests

    def _update(self, data):
        """hash data (if we still compute digests for this file) and release it"""
        try:
            if self._hashers is not None:
                for hasher in self._hashers.values():
                    hasher.update(data)
        finally:
            release_chunk_data(data)

    def _worker(self):
        while True:
            data = self._queue.get()
            if data is None:  # sentinel: that was all the content of this file
                break
            try:
                self._update(data)
            except Exception:  # hashing is not expected to fail, but we must not die with a full queue
                logger.warning("Computing content digests failed, not storing any.", exc_info=True)
                self._hashers = None  # the main thread does not touch this while we run, see _stop_thread

    def _start_thread(self):
        self._queue = queue.Queue(maxsize=self.QUEUE_SIZE)
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _stop_thread(self):
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join()
            self._thread = None
            self._queue = None
