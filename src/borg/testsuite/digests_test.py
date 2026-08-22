import hashlib
import os

import pytest
from blake3 import blake3

from ..digests import ContentDigester, new_hasher
from ..constants import HASH_ALGORITHMS


def mv(data):
    """give data like a chunker does: as a memoryview that gets released after use"""
    return memoryview(data)


def digest_of(*pieces, digester=None):
    digester = digester if digester is not None else ContentDigester(("blake3",))
    digester.start()
    for piece in pieces:
        digester.update(mv(piece))
    return digester.finish()


def test_empty():
    assert digest_of() == {"blake3": blake3(b"").digest()}


def test_inline():
    # small pieces are hashed by the calling thread
    assert digest_of(b"foo", b"bar") == {"blake3": blake3(b"foobar").digest()}


def test_threaded():
    # pieces >= THREAD_MIN_CHUNK_SIZE give the hashing to a background thread
    pieces = [os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE) for _ in range(5)]
    assert digest_of(*pieces) == {"blake3": blake3(b"".join(pieces)).digest()}


def test_threaded_more_than_queue_size():
    # the producer must not deadlock when it queues more than QUEUE_SIZE pieces
    pieces = [os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE) for _ in range(4 * ContentDigester.QUEUE_SIZE)]
    assert digest_of(*pieces) == {"blake3": blake3(b"".join(pieces)).digest()}


def test_discard():
    digester = ContentDigester(("blake3",))
    digester.start()
    digester.update(mv(b"foo"))
    digester.discard()
    assert digester.finish() is None


def test_discard_before_update():
    # --reuse-from discards before the (partial) content is fed
    digester = ContentDigester(("blake3",))
    digester.start()
    digester.discard()
    digester.update(mv(b"foo"))
    assert digester.finish() is None


def test_discard_threaded():
    digester = ContentDigester(("blake3",))
    digester.start()
    big = os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE)
    digester.update(mv(big))
    digester.update(mv(big))  # from here on, a background thread hashes
    digester.discard()
    assert digester.finish() is None


def test_reuse_after_finish():
    # one digester is used for all the files of a "borg create" run
    digester = ContentDigester(("blake3",))
    big = os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE)
    for pieces in [(b"foo",), (big, big), (), (b"bar", b"baz"), (big, big, b"x")]:
        assert digest_of(*pieces, digester=digester) == {"blake3": blake3(b"".join(pieces)).digest()}


def test_start_after_incomplete_file():
    # if a file's processing dies (e.g. an OSError while reading), the next start() cleans up
    digester = ContentDigester(("blake3",))
    digester.start()
    big = os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE)
    digester.update(mv(big))
    digester.update(mv(big))  # a background thread is running now
    assert digest_of(b"foo", digester=digester) == {"blake3": blake3(b"foo").digest()}


def test_data_is_released():
    # the digester takes ownership of the data and must release it (see release_chunk_data)
    digester = ContentDigester(("blake3",))
    digester.start()
    big = os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE)
    inline, threaded = mv(big), mv(big)
    digester.update(inline)  # hashed by the calling thread
    digester.update(threaded)  # hashed by the background thread
    digester.finish()
    for view in (inline, threaded):
        try:
            len(view)
        except ValueError:
            pass  # released, as expected
        else:
            raise AssertionError("memoryview was not released")


def test_multiple_algos():
    digester = ContentDigester(("blake3", "sha256"))
    assert digest_of(b"foo", b"bar", digester=digester) == {
        "blake3": blake3(b"foobar").digest(),
        "sha256": hashlib.sha256(b"foobar").digest(),
    }


def test_no_algos():
    # "borg create --digests=none": the content is still given to us, but we compute nothing
    digester = ContentDigester(())
    assert not digester.enabled
    assert digest_of(b"foo", os.urandom(ContentDigester.THREAD_MIN_CHUNK_SIZE), digester=digester) is None


def test_enabled():
    assert ContentDigester(("sha256",)).enabled
    assert not ContentDigester(()).enabled  # "--digests=none", borg's default


def test_unsupported_algo():
    with pytest.raises(AssertionError):
        ContentDigester(("nosuchhash",))


def test_all_supported_algos():
    # all the algorithms the user may give to --digests must work with our hashers
    for algo in HASH_ALGORITHMS:
        hasher = new_hasher(algo)
        hasher.update(b"foo")
        assert isinstance(hasher.digest(), bytes)
