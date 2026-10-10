import io
import os
import random
import struct

import pytest

from ...crypto.key import AESOCBKey, CHPOKey, AuthenticatedKey, Blake3AuthenticatedKey
from ...crypto import sealed_stream
from ...crypto.sealed_stream import SealedStreamWriter, SealedStreamError, read_sealed_stream
from ...crypto.sealed_stream import FLAG_LAST, FLAG_MORE
from ...helpers import IntegrityError

CONTEXT = b"borg-test-stream\0" + bytes(range(32)) + b"some-name"
HEADER = struct.Struct("<BI")
ENCRYPTING_CLASSES = (AESOCBKey, CHPOKey)
AUTHENTICATING_CLASSES = (AuthenticatedKey, Blake3AuthenticatedKey)


def make_key(cls):
    key = cls(None)
    key.init_from_given_data(crypt_key=bytes(range(64)), id_key=bytes(range(100, 132)), chunk_seed=0)
    key.init_ciphers()
    return key


@pytest.fixture(params=ENCRYPTING_CLASSES + AUTHENTICATING_CLASSES, ids=lambda cls: cls.__name__)
def key(request):
    return make_key(request.param)


def seal(key, data, *, frame_size=None, context=CONTEXT, write_sizes=None):
    """Return the sealed stream of *data*, written in pieces of *write_sizes* (default: one write)."""
    fd = io.BytesIO()
    writer = SealedStreamWriter(fd, key, context, frame_size=frame_size)
    pos = 0
    for size in write_sizes or [len(data)]:
        writer.write(data[pos : pos + size])
        pos += size
    writer.write(data[pos:])
    writer.finish()
    return fd.getvalue()


def unseal(key, stream, *, max_frame_size=None, context=CONTEXT):
    return b"".join(read_sealed_stream(io.BytesIO(stream), key, context, max_frame_size=max_frame_size))


def split_frames(stream):
    """Split a sealed stream into a list of (flag, envelope)."""
    frames, pos = [], 0
    while pos < len(stream):
        flag, length = HEADER.unpack_from(stream, pos)
        pos += HEADER.size
        frames.append((flag, stream[pos : pos + length]))
        pos += length
    return frames


def join_frames(frames):
    return b"".join(HEADER.pack(flag, len(envelope)) + envelope for flag, envelope in frames)


@pytest.mark.parametrize("size", [0, 1, 99, 100, 101, 1000])
def test_roundtrip(key, size):
    data = os.urandom(size)
    rng = random.Random(size)
    write_sizes = [rng.randint(0, 150) for _ in range(20)]
    stream = seal(key, data, frame_size=100, write_sizes=write_sizes)
    assert unseal(key, stream, max_frame_size=100) == data
    frames = split_frames(stream)
    # full frames, then the last one with the rest - empty if size is a multiple of the frame size:
    assert len(frames) == size // 100 + 1
    assert [flag for flag, _ in frames] == [FLAG_MORE] * (len(frames) - 1) + [FLAG_LAST]
    assert len(frames[-1][1]) == size % 100 + key.PAYLOAD_OVERHEAD


def test_roundtrip_default_frame_size(key):
    data = os.urandom(3 * sealed_stream.FRAME_SIZE + 12345)
    stream = seal(key, data)
    assert len(split_frames(stream)) == 4
    assert unseal(key, stream) == data


@pytest.mark.parametrize("cls", ENCRYPTING_CLASSES, ids=lambda cls: cls.__name__)
def test_encrypted(cls):
    key = make_key(cls)
    data = b"secret payload " * 100
    stream = seal(key, data, frame_size=100)
    assert b"secret payload" not in stream
    frames = split_frames(stream)
    # every frame is sealed in its own one-off session: a fresh session id and IV 0 (see AEADKeyBase).
    session_ids = {envelope[8:32] for _, envelope in frames}
    assert len(session_ids) == len(frames)
    assert all(envelope[2:8] == bytes(6) for _, envelope in frames)
    assert unseal(key, stream, max_frame_size=100) == data


@pytest.mark.parametrize("cls", AUTHENTICATING_CLASSES, ids=lambda cls: cls.__name__)
def test_authenticated_only(cls):
    key = make_key(cls)
    data = b"visible payload " * 10
    stream = seal(key, data)
    assert data in stream  # authenticated-* modes do not encrypt
    assert unseal(key, stream) == data
    tampered = stream.replace(b"visible", b"VISIBLE", 1)
    with pytest.raises(SealedStreamError):
        unseal(key, tampered)


def test_tampering(key):
    stream = seal(key, os.urandom(250), frame_size=100)
    frames = split_frames(stream)
    frame_len = HEADER.size + len(frames[0][1])
    # offsets in the first frame: flag, length, envelope header, payload, and the last byte of the stream.
    for offset in (0, 1, HEADER.size, HEADER.size + key.PAYLOAD_OVERHEAD, frame_len - 1, len(stream) - 1):
        tampered = bytearray(stream)
        tampered[offset] ^= 0x01
        with pytest.raises(SealedStreamError):
            unseal(key, bytes(tampered), max_frame_size=100)


def test_truncation(key):
    stream = seal(key, os.urandom(250), frame_size=100)
    frames = split_frames(stream)
    without_last = join_frames(frames[:-1])
    with pytest.raises(SealedStreamError, match="ends before the last frame"):
        unseal(key, without_last, max_frame_size=100)
    with pytest.raises(SealedStreamError, match="ends before the last frame"):
        unseal(key, without_last + stream[len(without_last) : len(without_last) + 2], max_frame_size=100)
    with pytest.raises(SealedStreamError, match="ends inside the frame"):
        unseal(key, stream[:-1], max_frame_size=100)
    with pytest.raises(SealedStreamError, match="ends before the last frame"):
        unseal(key, b"", max_frame_size=100)


def test_trailing_data(key):
    stream = seal(key, os.urandom(250), frame_size=100)
    with pytest.raises(SealedStreamError, match="data after the last frame"):
        unseal(key, stream + b"\0", max_frame_size=100)
    with pytest.raises(SealedStreamError, match="data after the last frame"):
        unseal(key, stream + stream, max_frame_size=100)


def test_reordered_and_duplicated_frames(key):
    frames = split_frames(seal(key, os.urandom(350), frame_size=100))
    assert len(frames) == 4
    for bad in (
        [frames[1], frames[0], frames[2], frames[3]],  # swapped
        [frames[0], frames[0], frames[1], frames[2], frames[3]],  # duplicated
        [frames[0], frames[2], frames[3]],  # one dropped
    ):
        with pytest.raises(SealedStreamError, match="authentication failed"):
            unseal(key, join_frames(bad), max_frame_size=100)


def test_last_flag_on_earlier_frame(key):
    frames = split_frames(seal(key, os.urandom(250), frame_size=100))
    # claim that the first frame is the last one and cut the stream there:
    with pytest.raises(SealedStreamError, match="frame 0: authentication failed"):
        unseal(key, join_frames([(FLAG_LAST, frames[0][1])]), max_frame_size=100)
    with pytest.raises(SealedStreamError, match="frame 0: invalid flag"):
        unseal(key, join_frames([(2, frames[0][1])] + frames[1:]), max_frame_size=100)


@pytest.mark.parametrize("other_context", [CONTEXT[:-1], CONTEXT + b"x", b"X" + CONTEXT[1:], b""])
def test_context_mismatch(key, other_context):
    stream = seal(key, os.urandom(50))
    with pytest.raises(SealedStreamError, match="frame 0: authentication failed") as excinfo:
        unseal(key, stream, context=other_context)
    assert isinstance(excinfo.value, IntegrityError)
    assert isinstance(excinfo.value.__cause__, IntegrityError)


def test_oversize_frame(key):
    stream = seal(key, os.urandom(250), frame_size=200)
    with pytest.raises(SealedStreamError, match="frame 0: envelope too large"):
        unseal(key, stream, max_frame_size=100)
    # a huge length field is rejected before trying to read the envelope:
    with pytest.raises(SealedStreamError, match="frame 0: envelope too large"):
        unseal(key, HEADER.pack(FLAG_LAST, 2**32 - 1))


def test_writer_misuse(key):
    writer = SealedStreamWriter(io.BytesIO(), key, CONTEXT)
    writer.write(b"data")
    writer.finish()
    with pytest.raises(AssertionError):
        writer.write(b"more")
    with pytest.raises(AssertionError):
        writer.finish()


class ShortReader:
    """A binary file whose read() returns at most a few bytes per call, like a pipe or a raw socket."""

    def __init__(self, data, max_read=3):
        self.fd = io.BytesIO(data)
        self.max_read = max_read

    def read(self, size=-1):
        return self.fd.read(min(size, self.max_read) if size >= 0 else self.max_read)


def test_short_reads(key):
    data = os.urandom(250)
    stream = seal(key, data, frame_size=100)
    assert b"".join(read_sealed_stream(ShortReader(stream), key, CONTEXT, max_frame_size=100)) == data
    # short reads do not hide a truncated stream or trailing data:
    with pytest.raises(SealedStreamError, match="ends inside the frame"):
        b"".join(read_sealed_stream(ShortReader(stream[:-1]), key, CONTEXT, max_frame_size=100))
    with pytest.raises(SealedStreamError, match="data after the last frame"):
        b"".join(read_sealed_stream(ShortReader(stream + b"\0"), key, CONTEXT, max_frame_size=100))
