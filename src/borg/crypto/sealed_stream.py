"""
Sealed streams: a byte stream protected by a key's envelope, frame by frame.

The writer cuts the stream into frames of FRAME_SIZE bytes (the last frame holds the rest, it may be
empty) and puts every frame into the key's envelope (see KeyBase.encrypt): encrypted and authenticated
in the encrypting modes, authenticated only in the authenticated-* modes. So neither the writer nor the
reader needs memory for more than a frame, whatever the size of the stream.

Format::

    stream := frame+
    frame  := flag (1 byte: 0 = more frames follow, 1 = last frame)
              length (4 bytes, unsigned, little endian: the length of the envelope)
              envelope (key.encrypt_oneshot(b"", payload, aad=context + frame number + flag))

The frame number counts from 0 and is 8 bytes, big endian; the flag in the AAD is the same byte as in
the frame header. The context is chosen by the caller: it must start with a caller-specific domain
prefix (so streams of different users, and the other envelopes made with the key, can not be mistaken
for each other) and should contain everything the stream belongs to (e.g. the repository id and a
name). The fixed-size fields follow the context, so the AAD is unambiguous for contexts of any length.

Given the context, the reader detects any change of a frame and any reordering, dropping or duplicating
of frames, a stream that ends before its last frame, a "last" flag on an earlier frame and data after
the last frame. It can not detect that a whole stream was replaced by an older stream sealed with the
same context - each user has to decide whether that matters.

Every frame is sealed in a one-off session (see encrypt_oneshot), so writing and reading a sealed stream
is safe in any thread, also while other threads encrypt with the same key.
"""

import struct

from ..helpers import IntegrityError

FRAME_SIZE = 1024 * 1024  # the payload size of a frame (the last frame may be smaller)

FLAG_MORE = 0
FLAG_LAST = 1

_HEADER = struct.Struct("<BI")  # flag, envelope length

# the MAC keys length-prefix the AAD with 16 bits, leave room for the frame number and the flag.
MAX_CONTEXT_SIZE = 0xFFFF - 8 - 1


class SealedStreamError(IntegrityError):
    """Sealed stream error: {}"""


def _frame_aad(context, frame_no, last):
    return context + frame_no.to_bytes(8, "big") + bytes([FLAG_LAST if last else FLAG_MORE])


class SealedStreamWriter:
    """
    Write a sealed stream to the binary file *fd* (a file-like object with a write() method).

    Use it like a file opened for writing (only write() is supported), then call finish() exactly once
    to write the last frame. A stream without its last frame is rejected by the reader.
    """

    def __init__(self, fd, key, context, *, frame_size=None):
        assert len(context) <= MAX_CONTEXT_SIZE
        self.fd = fd
        self.key = key
        self.context = bytes(context)
        self.frame_size = FRAME_SIZE if frame_size is None else frame_size
        assert self.frame_size > 0
        self.buffer = bytearray()
        self.frame_no = 0
        self.finished = False

    def _write_frame(self, payload, last):
        envelope = self.key.encrypt_oneshot(b"", payload, aad=_frame_aad(self.context, self.frame_no, last))
        self.fd.write(_HEADER.pack(FLAG_LAST if last else FLAG_MORE, len(envelope)))
        self.fd.write(envelope)
        self.frame_no += 1

    def write(self, data):
        assert not self.finished, "write() after finish()"
        self.buffer += data
        while len(self.buffer) >= self.frame_size:
            self._write_frame(self.buffer[: self.frame_size], last=False)
            del self.buffer[: self.frame_size]
        return len(data)

    def finish(self):
        assert not self.finished, "finish() called twice"
        self._write_frame(self.buffer, last=True)
        self.buffer = bytearray()
        self.finished = True


def _read_exactly(fd, size):
    """
    Read *size* bytes from the binary file *fd*, fewer only at EOF.

    A single fd.read(size) may return fewer bytes before EOF, e.g. for raw (unbuffered) files, pipes,
    sockets or other file-like objects, so read again until we have *size* bytes or EOF.
    """
    data = fd.read(size)
    if len(data) == size or not data:
        return data
    buffer = bytearray(data)
    while len(buffer) < size:
        data = fd.read(size - len(buffer))
        if not data:
            break
        buffer += data
    return bytes(buffer)


def read_sealed_stream(fd, key, context, *, max_frame_size=None):
    """
    Read the sealed stream from the binary file *fd*, yield the payloads of its frames in order.

    Every frame is verified before its payload is yielded. Raises SealedStreamError if the stream is
    not intact (see the module docstring) - this may happen after some payloads were yielded already,
    so the caller must not use what it got before the generator is exhausted.

    *max_frame_size* (default: FRAME_SIZE) is the largest frame payload accepted.
    """
    assert len(context) <= MAX_CONTEXT_SIZE
    context = bytes(context)
    max_envelope_size = (FRAME_SIZE if max_frame_size is None else max_frame_size) + key.PAYLOAD_OVERHEAD
    frame_no = 0
    while True:
        header = _read_exactly(fd, _HEADER.size)
        if len(header) != _HEADER.size:
            raise SealedStreamError(f"frame {frame_no}: stream ends before the last frame")
        flag, length = _HEADER.unpack(header)
        if flag not in (FLAG_MORE, FLAG_LAST):
            raise SealedStreamError(f"frame {frame_no}: invalid flag {flag}")
        if length > max_envelope_size:
            raise SealedStreamError(f"frame {frame_no}: envelope too large ({length} bytes)")
        envelope = _read_exactly(fd, length)
        if len(envelope) != length:
            raise SealedStreamError(f"frame {frame_no}: stream ends inside the frame")
        last = flag == FLAG_LAST
        try:
            payload = key.decrypt(b"", envelope, aad=_frame_aad(context, frame_no, last))
        except IntegrityError as err:
            raise SealedStreamError(f"frame {frame_no}: authentication failed") from err
        yield payload
        if last:
            break
        frame_no += 1
    if fd.read(1):
        raise SealedStreamError("data after the last frame")
