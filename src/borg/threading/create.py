import os
import stat
import struct
import sys

import zmq

from . import ThreadedService
from ..archive import Archive, Statistics, is_special
from ..helpers import safe_encode
from ..item import Item


class FilesCacheService(ThreadedService):
    """
    This is the first stage in the file processing pipeline.
    First, a file is checked against inodes seen so far to directly deduplicate
    hardlinks against each other ("h" status).
    Second, the file is checked against the files cache (the namesake of this),
    which also involves the chunks cache.
    If the files cache is hit, metadata is collected and the now finished item
    is transferred to the ItemBufferService.
    If the files cache is missed, processing continues to the ChunkerService.
    """

    # PULL: (item_optr, path)
    INPUT = 'inproc://files-cache'
    # PULL: (stat_data, safe_path)
    HARDLINK = 'inproc://files-cache/hardlink'

    @classmethod
    def get_process_file(cls):
        socket = zmq.Context.instance().socket(zmq.PUSH)
        socket.connect(FilesCacheService.INPUT)

        def process_file(item, path):
            socket.send_multipart([item.to_optr(), path.encode()])

        return process_file

    def __init__(self, id_hash, metadata,
                 chunker_url=None, zmq_context=None):
        super().__init__(zmq_context)
        self.id_hash = id_hash
        self.metadata = metadata
        self.chunker_url = chunker_url or ChunkerService.INPUT
        self.cwd = safe_encode(os.getcwd())
        self.hard_links = {}

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.hardlink = self.context.socket(zmq.PULL)
        self.output = self.context.socket(zmq.PUSH)

        self.add_item = ItemBufferService.get_add_item()
        self.file_known_and_unchanged = ChunksCacheService.get_file_known_and_unchanged()

        self.poller.register(self.input)
        self.output.connect(self.chunker_url)
        self.input.bind(self.INPUT)
        self.hardlink.bind(self.HARDLINK)

    def events(self, poll_events):
        if self.input in poll_events:
            self.process_file()
        if self.hardlink in poll_events:
            self.add_hardlink_master()

    def process_file(self):
        item_optr, path = self.input.recv_multipart()
        item = Item.from_optr(item_optr)

        st = os.stat(path)

        # Is it a hard link?
        if st.st_nlink > 1:
            source = self.hard_links.get((st.st_ino, st.st_dev))
            if source is not None:
                item.source = source
                item.update(self.metadata.stat_attrs(st, path))
                item.status = 'h'  # regular file, hardlink (to already seen inodes)
                self.add_item(item)
                return

        # in --read-special mode, we may be called upon for special files.
        # there should be no information in the cache about special files processed in
        # read-special mode, but we better play safe as this was wrong in the past:
        is_special_file = is_special(st.st_mode)
        if not is_special_file:
            path_hash = self.id_hash(os.path.join(self.cwd, path))
            id_list = self.file_known_and_unchanged(path_hash, st)
            if id_list is not None:
                item.chunks = id_list
                item.status = 'U'

        # item is a hard link and has the chunks
        item.hardlink_master = st.st_nlink > 1
        item.update(self.metadata.stat_simple_attrs(st))

        if is_special_file:
            # we processed a special file like a regular file. reflect that in mode,
            # so it can be extracted / accessed in FUSE mount like a regular file:
            item.mode = stat.S_IFREG | stat.S_IMODE(item.mode)

        if 'chunks' not in item:
            # Only chunkify the file if needed
            item.status = 'A'
            item.chunks = []
            self.output.send_multipart([b'FILE' + item.to_optr(), path])
        else:
            self.add_item(item)

    def add_hardlink_master(self):
        # Called by ItemHandler when a file is done and has the hardlink_master flag set
        stat_data, safe_path = self.input.recv_multipart()
        st_ino, st_dev = struct.unpack('=qq', stat_data)
        # Add the hard link reference *after* the file has been added to the archive.
        self.hard_links[st_ino, st_dev] = safe_path.decode()

    @classmethod
    def get_add_hardlink_master(cls):
        socket = zmq.Context.instance().socket(zmq.PUSH)
        socket.connect(cls.HARDLINK)

        def add_hardlink_master(item):
            stat_data = struct.pack('=qq', item.st_ino, item.st_dev)
            socket.send_multipart([stat_data, item.path.encode()])

        return add_hardlink_master


class ChunkerService(ThreadedService):
    # PULL: (ctx, path)
    INPUT = 'inproc://chunker'
    RELEASE_CHUNK = 'inproc://chunker/release-chunk'

    LARGE_CHUNK_TRESHOLD = 256 * 1024
    MEM_BUDGET = 64 * 1024 * 1024

    pure = False

    def __init__(self, chunker, zmq_context=None):
        super().__init__(zmq_context)
        self.chunker = chunker
        self.mem_budget = self.MEM_BUDGET

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.release_chunk = self.context.socket(zmq.PULL)

        self.output = self.context.socket(zmq.PUSH)
        self.finished_output = self.context.socket(zmq.PUSH)

        self.poller.register(self.input)
        self.poller.register(self.release_chunk)
        self.output.connect(IdHashService.INPUT)
        self.finished_output.connect(ItemHandler.FINISHED_INPUT)
        self.input.bind(self.INPUT)
        self.release_chunk.bind(self.RELEASE_CHUNK)

    def events(self, poll_events):
        if self.release_chunk in poll_events:
            self.mem_budget += int.from_bytes(self.release_chunk.recv(), sys.byteorder)
        if self.input in poll_events:
            self.chunk_file()

    def chunk_file(self):
        ctx, path = self.input.recv_multipart()
        n = 0
        fh = Archive._open_rb(path)
        with os.fdopen(fh, 'rb') as fd:
            for chunk in self.chunker.chunkify(fd, fh):
                # Important bit right here: The chunker gives us a memoryview of it's *internal* buffer,
                # so as soon as we return control back to it (via next() via iteration), it will start
                # copying new stuff into it's internal buffer. Therefore we need to make a copy here.

                if len(chunk) >= self.LARGE_CHUNK_TRESHOLD:
                    self.mem_budget -= len(chunk)
                    while self.mem_budget <= 0:
                        self.mem_budget += int.from_bytes(self.release_chunk.recv(), sys.byteorder)

                self.output.send_multipart([ctx, n.to_bytes(8, sys.byteorder), chunk], copy=True)
                n += 1
        self.finished_output.send_multipart([ctx, n.to_bytes(8, sys.byteorder)])


class IdHashService(ThreadedService):
    # PULL: (ctx, n, chunk)
    INPUT = 'inproc://id-hash'

    pure = False

    def __init__(self, id_hash, zmq_context=None):
        super().__init__(zmq_context)
        self.id_hash = id_hash

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.output = self.context.socket(zmq.PUSH)

        self.poller.register(self.input)
        self.output.connect(ChunksCacheService.INPUT)
        self.input.bind(self.INPUT)

    def events(self, poll_events):
        if self.input in poll_events:
            ctx, n, chunk = self.input.recv_multipart(copy=False)
            id = self.id_hash(chunk.buffer)
            self.output.send_multipart([ctx, n, chunk, id], copy=False)


class ChunksCacheService(ThreadedService):
    # PULL: (ctx, n, chunk, id)
    INPUT = 'inproc://cache'

    # PULL: (ctx, n, id, csize, size)
    CHUNK_SAVED = 'inproc://cache/chunk-saved'

    # REP: path_hash, packed_st -> (ChunkListEntry, ...) or (,) if file not known
    FILE_KNOWN = 'inproc://cache/file-known'

    MEMORIZE = 'inproc://cache/memorize-file'

    CONTROL_COMMIT = b'COMMIT'

    @classmethod
    def get_file_known_and_unchanged(cls):
        socket = zmq.Context.instance().socket(zmq.REQ)
        socket.connect(cls.FILE_KNOWN)

        def file_known_and_unchanged(path_hash, st):
            """
            *path_hash* is the id_hash of the file to be queried; st is a standard os.stat_result.
            Returns None, for a changed or unknown files, or a chunk ID list.
            """
            packed_st = struct.pack('=qqq', st.st_ino, st.st_size, st.st_mtime_ns)
            socket.send_multipart([path_hash, packed_st])
            response = socket.recv_multipart()
            if not response:
                return
            chunks_list = []
            for entry in response:
                # could/should use ChunkListEntry here?
                if entry == b'0':
                    return None
                if entry:
                    chunks_list.append(struct.unpack('=32sLL', entry))
            return chunks_list

        return file_known_and_unchanged

    class StatResult:
        st_mode = stat.S_IFREG
        st_ino = st_size = st_mtime_ns = 0

    def __init__(self, backend_cache, zmq_context=None):
        super().__init__(zmq_context)
        self.cache = backend_cache
        self.stats = Statistics()
        self.st = self.StatResult()

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.chunk_saved = self.context.socket(zmq.PULL)
        self.memorize = self.context.socket(zmq.PULL)
        self.file_known = self.context.socket(zmq.REP)

        self.output_new = self.context.socket(zmq.PUSH)
        self.file_chunk_output = self.context.socket(zmq.PUSH)
        self.meta_chunk_output = self.context.socket(zmq.PUSH)
        self.output_release_chunk = self.context.socket(zmq.PUSH)

        self.poller.register(self.input)
        self.poller.register(self.chunk_saved)
        self.poller.register(self.memorize)
        self.poller.register(self.file_known)
        self.input.bind(self.INPUT)
        self.chunk_saved.bind(self.CHUNK_SAVED)
        self.memorize.bind(self.MEMORIZE)
        self.file_known.bind(self.FILE_KNOWN)
        self.output_new.connect(CompressionService.INPUT)
        self.file_chunk_output.connect(ItemHandler.CHUNK_INPUT)
        self.meta_chunk_output.connect(ItemBufferService.CHUNK_INPUT)
        self.output_release_chunk.connect(ChunkerService.RELEASE_CHUNK)

    def events(self, poll_events):
        if self.input in poll_events:
            self.route_chunk()
        if self.chunk_saved in poll_events:
            self.add_new_saved_chunk()
        if self.memorize in poll_events:
            self.memorize_file()
        if self.file_known in poll_events:
            self.respond_file_known()
        self.stats.show_progress(dt=0.2)

    def handle_control(self, opcode, args):
        if opcode == self.CONTROL_COMMIT:
            self.cache.commit()
            self.control_sock.send(b'ok')
            return
        super().handle_control(opcode, args)

    def output_chunk_list_entry(self, ctx, n, chunk_list_entry):
        if ctx.startswith(b'FILE'):
            self.file_chunk_output.send_multipart([ctx[4:], n, chunk_list_entry])
        elif ctx.startswith(b'META'):
            self.meta_chunk_output.send_multipart([ctx, n, chunk_list_entry])
        else:
            raise ValueError('Unknown context prefix: ' + repr(ctx[4:]))

    def route_chunk(self):
        ctx, n, chunk, id = self.input.recv_multipart(copy=False)
        id = id.bytes
        if self.cache.seen_chunk(id):
            chunk_list_entry = struct.pack('=32sLL', *self.cache.chunk_incref(id, self.stats))
            self.output_chunk_list_entry(ctx, n, chunk_list_entry)
            if len(chunk) >= ChunkerService.LARGE_CHUNK_TRESHOLD:
                self.output_release_chunk.send(len(chunk).to_bytes(4, sys.byteorder))
        else:
            self.output_new.send_multipart([ctx, n, chunk, id], copy=False)

    def add_new_saved_chunk(self):
        ctx, n, id, sizes = self.chunk_saved.recv_multipart()
        csize, size = struct.unpack('=LL', sizes)
        if size >= ChunkerService.LARGE_CHUNK_TRESHOLD:
            self.output_release_chunk.send(size.to_bytes(4, sys.byteorder))
        self.cache.chunks.chunks.add(id, 1, size, csize)
        # Depending on how long chunk processing takes we may issue the same chunk multiple times, so it will
        # be stored a few times and reported here a few times. This is unproblematic, since these are compacted
        # away by the Repository.
        # However, this also ensures that the system is always in a forward-consistent state,
        # i.e. items are not added until all their chunks were fully processes.
        # Forward-consistency makes everything much simpler.
        refcount = self.cache.seen_chunk(id)
        self.stats.update(size, csize, refcount == 1)
        chunk_list_entry = struct.pack('=32sLL', id, size, csize)
        self.output_chunk_list_entry(ctx, n, chunk_list_entry)

    def respond_file_known(self):
        path_hash, st = self.file_known.recv_multipart()
        self.st.st_ino, self.st.st_size, self.st.st_mtime_ns = struct.unpack('=qqq', st)

        ids = self.cache.file_known_and_unchanged(path_hash, self.st)

        if ids is None:
            self.file_known.send(b'0')
            return

        if not all(self.cache.seen_chunk(id) for id in ids):
            self.file_known.send(b'0')
            return

        chunk_list = [struct.pack('=32sLL', *self.cache.chunk_incref(id, self.stats)) for id in ids]
        if chunk_list:
            self.file_known.send_multipart(chunk_list)
        else:
            self.file_known.send(b'')

    def memorize_file(self):
        path_hash, st, *ids = self.memorize.recv_multipart()
        self.st.st_ino, self.st.st_size, self.st.st_mtime_ns = struct.unpack('=qqq', st)
        self.cache.memorize_file(path_hash, self.st, ids)


class CompressionService(ThreadedService):
    INPUT = 'inproc://compression'

    pure = False

    def __init__(self, compr_spec, zmq_context=None):
        super().__init__(zmq_context)
        self.compressor = compr_spec.compressor

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.output = self.context.socket(zmq.PUSH)

        self.poller.register(self.input)
        self.input.bind(self.INPUT)
        self.output.connect(EncryptionService.INPUT)

    def events(self, poll_events):
        if self.input in poll_events:
            ctx, n, chunk, id = self.input.recv_multipart(copy=False)
            size = len(chunk.buffer).to_bytes(4, sys.byteorder)
            compressed = self.compressor.compress(chunk.buffer)
            self.output.send_multipart([ctx, n, compressed, id, size], copy=False)


class EncryptionService(ThreadedService):
    INPUT = 'inproc://encryption'

    pure = False

    def __init__(self, key, zmq_context=None):
        super().__init__(zmq_context)
        self.key = key

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.output = self.context.socket(zmq.PUSH)

        self.poller.register(self.input)
        self.input.bind(self.INPUT)
        self.output.connect(RepositoryService.INPUT)

    def events(self, poll_events):
        if self.input in poll_events:
            ctx, n, chunk, id, size = self.input.recv_multipart(copy=False)
            encrypted = self.key.encrypt(chunk, compress=False)
            self.output.send_multipart([ctx, n, encrypted, id, size, len(encrypted)], copy=False)


class RepositoryService(ThreadedService):
    INPUT = 'inproc://repository/put'
    API = 'inproc://repository'

    CONTROL_COMMIT = b'COMMIT'

    def __init__(self, repository, chunk_saved_url=ChunksCacheService.CHUNK_SAVED, zmq_context=None):
        super().__init__(zmq_context)
        self.repository = repository
        self.chunk_saved_url = chunk_saved_url

    def init(self):
        super().init()
        self.input = self.context.socket(zmq.PULL)
        self.api = self.context.socket(zmq.REP)
        self.output = self.context.socket(zmq.PUSH)

        self.poller.register(self.input)
        self.poller.register(self.api)
        self.input.bind(self.INPUT)
        self.api.bind(self.API)
        self.output.connect(self.chunk_saved_url)

    def events(self, poll_events):
        if self.input in poll_events:
            self.put()
        if self.api in poll_events:
            self.api_reply()

    def handle_control(self, opcode, args):
        if opcode == self.CONTROL_COMMIT:
            self.repository.commit()
            self.control_sock.send(b'OK')
        else:
            super().handle_control(opcode, args)

    def put(self):
        ctx, n, data, id, *extra = self.input.recv_multipart()
        self.repository.put(id, data, wait=False)
        self.repository.async_response(wait=False)
        self.output.send_multipart([ctx, n, id] + extra)

    def api_reply(self):
        pass
