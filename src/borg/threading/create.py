import enum
import os
import signal
import socket
import stat
import struct
import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timedelta
from getpass import getuser

import zmq

from . import ThreadedService
from ..archive import Archive, Statistics, is_special
from ..archive import ChunkBuffer
from ..archive import MetadataCollector
from ..archive import backup_io
from ..chunker import Chunker
from ..helpers import Manifest
from ..helpers import make_path_safe
from ..helpers import safe_encode
from ..helpers import  uid2user, gid2group
from ..item import ArchiveItem, Item
from ..logger import create_logger

logger = create_logger(__name__)


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
    # REP: (stat_data) -> (safe_path)
    GET_HARDLINK_MASTER = 'inproc://files-cache/get-hardlink-master'

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
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.hardlink = self.socket(zmq.PULL, self.HARDLINK)
        self.get_hardlink_master = self.socket(zmq.REP, self.GET_HARDLINK_MASTER)
        self.output = self.socket(zmq.PUSH, self.chunker_url)

        self.add_item = ItemBufferService.get_add_item()
        self.file_known_and_unchanged = ChunksCacheService.get_file_known_and_unchanged()

    def events(self, poll_events):
        if self.input in poll_events:
            self.process_file()
        if self.hardlink in poll_events:
            self.add_hardlink_master()
        if self.get_hardlink_master in poll_events:
            self.reply_hardlink_master()

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
        stat_data, safe_path = self.hardlink.recv_multipart()
        st_ino, st_dev = struct.unpack('=qq', stat_data)
        # Add the hard link reference *after* the file has been added to the archive.
        self.hard_links[st_ino, st_dev] = safe_path.decode()

    @classmethod
    def get_add_hardlink_master(cls):
        socket = zmq.Context.instance().socket(zmq.PUSH)
        socket.connect(cls.HARDLINK)

        def add_hardlink_master(st, path):
            stat_data = struct.pack('=qq', st.st_ino, st.st_dev)
            socket.send_multipart([stat_data, path.encode()])

        return add_hardlink_master

    def reply_hardlink_master(self):
        stat_data = self.get_hardlink_master.recv()
        st_ino, st_dev = struct.unpack('=qq', stat_data)
        # path can't be empty, thus empty path = no hardlink master found.
        self.get_hardlink_master.send(self.hard_links.get((st_ino, st_dev), '').encode())

    @classmethod
    def get_get_hardlink_master(cls):
        socket = zmq.Context.instance().socket(zmq.REQ)
        socket.connect(cls.GET_HARDLINK_MASTER)

        def get_hardlink_master(st):
            stat_data = struct.pack('=qq', st.st_ino, st.st_dev)
            return socket.send(stat_data).decode() or None

        return get_hardlink_master


class ChunkerService(ThreadedService):
    # PULL: (ctx, path)
    INPUT = 'inproc://chunker'
    RELEASE_CHUNK = 'inproc://chunker/release-chunk'

    LARGE_CHUNK_TRESHOLD = 256 * 1024
    MEM_BUDGET = 64 * 1024 * 1024

    pure = False

    def __init__(self, chunker_seed, chunker_params, zmq_context=None):
        super().__init__(zmq_context)
        self.chunker = Chunker(chunker_seed, *chunker_params)
        self.mem_budget = self.MEM_BUDGET

    def init(self):
        super().init()
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.release_chunk = self.socket(zmq.PULL, self.RELEASE_CHUNK)
        self.output = self.socket(zmq.PUSH, IdHashService.INPUT)
        self.finished_output = self.socket(zmq.PUSH, ItemHandler.FINISHED_INPUT)

    def events(self, poll_events):
        if self.release_chunk in poll_events:
            self.mem_budget += int.from_bytes(self.release_chunk.recv(), sys.byteorder)
        if self.input in poll_events:
            self.chunk_file()

    def chunk_file(self):
        # XXX Error handling
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
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.output = self.socket(zmq.PUSH, ChunksCacheService.INPUT)

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

    # REP: path_hash, packed_st -> (ChunkListEntry, ...) or '0' if file not known
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

    def __init__(self, backend_cache, stats=None, zmq_context=None):
        super().__init__(zmq_context)
        self.cache = backend_cache
        self.cache.begin_txn()
        self.stats = stats or Statistics()
        self.st = self.StatResult()

    def init(self):
        super().init()
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.chunk_saved = self.socket(zmq.PULL, self.CHUNK_SAVED)
        self.memorize = self.socket(zmq.PULL, self.MEMORIZE)
        self.file_known = self.socket(zmq.REP, self.FILE_KNOWN)

        self.output_new = self.socket(zmq.PUSH, CompressionService.INPUT)
        self.file_chunk_output = self.socket(zmq.PUSH, ItemHandler.CHUNK_INPUT)
        self.meta_chunk_output = self.socket(zmq.PUSH, ItemBufferService.CHUNK_INPUT)
        self.output_release_chunk = self.socket(zmq.PUSH, ChunkerService.RELEASE_CHUNK)

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
            logger.debug('Cache committed.')
            self.control_sock.send(b'ok')
            return
        super().handle_control(opcode, args)

    def output_chunk_list_entry(self, ctx, n, chunk_list_entry):
        if ctx.startswith(b'FILE'):
            self.file_chunk_output.send_multipart([ctx, n, chunk_list_entry])
        elif ctx.startswith(b'META'):
            self.meta_chunk_output.send_multipart([ctx, n, chunk_list_entry])
        else:
            raise ValueError('Unknown context prefix: ' + repr(ctx[4:]))

    def route_chunk(self):
        ctx, n, chunk, id = self.input.recv_multipart(copy=False)
        id = id.bytes
        if self.cache.seen_chunk(id):
            chunk_list_entry = struct.pack('=32sLL', *self.cache.chunk_incref(id, self.stats))
            self.output_chunk_list_entry(bytes(ctx), bytes(n), chunk_list_entry)
            if len(chunk) >= ChunkerService.LARGE_CHUNK_TRESHOLD:
                self.output_release_chunk.send(len(chunk).to_bytes(4, sys.byteorder))
        else:
            self.output_new.send_multipart([ctx, n, chunk, id], copy=False)

    def add_new_saved_chunk(self):
        ctx, n, id, size, csize = self.chunk_saved.recv_multipart()
        size = int.from_bytes(size, sys.byteorder)
        csize = int.from_bytes(csize, sys.byteorder)
        if size >= ChunkerService.LARGE_CHUNK_TRESHOLD:
            self.output_release_chunk.send(size.to_bytes(4, sys.byteorder))
        if ctx == ItemBufferService.MANIFEST_CTX:
            # Avoid adding the manifest to the cache
            assert id == Manifest.MANIFEST_ID
        else:
            self.cache.chunks.add(id, 1, size, csize)
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
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.output = self.socket(zmq.PUSH, EncryptionService.INPUT)

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
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.output = self.socket(zmq.PUSH, RepositoryService.INPUT)

    def events(self, poll_events):
        if self.input in poll_events:
            ctx, n, chunk, id, size = self.input.recv_multipart(copy=False)
            encrypted = self.key.encrypt(chunk, compress=False)
            self.output.send_multipart([ctx, n, encrypted, id, size, len(encrypted).to_bytes(4, sys.byteorder)], copy=False)


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
        self.input = self.socket(zmq.PULL, self.INPUT)
        self.api = self.socket(zmq.REP, self.API)
        self.output = self.socket(zmq.PUSH, self.chunk_saved_url)

    def events(self, poll_events):
        if self.input in poll_events:
            self.put()
        if self.api in poll_events:
            self.api_reply()

    def handle_control(self, opcode, args):
        if opcode == self.CONTROL_COMMIT:
            self.repository.commit()
            logger.debug('Repository committed.')
            self.control_sock.send(b'OK')
        else:
            super().handle_control(opcode, args)

    def put(self):
        ctx, n, data, id, *extra = self.input.recv_multipart()
        self.repository.put(id, data, wait=False)
        self.repository.async_response(wait=False)
        self.output.send_multipart([ctx, n, id] + extra)

    def api_reply(self):
        # TODO XXX implement API & replace Repository object in other places to avoid accessing it from multiple threads
        #      XXX Python has no concept of ownership so this is a bit annoying to see through.
        pass


class ItemHandler(ThreadedService):
    CHUNK_INPUT = 'inproc://item-handler/chunks'
    FINISHED_INPUT = 'inproc://item-handler/finished'

    def __init__(self, metadata_collector: MetadataCollector, zmq_context=None):
        super().__init__(zmq_context)
        self.metadata = metadata_collector
        self.items_in_progress = {}
        self.add_item = ItemBufferService.get_add_item()
        self.add_hardlink_master = FilesCacheService.get_add_hardlink_master()

    def init(self):
        super().init()
        self.chunk_input = self.socket(zmq.PULL, self.CHUNK_INPUT)
        self.finished_chunking_file = self.socket(zmq.PULL, self.FINISHED_INPUT)

    def events(self, poll_events):
        if self.chunk_input in poll_events:
            self.process_chunk()
        if self.finished_chunking_file in poll_events:
            self.set_item_finished()

    def process_chunk(self):
        ctx, chunk_index, chunk_list_entry = self.chunk_input.recv_multipart()
        assert ctx.startswith(b'FILE')
        item_optr = ctx[4:]
        if item_optr not in self.items_in_progress:
            self.items_in_progress[item_optr] = Item.from_optr(item_optr)
        item = self.items_in_progress[item_optr]
        chunk_index = int.from_bytes(chunk_index, sys.byteorder)
        if chunk_index >= len(item.chunks):
            item.chunks.extend([None] * (chunk_index - len(item.chunks) + 1))
        item.chunks[chunk_index] = struct.unpack('=32sLL', chunk_list_entry)
        self.check_item_done(item_optr, item)

    def set_item_finished(self):
        ctx, num_chunks = self.finished_chunking_file.recv_multipart()
        assert ctx.startswith(b'FILE')
        item_optr = ctx[4:]
        if item_optr not in self.items_in_progress:
            self.items_in_progress[item_optr] = Item.from_optr(item_optr)
        item = self.items_in_progress[item_optr]
        num_chunks = int.from_bytes(num_chunks, sys.byteorder)
        item.num_chunks = num_chunks
        self.check_item_done(item_optr, item)

    def check_item_done(self, item_optr, item):
        if getattr(item, 'num_chunks', None) == len(item.chunks) and all(item.chunks):
            del self.items_in_progress[item_optr]

            # XXX Error handling
            st = os.stat(item.original_path)
            item.update(self.metadata.stat_attrs(st, item.original_path))
            if item.get('hardlink_master'):
                self.add_hardlink_master(st, item.path)

            self.add_item(item)


class ItemBufferService(ChunkBuffer, ThreadedService):
    CHUNK_INPUT = 'inproc://chunk-buffer/chunks'
    ITEM_INPUT = 'inproc://chunk-buffer/add-item'

    CONTROL_SAVE = b'SAVE'

    class States(enum.Enum):
        WAITING_FOR_SAVE = 0
        WAITING_FOR_ITEMS = 1
        WAITING_FOR_ARCHIVE_CHUNKS = 2
        WAITING_FOR_ARCHIVE_ITEM = 3
        WAITING_FOR_MANIFEST = 4

    ARCHIVE_ITEM_CTX = b'META_ARCHIVE_ITEM'
    MANIFEST_CTX = b'META_MANIFEST'

    @classmethod
    def get_add_item(cls):
        socket = zmq.Context.instance().socket(zmq.PUSH)
        socket.connect(cls.ITEM_INPUT)

        def add_item(item):
            socket.send(item.to_optr())

        return add_item

    def __init__(self, key, archive, archive_data, cache_control, repository_control, print_file_status,
                 push_chunk_url=IdHashService.INPUT, compress_url=CompressionService.INPUT):
        super().__init__(key)
        self.archive = archive
        self.archive_data = archive_data
        self.push_chunk_url = push_chunk_url
        self.compress_url = compress_url
        self.cache_control = cache_control
        self.repository_control = repository_control
        self.print_file_status = print_file_status

        self.num_items = 0
        self.save_after_item_no = None
        self.die_after_save = False

        self.state = self.States.WAITING_FOR_SAVE

    def init(self):
        super().init()
        self.add_item = self.socket(zmq.PULL, self.ITEM_INPUT)
        self.chunk_added = self.socket(zmq.PULL, self.CHUNK_INPUT)

        self.push_chunk = self.socket(zmq.PUSH, self.push_chunk_url)
        self.compress_chunk = self.socket(zmq.PUSH, self.compress_url)

    def events(self, poll_events):
        if self.add_item in poll_events:
            self.pack_and_add_item()
        if self.chunk_added in poll_events:
            ctx, n, chunk_list_entry = self.chunk_added.recv_multipart()
            chunk_id, *_ = struct.unpack('=32sLL', chunk_list_entry)
            if self.state == self.States.WAITING_FOR_ARCHIVE_ITEM and ctx == self.ARCHIVE_ITEM_CTX:
                logger.debug('Archive saved, updating manifest.')
                self.update_manifest(chunk_id)
            elif self.state == self.States.WAITING_FOR_MANIFEST and ctx == self.MANIFEST_CTX:
                logger.debug('Manifest saved, initiating repository and cache commits.')
                self.commit()
            else:
                assert ctx == b'META'
                n = int.from_bytes(n, sys.byteorder)
                assert self.chunks[n] is None
                self.chunks[n] = chunk_id
        if self.state == self.States.WAITING_FOR_ITEMS and self.num_items == self.save_after_item_no:
            # Got all items, flush (no-op if nothing buffered)
            logger.debug('Last item for archive save added, flushing chunk buffer.')
            self.flush(flush=True)
            self.state = self.States.WAITING_FOR_ARCHIVE_CHUNKS
        if self.state == self.States.WAITING_FOR_ARCHIVE_CHUNKS and self.is_complete():
            # If we're complete we can go ahead and make the archive item,
            # update the manifest and commit.
            logger.debug('Archive chunks flushed, saving archive.')
            self.save_archive()

    def handle_control(self, opcode, args):
        if opcode == self.CONTROL_SAVE:
            assert len(args) == 1
            assert self.state == self.States.WAITING_FOR_SAVE
            self.state = self.States.WAITING_FOR_ITEMS
            self.save_after_item_no = int.from_bytes(args[0], sys.byteorder)
            logger.debug('Received save command at item %d.', self.save_after_item_no)
            # Reply is sent _after_ it's done (blocking the main thread until then).
        else:
            super().handle_control(opcode, args)

    def save(self, pipeline):
        num_items = pipeline.fso.num_items
        self.control(self.CONTROL_SAVE, num_items.to_bytes(8, sys.byteorder))

    def pack_and_add_item(self):
        item = Item.from_optr(self.add_item.recv())
        self.num_items += 1
        if 'chunks' in item:
            self.archive.stats.nfiles += 1
        if 'status' in item:
            self.print_file_status(item.status, item.original_path)
        try:
            # XXX This is the sledgehammer approach of getting rid of these, see comment in Item
            del item.original_path
            del item.status
            del item.num_chunks
        except AttributeError:
            pass
        self.add(item)

    def write_chunk(self, chunk):
        ctx = b'META'
        n = len(self.chunks).to_bytes(8, sys.byteorder)
        self.push_chunk.send_multipart([ctx, n, chunk])
        return None  # we'll fill the ID later in

    def is_complete(self):
        return all(self.chunks)

    def save_archive(self):
        data = self.archive.pack_archive_item(**self.archive_data)
        self.push_chunk.send_multipart([self.ARCHIVE_ITEM_CTX, b'', data])
        self.state = self.States.WAITING_FOR_ARCHIVE_ITEM

    def update_manifest(self, archive_item_id):
        self.archive.id = archive_item_id
        self.archive.manifest.archives[self.archive.name] = (archive_item_id, self.archive.start.isoformat())
        manifest_data = self.archive.manifest.pack()
        self.compress_chunk.send_multipart([self.MANIFEST_CTX, b'', manifest_data, Manifest.MANIFEST_ID])
        self.state = self.States.WAITING_FOR_MANIFEST

    def commit(self):
        self.repository_control(RepositoryService.CONTROL_COMMIT)
        self.cache_control(ChunksCacheService.CONTROL_COMMIT)
        self.state = self.States.WAITING_FOR_SAVE
        # Notify main thread that we're done here.
        logger.debug('Data committed, unblocking main thread.')
        self.control_sock.send(b'OK')

# TODO checkpoints (via main thread, extension of CONTROL_SAVE w/ explicit archive name)
# TODO in-file checkpoints (IBS tells IH to emit part-file items for all in-flight items)
# TODO borg create --list


class FilesystemObjectProcessors:
    def __init__(self, *, metadata_collector,
                 add_item, process_file, get_hardlink_master, add_hardlink_master):
        self.metadata_collector = metadata_collector
        self.add_item = add_item
        # TODO: In theory, the hardlink masters of files and other stuff can't intersect,
        #       so it would be possible, with some additional checking of FS object types
        #       (to avoid races - they are present currently as well, so maybe even without),
        #       to have separate hard_links dicts for them.
        self.get_hardlink_master = get_hardlink_master
        self.add_hardlink_master = add_hardlink_master
        self._process_file = process_file

        self.hard_links = {}
        self.cwd = os.getcwd()

        self.num_items = 0

    @contextmanager
    def create_helper(self, path, st, status=None, hardlinkable=True):
        safe_path = make_path_safe(path)
        item = Item(path=safe_path)
        hardlink_master = False
        hardlinked = hardlinkable and st.st_nlink > 1
        if hardlinked:
            source = self.get_hardlink_master(st)
            if source is not None:
                item.source = source
                status = 'h'  # hardlink (to already seen inodes)
            else:
                hardlink_master = True
        yield item, status, hardlinked, hardlink_master
        # if we get here, "with"-block worked ok without error/exception, the item was processed ok...
        self.add_item(item)
        self.num_items += 1
        # ... and added to the archive, so we can remember it to refer to it later in the archive:
        if hardlink_master:
            self.add_hardlink_master(st, safe_path)

    def process_dir(self, path, st):
        with self.create_helper(path, st, 'd', hardlinkable=False) as (item, status, hardlinked, hardlink_master):
            item.update(self.metadata_collector.stat_attrs(st, path))
            return status

    def process_fifo(self, path, st):
        with self.create_helper(path, st, 'f') as (item, status, hardlinked, hardlink_master):  # fifo
            item.update(self.metadata_collector.stat_attrs(st, path))
            return status

    def process_dev(self, path, st, dev_type):
        with self.create_helper(path, st, dev_type) as (item, status, hardlinked, hardlink_master):  # char/block device
            item.rdev = st.st_rdev
            item.update(self.metadata_collector.stat_attrs(st, path))
            return status

    def process_symlink(self, path, st):
        # note: using hardlinkable=False because we can not support hardlinked symlinks,
        #       due to the dual-use of item.source, see issue #2343:
        with self.create_helper(path, st, 's', hardlinkable=False) as (item, status, hardlinked, hardlink_master):
            with backup_io('readlink'):
                source = os.readlink(path)
            item.source = source
            if st.st_nlink > 1:
                logger.warning('hardlinked symlinks will be archived as non-hardlinked symlinks!')
            item.update(self.metadata_collector.stat_attrs(st, path))
            return status

    def process_stdin(self, path, cache):
        # TODO implement
        uid, gid = 0, 0
        t = int(time.time()) * 1000000000
        item = Item(
            path=path,
            mode=0o100660,  # regular file, ug=rw
            uid=uid, user=uid2user(uid),
            gid=gid, group=gid2group(gid),
            mtime=t, atime=t, ctime=t,
        )
        fd = sys.stdin.buffer  # binary
        raise NotImplementedError
        self.process_file_chunks(item, cache, self.stats, backup_io_iter(self.chunker.chunkify(fd)))
        item.get_size(memorize=True)
        self.stats.nfiles += 1
        self.add_item(item)
        return 'i'  # stdin

    def process_file(self, path, st, cache, ignore_inode=False):
        # XXX ignore_inode is initialization-time, move to FilesCacheService
        item = Item(path=make_path_safe(path))
        item.original_path = path
        self._process_file(item, path)
        self.num_items += 1
        return 'async'


class CreateArchivePipeline:
    def __init__(self, *, repository, key, cache, archive, compr_spec, archive_data,
                 metadata_collector, print_file_status):
        # Explicitly create Context with no IO threads, so any attempt at networking will fail.
        zmq.Context.instance(io_threads=0)
        self.metadata_collector = metadata_collector

        self.files_cache = FilesCacheService(key.id_hash, self.metadata_collector)
        self.chunker = ChunkerService(key.chunk_seed, archive.chunker_params)
        self.id_hash = IdHashService(key.id_hash)
        self.chunks_cache = ChunksCacheService(cache, archive.stats)
        self.compressor = CompressionService(compr_spec)
        self.encryption = EncryptionService(key)
        self.repository = RepositoryService(repository)
        self.item_handler = ItemHandler(self.metadata_collector)
        self.item_buffer = ItemBufferService(key, archive,
                                             archive_data=archive_data,
                                             cache_control=self.chunks_cache.control,
                                             repository_control=self.repository.control,
                                             print_file_status=print_file_status)

        self.fso = FilesystemObjectProcessors(
            metadata_collector=self.metadata_collector,
            add_item=self.item_buffer.get_add_item(),
            process_file=self.files_cache.get_process_file(),
            get_hardlink_master=self.files_cache.get_get_hardlink_master(),
            add_hardlink_master=self.files_cache.get_add_hardlink_master())

        self.services = [
            self.files_cache, self.chunker, self.id_hash,
            self.chunks_cache, self.compressor, self.encryption,
            self.repository, self.item_handler, self.item_buffer,
        ]

    def save(self):
        self.item_buffer.save(self)

    def __enter__(self):
        for service in self.services:
            service.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            logger.error('--- Critical error ---')
            traceback.print_exc()
            os.kill(os.getpid(), signal.SIGABRT)
        else:
            logger.debug('Joining threads...')
            for service in self.services:
                logger.debug('Terminating %s', service.__class__.__name__)
                service.control(ThreadedService.CONTROL_DIE)
                logger.debug('Joining %s', service.__class__.__name__)
                service.join()
            logger.debug('Joined all %d threads.', len(self.services))
            zmq.Context.instance().destroy()
