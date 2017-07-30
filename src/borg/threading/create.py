import os
import stat
import struct

import zmq

from . import ThreadedService
from ..archive import is_special
from ..helpers import safe_encode
from ..item import Item


class FilesCacheService(ThreadedService):
    INPUT = 'inproc://files-cache'
    HARDLINK = 'inproc://files-cache/hardlink'
    CONTROL = 'inproc://files-cache/control'

    __doc__ = \
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
