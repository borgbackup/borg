import argparse
import base64
from datetime import datetime
import logging
import os
import stat
import tarfile
import time

from ..archive import Archive, TarfileObjectProcessors, ChunksProcessor
from ..compress import CompressionSpec
from ..constants import *  # NOQA
from ..helpers import Manifest
from ..helpers import HardLinkManager
from ..helpers import ProgressIndicatorPercent
from ..helpers import get_tar_filter
from ..helpers import dash_open
from ..helpers import msgpack
from ..helpers import create_filter_process
from ..helpers import ChunkIteratorFileWrapper
from ..helpers import ChunkerParams
from ..helpers import NameSpec
from ..helpers import remove_surrogates
from ..helpers import timestamp
from ..helpers import basic_json_data, json_print
from ..helpers import log_multi

from .common import with_repository, with_archive, Highlander, define_exclusion_group
from .common import build_matcher, build_filter

from ..logger import create_logger

logger = create_logger(__name__)


class TarMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    @with_archive
    def do_export_tar(self, args, repository, manifest, key, archive):
        """Export archive contents as a tarball"""
        self.output_list = args.output_list

        # A quick note about the general design of tar_filter and tarfile;
        # The tarfile module of Python can provide some compression mechanisms
        # by itself, using the builtin gzip, bz2 and lzma modules (and "tarmodes"
        # such as "w:xz").
        #
        # Doing so would have three major drawbacks:
        # For one the compressor runs on the same thread as the program using the
        # tarfile, stealing valuable CPU time from Borg and thus reducing throughput.
        # Then this limits the available options - what about lz4? Brotli? zstd?
        # The third issue is that systems can ship more optimized versions than those
        # built into Python, e.g. pigz or pxz, which can use more than one thread for
        # compression.
        #
        # Therefore we externalize compression by using a filter program, which has
        # none of these drawbacks. The only issue of using an external filter is
        # that it has to be installed -- hardly a problem, considering that
        # the decompressor must be installed as well to make use of the exported tarball!

        filter = get_tar_filter(args.tarfile, decompress=False) if args.tar_filter == "auto" else args.tar_filter

        tarstream = dash_open(args.tarfile, "wb")
        tarstream_close = args.tarfile != "-"

        with create_filter_process(filter, stream=tarstream, stream_close=tarstream_close, inbound=False) as _stream:
            self._export_tar(args, archive, _stream)

        return self.exit_code

    def _export_tar(self, args, archive, tarstream):
        matcher = build_matcher(args.patterns, args.paths)

        progress = args.progress
        output_list = args.output_list
        strip_components = args.strip_components
        hlm = HardLinkManager(id_type=bytes, info_type=str)  # hlid -> path

        filter = build_filter(matcher, strip_components)

        # The | (pipe) symbol instructs tarfile to use a streaming mode of operation
        # where it never seeks on the passed fileobj.
        tar_format = dict(GNU=tarfile.GNU_FORMAT, PAX=tarfile.PAX_FORMAT, BORG=tarfile.PAX_FORMAT)[args.tar_format]
        tar = tarfile.open(fileobj=tarstream, mode="w|", format=tar_format)

        if progress:
            pi = ProgressIndicatorPercent(msg="%5.1f%% Processing: %s", step=0.1, msgid="extract")
            pi.output("Calculating size")
            extracted_size = sum(item.get_size() for item in archive.iter_items(filter))
            pi.total = extracted_size
        else:
            pi = None

        def item_content_stream(item):
            """
            Return a file-like object that reads from the chunks of *item*.
            """
            chunk_iterator = archive.pipeline.fetch_many([chunk_id for chunk_id, _ in item.chunks], is_preloaded=True)
            if pi:
                info = [remove_surrogates(item.path)]
                return ChunkIteratorFileWrapper(
                    chunk_iterator, lambda read_bytes: pi.show(increase=len(read_bytes), info=info)
                )
            else:
                return ChunkIteratorFileWrapper(chunk_iterator)

        def item_to_tarinfo(item, original_path):
            """
            Transform a Borg *item* into a tarfile.TarInfo object.

            Return a tuple (tarinfo, stream), where stream may be a file-like object that represents
            the file contents, if any, and is None otherwise. When *tarinfo* is None, the *item*
            cannot be represented as a TarInfo object and should be skipped.
            """
            stream = None
            tarinfo = tarfile.TarInfo()
            tarinfo.name = item.path
            tarinfo.mtime = item.mtime / 1e9
            tarinfo.mode = stat.S_IMODE(item.mode)
            tarinfo.uid = item.uid
            tarinfo.gid = item.gid
            tarinfo.uname = item.get("user", "")
            tarinfo.gname = item.get("group", "")
            # The linkname in tar has 2 uses:
            # for symlinks it means the destination, while for hardlinks it refers to the file.
            # Since hardlinks in tar have a different type code (LNKTYPE) the format might
            # support hardlinking arbitrary objects (including symlinks and directories), but
            # whether implementations actually support that is a whole different question...
            tarinfo.linkname = ""

            modebits = stat.S_IFMT(item.mode)
            if modebits == stat.S_IFREG:
                tarinfo.type = tarfile.REGTYPE
                if "hlid" in item:
                    linkname = hlm.retrieve(id=item.hlid)
                    if linkname is not None:
                        # the first hardlink was already added to the archive, add a tar-hardlink reference to it.
                        tarinfo.type = tarfile.LNKTYPE
                        tarinfo.linkname = linkname
                    else:
                        tarinfo.size = item.get_size()
                        stream = item_content_stream(item)
                        hlm.remember(id=item.hlid, info=item.path)
                else:
                    tarinfo.size = item.get_size()
                    stream = item_content_stream(item)
            elif modebits == stat.S_IFDIR:
                tarinfo.type = tarfile.DIRTYPE
            elif modebits == stat.S_IFLNK:
                tarinfo.type = tarfile.SYMTYPE
                tarinfo.linkname = item.source
            elif modebits == stat.S_IFBLK:
                tarinfo.type = tarfile.BLKTYPE
                tarinfo.devmajor = os.major(item.rdev)
                tarinfo.devminor = os.minor(item.rdev)
            elif modebits == stat.S_IFCHR:
                tarinfo.type = tarfile.CHRTYPE
                tarinfo.devmajor = os.major(item.rdev)
                tarinfo.devminor = os.minor(item.rdev)
            elif modebits == stat.S_IFIFO:
                tarinfo.type = tarfile.FIFOTYPE
            else:
                self.print_warning(
                    "%s: unsupported file type %o for tar export", remove_surrogates(item.path), modebits
                )
                return None, stream
            return tarinfo, stream

        def item_to_paxheaders(format, item):
            """
            Transform (parts of) a Borg *item* into a pax_headers dict.
            """
            # PAX format
            # ----------
            # When using the PAX (POSIX) format, we can support some things that aren't possible
            # with classic tar formats, including GNU tar, such as:
            # - atime, ctime (DONE)
            # - possibly Linux capabilities, security.* xattrs (TODO)
            # - various additions supported by GNU tar in POSIX mode (TODO)
            #
            # BORG format
            # -----------
            # This is based on PAX, but additionally adds BORG.* pax headers.
            # Additionally to the standard tar / PAX metadata and data, it transfers
            # ALL borg item metadata in a BORG specific way.
            #
            ph = {}
            # note: for mtime this is a bit redundant as it is already done by tarfile module,
            #       but we just do it in our way to be consistent for sure.
            for name in "atime", "ctime", "mtime":
                if hasattr(item, name):
                    ns = getattr(item, name)
                    ph[name] = str(ns / 1e9)
            if format == "BORG":  # BORG format additions
                ph["BORG.item.version"] = "1"
                # BORG.item.meta - just serialize all metadata we have:
                meta_bin = msgpack.packb(item.as_dict())
                meta_text = base64.b64encode(meta_bin).decode()
                ph["BORG.item.meta"] = meta_text
            return ph

        for item in archive.iter_items(filter, preload=True):
            orig_path = item.path
            if strip_components:
                item.path = os.sep.join(orig_path.split(os.sep)[strip_components:])
            tarinfo, stream = item_to_tarinfo(item, orig_path)
            if tarinfo:
                if args.tar_format in ("BORG", "PAX"):
                    tarinfo.pax_headers = item_to_paxheaders(args.tar_format, item)
                if output_list:
                    logging.getLogger("borg.output.list").info(remove_surrogates(orig_path))
                tar.addfile(tarinfo, stream)

        if pi:
            pi.finish()

        # This does not close the fileobj (tarstream) we passed to it -- a side effect of the | mode.
        tar.close()

        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning("Include pattern '%s' never matched.", pattern)
        return self.exit_code

    @with_repository(cache=True, exclusive=True, compatibility=(Manifest.Operation.WRITE,))
    def do_import_tar(self, args, repository, manifest, key, cache):
        """Create a backup archive from a tarball"""
        self.output_filter = args.output_filter
        self.output_list = args.output_list

        filter = get_tar_filter(args.tarfile, decompress=True) if args.tar_filter == "auto" else args.tar_filter

        tarstream = dash_open(args.tarfile, "rb")
        tarstream_close = args.tarfile != "-"

        with create_filter_process(filter, stream=tarstream, stream_close=tarstream_close, inbound=True) as _stream:
            self._import_tar(args, repository, manifest, key, cache, _stream)

        return self.exit_code

    def _import_tar(self, args, repository, manifest, key, cache, tarstream):
        t0 = datetime.utcnow()
        t0_monotonic = time.monotonic()

        archive = Archive(
            repository,
            key,
            manifest,
            args.name,
            cache=cache,
            create=True,
            checkpoint_interval=args.checkpoint_interval,
            progress=args.progress,
            chunker_params=args.chunker_params,
            start=t0,
            start_monotonic=t0_monotonic,
            log_json=args.log_json,
        )
        cp = ChunksProcessor(
            cache=cache,
            key=key,
            add_item=archive.add_item,
            write_checkpoint=archive.write_checkpoint,
            checkpoint_interval=args.checkpoint_interval,
            rechunkify=False,
        )
        tfo = TarfileObjectProcessors(
            cache=cache,
            key=key,
            process_file_chunks=cp.process_file_chunks,
            add_item=archive.add_item,
            chunker_params=args.chunker_params,
            show_progress=args.progress,
            log_json=args.log_json,
            iec=args.iec,
            file_status_printer=self.print_file_status,
        )

        tar = tarfile.open(fileobj=tarstream, mode="r|")

        while True:
            tarinfo = tar.next()
            if not tarinfo:
                break
            if tarinfo.isreg():
                status = tfo.process_file(tarinfo=tarinfo, status="A", type=stat.S_IFREG, tar=tar)
                archive.stats.nfiles += 1
            elif tarinfo.isdir():
                status = tfo.process_dir(tarinfo=tarinfo, status="d", type=stat.S_IFDIR)
            elif tarinfo.issym():
                status = tfo.process_symlink(tarinfo=tarinfo, status="s", type=stat.S_IFLNK)
            elif tarinfo.islnk():
                # tar uses a hardlink model like: the first instance of a hardlink is stored as a regular file,
                # later instances are special entries referencing back to the first instance.
                status = tfo.process_hardlink(tarinfo=tarinfo, status="h", type=stat.S_IFREG)
            elif tarinfo.isblk():
                status = tfo.process_dev(tarinfo=tarinfo, status="b", type=stat.S_IFBLK)
            elif tarinfo.ischr():
                status = tfo.process_dev(tarinfo=tarinfo, status="c", type=stat.S_IFCHR)
            elif tarinfo.isfifo():
                status = tfo.process_fifo(tarinfo=tarinfo, status="f", type=stat.S_IFIFO)
            else:
                status = "E"
                self.print_warning("%s: Unsupported tarinfo type %s", tarinfo.name, tarinfo.type)
            self.print_file_status(status, tarinfo.name)

        # This does not close the fileobj (tarstream) we passed to it -- a side effect of the | mode.
        tar.close()

        if args.progress:
            archive.stats.show_progress(final=True)
        archive.stats += tfo.stats
        archive.save(comment=args.comment, timestamp=args.timestamp)
        args.stats |= args.json
        if args.stats:
            if args.json:
                json_print(basic_json_data(archive.manifest, cache=archive.cache, extra={"archive": archive}))
            else:
                log_multi(str(archive), str(archive.stats), logger=logging.getLogger("borg.output.stats"))

    def build_parser_tar(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog

        export_tar_epilog = process_epilog(
            """
        This command creates a tarball from an archive.

        When giving '-' as the output FILE, Borg will write a tar stream to standard output.

        By default (``--tar-filter=auto``) Borg will detect whether the FILE should be compressed
        based on its file extension and pipe the tarball through an appropriate filter
        before writing it to FILE:

        - .tar.gz or .tgz: gzip
        - .tar.bz2 or .tbz: bzip2
        - .tar.xz or .txz: xz
        - .tar.zstd: zstd
        - .tar.lz4: lz4

        Alternatively, a ``--tar-filter`` program may be explicitly specified. It should
        read the uncompressed tar stream from stdin and write a compressed/filtered
        tar stream to stdout.

        Depending on the ``-tar-format`` option, these formats are created:

        +--------------+---------------------------+----------------------------+
        | --tar-format | Specification             | Metadata                   |
        +--------------+---------------------------+----------------------------+
        | BORG         | BORG specific, like PAX   | all as supported by borg   |
        +--------------+---------------------------+----------------------------+
        | PAX          | POSIX.1-2001 (pax) format | GNU + atime/ctime/mtime ns |
        +--------------+---------------------------+----------------------------+
        | GNU          | GNU tar format            | mtime s, no atime/ctime,   |
        |              |                           | no ACLs/xattrs/bsdflags    |
        +--------------+---------------------------+----------------------------+

        A ``--sparse`` option (as found in borg extract) is not supported.

        By default the entire archive is extracted but a subset of files and directories
        can be selected by passing a list of ``PATHs`` as arguments.
        The file selection can further be restricted by using the ``--exclude`` option.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        ``--progress`` can be slower than no progress display, since it makes one additional
        pass over the archive metadata.
        """
        )
        subparser = subparsers.add_parser(
            "export-tar",
            parents=[common_parser],
            add_help=False,
            description=self.do_export_tar.__doc__,
            epilog=export_tar_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="create tarball from archive",
        )
        subparser.set_defaults(func=self.do_export_tar)
        subparser.add_argument(
            "--tar-filter", dest="tar_filter", default="auto", help="filter program to pipe data through"
        )
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "--tar-format",
            metavar="FMT",
            dest="tar_format",
            default="GNU",
            choices=("BORG", "PAX", "GNU"),
            help="select tar format: BORG, PAX or GNU",
        )
        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument("tarfile", metavar="FILE", help='output tar file. "-" to write to stdout instead.')
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to extract; patterns are supported"
        )
        define_exclusion_group(subparser, strip_components=True)

        import_tar_epilog = process_epilog(
            """
        This command creates a backup archive from a tarball.

        When giving '-' as path, Borg will read a tar stream from standard input.

        By default (--tar-filter=auto) Borg will detect whether the file is compressed
        based on its file extension and pipe the file through an appropriate filter:

        - .tar.gz or .tgz: gzip -d
        - .tar.bz2 or .tbz: bzip2 -d
        - .tar.xz or .txz: xz -d
        - .tar.zstd: zstd -d
        - .tar.lz4: lz4 -d

        Alternatively, a --tar-filter program may be explicitly specified. It should
        read compressed data from stdin and output an uncompressed tar stream on
        stdout.

        Most documentation of borg create applies. Note that this command does not
        support excluding files.

        A ``--sparse`` option (as found in borg create) is not supported.

        About tar formats and metadata conservation or loss, please see ``borg export-tar``.

        import-tar reads these tar formats:

        - BORG: borg specific (PAX-based)
        - PAX: POSIX.1-2001
        - GNU: GNU tar
        - POSIX.1-1988 (ustar)
        - UNIX V7 tar
        - SunOS tar with extended attributes

        """
        )
        subparser = subparsers.add_parser(
            "import-tar",
            parents=[common_parser],
            add_help=False,
            description=self.do_import_tar.__doc__,
            epilog=import_tar_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help=self.do_import_tar.__doc__,
        )
        subparser.set_defaults(func=self.do_import_tar)
        subparser.add_argument(
            "--tar-filter",
            dest="tar_filter",
            default="auto",
            action=Highlander,
            help="filter program to pipe data through",
        )
        subparser.add_argument(
            "-s",
            "--stats",
            dest="stats",
            action="store_true",
            default=False,
            help="print statistics for the created archive",
        )
        subparser.add_argument(
            "--list",
            dest="output_list",
            action="store_true",
            default=False,
            help="output verbose list of items (files, dirs, ...)",
        )
        subparser.add_argument(
            "--filter",
            dest="output_filter",
            metavar="STATUSCHARS",
            action=Highlander,
            help="only display items with the given status characters",
        )
        subparser.add_argument("--json", action="store_true", help="output stats as JSON (implies --stats)")

        archive_group = subparser.add_argument_group("Archive options")
        archive_group.add_argument(
            "--comment", dest="comment", metavar="COMMENT", default="", help="add a comment text to the archive"
        )
        archive_group.add_argument(
            "--timestamp",
            dest="timestamp",
            type=timestamp,
            default=None,
            metavar="TIMESTAMP",
            help="manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). "
            "alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "-c",
            "--checkpoint-interval",
            dest="checkpoint_interval",
            type=int,
            default=1800,
            metavar="SECONDS",
            help="write checkpoint every SECONDS seconds (Default: 1800)",
        )
        archive_group.add_argument(
            "--chunker-params",
            dest="chunker_params",
            action=Highlander,
            type=ChunkerParams,
            default=CHUNKER_PARAMS,
            metavar="PARAMS",
            help="specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, HASH_WINDOW_SIZE). default: %s,%d,%d,%d,%d" % CHUNKER_PARAMS,
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )

        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument("tarfile", metavar="TARFILE", help='input tar file. "-" to read from stdin instead.')
