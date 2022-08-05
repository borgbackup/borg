import argparse
from binascii import unhexlify, hexlify
import functools
import hashlib
import json
import textwrap

from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import msgpack
from ..helpers import sysinfo
from ..helpers import bin_to_hex, prepare_dump_dict
from ..helpers import Manifest
from ..helpers import dash_open
from ..helpers import StableDict
from ..helpers import positive_int_validator, NameSpec
from ..platform import get_process_id
from ..repository import Repository, LIST_SCAN_LIMIT, TAG_PUT, TAG_DELETE, TAG_COMMIT

from .common import with_repository
from .common import process_epilog


class DebugMixIn:
    def do_debug_info(self, args):
        """display system information for debugging / bug reports"""
        print(sysinfo())
        print("Process ID:", get_process_id())
        return EXIT_SUCCESS

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_dump_archive_items(self, args, repository, manifest, key):
        """dump (decrypted, decompressed) archive items metadata (not: data)"""
        archive = Archive(repository, key, manifest, args.name, consider_part_files=args.consider_part_files)
        for i, item_id in enumerate(archive.metadata.items):
            data = key.decrypt(item_id, repository.get(item_id))
            filename = "%06d_%s.items" % (i, bin_to_hex(item_id))
            print("Dumping", filename)
            with open(filename, "wb") as fd:
                fd.write(data)
        print("Done.")
        return EXIT_SUCCESS

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_dump_archive(self, args, repository, manifest, key):
        """dump decoded archive metadata (not: data)"""
        try:
            archive_meta_orig = manifest.archives.get_raw_dict()[args.name]
        except KeyError:
            raise Archive.DoesNotExist(args.name)

        indent = 4

        def do_indent(d):
            return textwrap.indent(json.dumps(d, indent=indent), prefix=" " * indent)

        def output(fd):
            # this outputs megabytes of data for a modest sized archive, so some manual streaming json output
            fd.write("{\n")
            fd.write('    "_name": ' + json.dumps(args.name) + ",\n")
            fd.write('    "_manifest_entry":\n')
            fd.write(do_indent(prepare_dump_dict(archive_meta_orig)))
            fd.write(",\n")

            data = key.decrypt(archive_meta_orig["id"], repository.get(archive_meta_orig["id"]))
            archive_org_dict = msgpack.unpackb(data, object_hook=StableDict)

            fd.write('    "_meta":\n')
            fd.write(do_indent(prepare_dump_dict(archive_org_dict)))
            fd.write(",\n")
            fd.write('    "_items": [\n')

            unpacker = msgpack.Unpacker(use_list=False, object_hook=StableDict)
            first = True
            items = []
            for chunk_id in archive_org_dict["item_ptrs"]:
                data = key.decrypt(chunk_id, repository.get(chunk_id))
                items.extend(msgpack.unpackb(data))
            for item_id in items:
                data = key.decrypt(item_id, repository.get(item_id))
                unpacker.feed(data)
                for item in unpacker:
                    item = prepare_dump_dict(item)
                    if first:
                        first = False
                    else:
                        fd.write(",\n")
                    fd.write(do_indent(item))

            fd.write("\n")
            fd.write("    ]\n}\n")

        with dash_open(args.path, "w") as fd:
            output(fd)
        return EXIT_SUCCESS

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_dump_manifest(self, args, repository, manifest, key):
        """dump decoded repository manifest"""

        data = key.decrypt(manifest.MANIFEST_ID, repository.get(manifest.MANIFEST_ID))

        meta = prepare_dump_dict(msgpack.unpackb(data, object_hook=StableDict))

        with dash_open(args.path, "w") as fd:
            json.dump(meta, fd, indent=4)
        return EXIT_SUCCESS

    @with_repository(manifest=False)
    def do_debug_dump_repo_objs(self, args, repository):
        """dump (decrypted, decompressed) repo objects, repo index MUST be current/correct"""
        from ..crypto.key import key_factory

        def decrypt_dump(i, id, cdata, tag=None, segment=None, offset=None):
            if cdata is not None:
                data = key.decrypt(id, cdata)
            else:
                data = b""
            tag_str = "" if tag is None else "_" + tag
            segment_str = "_" + str(segment) if segment is not None else ""
            offset_str = "_" + str(offset) if offset is not None else ""
            id_str = "_" + bin_to_hex(id) if id is not None else ""
            filename = "%08d%s%s%s%s.obj" % (i, segment_str, offset_str, tag_str, id_str)
            print("Dumping", filename)
            with open(filename, "wb") as fd:
                fd.write(data)

        if args.ghost:
            # dump ghosty stuff from segment files: not yet committed objects, deleted / superseded objects, commit tags

            # set up the key without depending on a manifest obj
            for id, cdata, tag, segment, offset in repository.scan_low_level():
                if tag == TAG_PUT:
                    key = key_factory(repository, cdata)
                    break
            i = 0
            for id, cdata, tag, segment, offset in repository.scan_low_level(segment=args.segment, offset=args.offset):
                if tag == TAG_PUT:
                    decrypt_dump(i, id, cdata, tag="put", segment=segment, offset=offset)
                elif tag == TAG_DELETE:
                    decrypt_dump(i, id, None, tag="del", segment=segment, offset=offset)
                elif tag == TAG_COMMIT:
                    decrypt_dump(i, None, None, tag="commit", segment=segment, offset=offset)
                i += 1
        else:
            # set up the key without depending on a manifest obj
            ids = repository.list(limit=1, marker=None)
            cdata = repository.get(ids[0])
            key = key_factory(repository, cdata)
            marker = None
            i = 0
            while True:
                result = repository.scan(limit=LIST_SCAN_LIMIT, marker=marker)  # must use on-disk order scanning here
                if not result:
                    break
                marker = result[-1]
                for id in result:
                    cdata = repository.get(id)
                    decrypt_dump(i, id, cdata)
                    i += 1
        print("Done.")
        return EXIT_SUCCESS

    @with_repository(manifest=False)
    def do_debug_search_repo_objs(self, args, repository):
        """search for byte sequences in repo objects, repo index MUST be current/correct"""
        context = 32

        def print_finding(info, wanted, data, offset):
            before = data[offset - context : offset]
            after = data[offset + len(wanted) : offset + len(wanted) + context]
            print(
                "{}: {} {} {} == {!r} {!r} {!r}".format(
                    info, before.hex(), wanted.hex(), after.hex(), before, wanted, after
                )
            )

        wanted = args.wanted
        try:
            if wanted.startswith("hex:"):
                wanted = unhexlify(wanted[4:])
            elif wanted.startswith("str:"):
                wanted = wanted[4:].encode()
            else:
                raise ValueError("unsupported search term")
        except (ValueError, UnicodeEncodeError):
            wanted = None
        if not wanted:
            self.print_error("search term needs to be hex:123abc or str:foobar style")
            return EXIT_ERROR

        from ..crypto.key import key_factory

        # set up the key without depending on a manifest obj
        ids = repository.list(limit=1, marker=None)
        cdata = repository.get(ids[0])
        key = key_factory(repository, cdata)

        marker = None
        last_data = b""
        last_id = None
        i = 0
        while True:
            result = repository.scan(limit=LIST_SCAN_LIMIT, marker=marker)  # must use on-disk order scanning here
            if not result:
                break
            marker = result[-1]
            for id in result:
                cdata = repository.get(id)
                data = key.decrypt(id, cdata)

                # try to locate wanted sequence crossing the border of last_data and data
                boundary_data = last_data[-(len(wanted) - 1) :] + data[: len(wanted) - 1]
                if wanted in boundary_data:
                    boundary_data = last_data[-(len(wanted) - 1 + context) :] + data[: len(wanted) - 1 + context]
                    offset = boundary_data.find(wanted)
                    info = "%d %s | %s" % (i, last_id.hex(), id.hex())
                    print_finding(info, wanted, boundary_data, offset)

                # try to locate wanted sequence in data
                count = data.count(wanted)
                if count:
                    offset = data.find(wanted)  # only determine first occurrence's offset
                    info = "%d %s #%d" % (i, id.hex(), count)
                    print_finding(info, wanted, data, offset)

                last_id, last_data = id, data
                i += 1
                if i % 10000 == 0:
                    print("%d objects processed." % i)
        print("Done.")
        return EXIT_SUCCESS

    @with_repository(manifest=False)
    def do_debug_get_obj(self, args, repository):
        """get object contents from the repository and write it into file"""
        hex_id = args.id
        try:
            id = unhexlify(hex_id)
        except ValueError:
            print("object id %s is invalid." % hex_id)
        else:
            try:
                data = repository.get(id)
            except Repository.ObjectNotFound:
                print("object %s not found." % hex_id)
            else:
                with open(args.path, "wb") as f:
                    f.write(data)
                print("object %s fetched." % hex_id)
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True)
    def do_debug_put_obj(self, args, repository):
        """put file(s) contents into the repository"""
        for path in args.paths:
            with open(path, "rb") as f:
                data = f.read()
            h = hashlib.sha256(data)  # XXX hardcoded
            repository.put(h.digest(), data)
            print("object %s put." % h.hexdigest())
        repository.commit(compact=False)
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True)
    def do_debug_delete_obj(self, args, repository):
        """delete the objects with the given IDs from the repo"""
        modified = False
        for hex_id in args.ids:
            try:
                id = unhexlify(hex_id)
            except ValueError:
                print("object id %s is invalid." % hex_id)
            else:
                try:
                    repository.delete(id)
                    modified = True
                    print("object %s deleted." % hex_id)
                except Repository.ObjectNotFound:
                    print("object %s not found." % hex_id)
        if modified:
            repository.commit(compact=False)
        print("Done.")
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True, cache=True, compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_refcount_obj(self, args, repository, manifest, key, cache):
        """display refcounts for the objects with the given IDs"""
        for hex_id in args.ids:
            try:
                id = unhexlify(hex_id)
            except ValueError:
                print("object id %s is invalid." % hex_id)
            else:
                try:
                    refcount = cache.chunks[id][0]
                    print("object %s has %d referrers [info from chunks cache]." % (hex_id, refcount))
                except KeyError:
                    print("object %s not found [info from chunks cache]." % hex_id)
        return EXIT_SUCCESS

    @with_repository(manifest=False, exclusive=True)
    def do_debug_dump_hints(self, args, repository):
        """dump repository hints"""
        if not repository._active_txn:
            repository.prepare_txn(repository.get_transaction_id())
        try:
            hints = dict(
                segments=repository.segments,
                compact=repository.compact,
                storage_quota_use=repository.storage_quota_use,
                shadow_index={hexlify(k).decode(): v for k, v in repository.shadow_index.items()},
            )
            with dash_open(args.path, "w") as fd:
                json.dump(hints, fd, indent=4)
        finally:
            repository.rollback()
        return EXIT_SUCCESS

    def do_debug_convert_profile(self, args):
        """convert Borg profile to Python profile"""
        import marshal

        with args.output, args.input:
            marshal.dump(msgpack.unpack(args.input, use_list=False, raw=False), args.output)
        return EXIT_SUCCESS

    def build_parser_debug(self, subparsers, common_parser, mid_common_parser):

        debug_epilog = process_epilog(
            """
        These commands are not intended for normal use and potentially very
        dangerous if used incorrectly.

        They exist to improve debugging capabilities without direct system access, e.g.
        in case you ever run into some severe malfunction. Use them only if you know
        what you are doing or if a trusted developer tells you what to do."""
        )

        subparser = subparsers.add_parser(
            "debug",
            parents=[mid_common_parser],
            add_help=False,
            description="debugging command (not intended for normal use)",
            epilog=debug_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="debugging command (not intended for normal use)",
        )

        debug_parsers = subparser.add_subparsers(title="required arguments", metavar="<command>")
        subparser.set_defaults(fallback_func=functools.partial(self.do_subcommand_help, subparser))

        debug_info_epilog = process_epilog(
            """
        This command displays some system information that might be useful for bug
        reports and debugging problems. If a traceback happens, this information is
        already appended at the end of the traceback.
        """
        )
        subparser = debug_parsers.add_parser(
            "info",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_info.__doc__,
            epilog=debug_info_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show system infos for debugging / bug reports (debug)",
        )
        subparser.set_defaults(func=self.do_debug_info)

        debug_dump_archive_items_epilog = process_epilog(
            """
        This command dumps raw (but decrypted and decompressed) archive items (only metadata) to files.
        """
        )
        subparser = debug_parsers.add_parser(
            "dump-archive-items",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_dump_archive_items.__doc__,
            epilog=debug_dump_archive_items_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="dump archive items (metadata) (debug)",
        )
        subparser.set_defaults(func=self.do_debug_dump_archive_items)
        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")

        debug_dump_archive_epilog = process_epilog(
            """
        This command dumps all metadata of an archive in a decoded form to a file.
        """
        )
        subparser = debug_parsers.add_parser(
            "dump-archive",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_dump_archive.__doc__,
            epilog=debug_dump_archive_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="dump decoded archive metadata (debug)",
        )
        subparser.set_defaults(func=self.do_debug_dump_archive)
        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument("path", metavar="PATH", type=str, help="file to dump data into")

        debug_dump_manifest_epilog = process_epilog(
            """
        This command dumps manifest metadata of a repository in a decoded form to a file.
        """
        )
        subparser = debug_parsers.add_parser(
            "dump-manifest",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_dump_manifest.__doc__,
            epilog=debug_dump_manifest_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="dump decoded repository metadata (debug)",
        )
        subparser.set_defaults(func=self.do_debug_dump_manifest)
        subparser.add_argument("path", metavar="PATH", type=str, help="file to dump data into")

        debug_dump_repo_objs_epilog = process_epilog(
            """
        This command dumps raw (but decrypted and decompressed) repo objects to files.
        """
        )
        subparser = debug_parsers.add_parser(
            "dump-repo-objs",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_dump_repo_objs.__doc__,
            epilog=debug_dump_repo_objs_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="dump repo objects (debug)",
        )
        subparser.set_defaults(func=self.do_debug_dump_repo_objs)
        subparser.add_argument(
            "--ghost",
            dest="ghost",
            action="store_true",
            help="dump all segment file contents, including deleted/uncommitted objects and commits.",
        )
        subparser.add_argument(
            "--segment",
            metavar="SEG",
            dest="segment",
            default=None,
            type=positive_int_validator,
            help="used together with --ghost: limit processing to given segment.",
        )
        subparser.add_argument(
            "--offset",
            metavar="OFFS",
            dest="offset",
            default=None,
            type=positive_int_validator,
            help="used together with --ghost: limit processing to given offset.",
        )

        debug_search_repo_objs_epilog = process_epilog(
            """
        This command searches raw (but decrypted and decompressed) repo objects for a specific bytes sequence.
        """
        )
        subparser = debug_parsers.add_parser(
            "search-repo-objs",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_search_repo_objs.__doc__,
            epilog=debug_search_repo_objs_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="search repo objects (debug)",
        )
        subparser.set_defaults(func=self.do_debug_search_repo_objs)
        subparser.add_argument(
            "wanted",
            metavar="WANTED",
            type=str,
            help="term to search the repo for, either 0x1234abcd hex term or a string",
        )

        debug_get_obj_epilog = process_epilog(
            """
        This command gets an object from the repository.
        """
        )
        subparser = debug_parsers.add_parser(
            "get-obj",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_get_obj.__doc__,
            epilog=debug_get_obj_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="get object from repository (debug)",
        )
        subparser.set_defaults(func=self.do_debug_get_obj)
        subparser.add_argument("id", metavar="ID", type=str, help="hex object ID to get from the repo")
        subparser.add_argument("path", metavar="PATH", type=str, help="file to write object data into")

        debug_put_obj_epilog = process_epilog(
            """
        This command puts objects into the repository.
        """
        )
        subparser = debug_parsers.add_parser(
            "put-obj",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_put_obj.__doc__,
            epilog=debug_put_obj_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="put object to repository (debug)",
        )
        subparser.set_defaults(func=self.do_debug_put_obj)
        subparser.add_argument(
            "paths", metavar="PATH", nargs="+", type=str, help="file(s) to read and create object(s) from"
        )

        debug_delete_obj_epilog = process_epilog(
            """
        This command deletes objects from the repository.
        """
        )
        subparser = debug_parsers.add_parser(
            "delete-obj",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_delete_obj.__doc__,
            epilog=debug_delete_obj_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="delete object from repository (debug)",
        )
        subparser.set_defaults(func=self.do_debug_delete_obj)
        subparser.add_argument(
            "ids", metavar="IDs", nargs="+", type=str, help="hex object ID(s) to delete from the repo"
        )

        debug_refcount_obj_epilog = process_epilog(
            """
        This command displays the reference count for objects from the repository.
        """
        )
        subparser = debug_parsers.add_parser(
            "refcount-obj",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_refcount_obj.__doc__,
            epilog=debug_refcount_obj_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show refcount for object from repository (debug)",
        )
        subparser.set_defaults(func=self.do_debug_refcount_obj)
        subparser.add_argument("ids", metavar="IDs", nargs="+", type=str, help="hex object ID(s) to show refcounts for")

        debug_dump_hints_epilog = process_epilog(
            """
        This command dumps the repository hints data.
        """
        )
        subparser = debug_parsers.add_parser(
            "dump-hints",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_dump_hints.__doc__,
            epilog=debug_dump_hints_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="dump repo hints (debug)",
        )
        subparser.set_defaults(func=self.do_debug_dump_hints)
        subparser.add_argument("path", metavar="PATH", type=str, help="file to dump data into")

        debug_convert_profile_epilog = process_epilog(
            """
        Convert a Borg profile to a Python cProfile compatible profile.
        """
        )
        subparser = debug_parsers.add_parser(
            "convert-profile",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_convert_profile.__doc__,
            epilog=debug_convert_profile_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="convert Borg profile to Python profile (debug)",
        )
        subparser.set_defaults(func=self.do_debug_convert_profile)
        subparser.add_argument("input", metavar="INPUT", type=argparse.FileType("rb"), help="Borg profile")
        subparser.add_argument("output", metavar="OUTPUT", type=argparse.FileType("wb"), help="Output file")
