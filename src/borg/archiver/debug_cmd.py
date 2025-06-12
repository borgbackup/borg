import argparse
import functools
import json
import textwrap

from ..archive import Archive
from ..compress import CompressionSpec
from ..constants import *  # NOQA
from ..helpers import msgpack
from ..helpers import sysinfo
from ..helpers import bin_to_hex, hex_to_bin, prepare_dump_dict
from ..helpers import dash_open
from ..helpers import StableDict
from ..helpers import archivename_validator
from ..helpers import CommandError, RTError
from ..manifest import Manifest
from ..platform import get_process_id
from ..repository import Repository, LIST_SCAN_LIMIT, repo_lister
from ..repoobj import RepoObj

from ._common import with_repository, Highlander
from ._common import process_epilog


class DebugMixIn:
    def do_debug_info(self, args):
        """display system information for debugging / bug reports"""
        print(sysinfo())
        print("Process ID:", get_process_id())

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_dump_archive_items(self, args, repository, manifest):
        """dump (decrypted, decompressed) archive items metadata (not: data)"""
        repo_objs = manifest.repo_objs
        archive_info = manifest.archives.get_one([args.name])
        archive = Archive(manifest, archive_info.id)
        for i, item_id in enumerate(archive.metadata.items):
            _, data = repo_objs.parse(item_id, repository.get(item_id), ro_type=ROBJ_ARCHIVE_STREAM)
            filename = "%06d_%s.items" % (i, bin_to_hex(item_id))
            print("Dumping", filename)
            with open(filename, "wb") as fd:
                fd.write(data)
        print("Done.")

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_dump_archive(self, args, repository, manifest):
        """dump decoded archive metadata (not: data)"""
        archive_info = manifest.archives.get_one([args.name])
        repo_objs = manifest.repo_objs
        try:
            archive_meta_orig = manifest.archives.get_by_id(archive_info.id, raw=True)
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

            archive_id = archive_meta_orig["id"]
            _, data = repo_objs.parse(archive_id, repository.get(archive_id), ro_type=ROBJ_ARCHIVE_META)
            archive_org_dict = msgpack.unpackb(data, object_hook=StableDict)

            fd.write('    "_meta":\n')
            fd.write(do_indent(prepare_dump_dict(archive_org_dict)))
            fd.write(",\n")
            fd.write('    "_items": [\n')

            unpacker = msgpack.Unpacker(use_list=False, object_hook=StableDict)
            first = True
            items = []
            for chunk_id in archive_org_dict["item_ptrs"]:
                _, data = repo_objs.parse(chunk_id, repository.get(chunk_id), ro_type=ROBJ_ARCHIVE_CHUNKIDS)
                items.extend(msgpack.unpackb(data))
            for item_id in items:
                _, data = repo_objs.parse(item_id, repository.get(item_id), ro_type=ROBJ_ARCHIVE_STREAM)
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

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_dump_manifest(self, args, repository, manifest):
        """dump decoded repository manifest"""
        repo_objs = manifest.repo_objs
        cdata = repository.get_manifest()
        _, data = repo_objs.parse(manifest.MANIFEST_ID, cdata, ro_type=ROBJ_MANIFEST)

        meta = prepare_dump_dict(msgpack.unpackb(data, object_hook=StableDict))

        with dash_open(args.path, "w") as fd:
            json.dump(meta, fd, indent=4)

    @with_repository(manifest=False)
    def do_debug_dump_repo_objs(self, args, repository):
        """dump (decrypted, decompressed) repo objects"""
        from ..crypto.key import key_factory

        def decrypt_dump(id, cdata):
            if cdata is not None:
                _, data = repo_objs.parse(id, cdata, ro_type=ROBJ_DONTCARE)
            else:
                _, data = {}, b""
            filename = f"{bin_to_hex(id)}.obj"
            print("Dumping", filename)
            with open(filename, "wb") as fd:
                fd.write(data)

        # set up the key without depending on a manifest obj
        result = repository.list(limit=1, marker=None)
        id, _ = result[0]
        cdata = repository.get(id)
        key = key_factory(repository, cdata)
        repo_objs = RepoObj(key)
        for id, stored_size in repo_lister(repository, limit=LIST_SCAN_LIMIT):
            cdata = repository.get(id)
            decrypt_dump(id, cdata)
        print("Done.")

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
                wanted = hex_to_bin(wanted[4:])
            elif wanted.startswith("str:"):
                wanted = wanted[4:].encode()
            else:
                raise ValueError("unsupported search term")
        except (ValueError, UnicodeEncodeError):
            wanted = None
        if not wanted:
            raise CommandError("search term needs to be hex:123abc or str:foobar style")

        from ..crypto.key import key_factory

        # set up the key without depending on a manifest obj
        result = repository.list(limit=1, marker=None)
        id, _ = result[0]
        cdata = repository.get(id)
        key = key_factory(repository, cdata)
        repo_objs = RepoObj(key)

        last_data = b""
        last_id = None
        i = 0
        for id, stored_size in repo_lister(repository, limit=LIST_SCAN_LIMIT):
            cdata = repository.get(id)
            _, data = repo_objs.parse(id, cdata, ro_type=ROBJ_DONTCARE)

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

    @with_repository(manifest=False)
    def do_debug_get_obj(self, args, repository):
        """get object contents from the repository and write it into file"""
        hex_id = args.id
        try:
            id = hex_to_bin(hex_id, length=32)
        except ValueError as err:
            raise CommandError(f"object id {hex_id} is invalid [{str(err)}].")
        try:
            data = repository.get(id)
        except Repository.ObjectNotFound:
            raise RTError("object %s not found." % hex_id)
        with open(args.path, "wb") as f:
            f.write(data)
        print("object %s fetched." % hex_id)

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_id_hash(self, args, repository, manifest):
        """compute id-hash for file contents"""
        with open(args.path, "rb") as f:
            data = f.read()
        key = manifest.key
        id = key.id_hash(data)
        print(id.hex())

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_parse_obj(self, args, repository, manifest):
        """parse borg object file into meta dict and data (decrypting, decompressing)"""

        # get the object from id
        hex_id = args.id
        try:
            id = hex_to_bin(hex_id, length=32)
        except ValueError as err:
            raise CommandError(f"object id {hex_id} is invalid [{str(err)}].")

        with open(args.object_path, "rb") as f:
            cdata = f.read()

        repo_objs = manifest.repo_objs
        meta, data = repo_objs.parse(id=id, cdata=cdata, ro_type=ROBJ_DONTCARE)

        with open(args.json_path, "w") as f:
            json.dump(meta, f)

        with open(args.binary_path, "wb") as f:
            f.write(data)

    @with_repository(compatibility=Manifest.NO_OPERATION_CHECK)
    def do_debug_format_obj(self, args, repository, manifest):
        """format file and metadata into borg object file"""

        # get the object from id
        hex_id = args.id
        try:
            id = hex_to_bin(hex_id, length=32)
        except ValueError as err:
            raise CommandError(f"object id {hex_id} is invalid [{str(err)}].")

        with open(args.binary_path, "rb") as f:
            data = f.read()

        with open(args.json_path) as f:
            meta = json.load(f)

        repo_objs = manifest.repo_objs
        # TODO: support misc repo object types other than ROBJ_FILE_STREAM
        data_encrypted = repo_objs.format(id=id, meta=meta, data=data, ro_type=ROBJ_FILE_STREAM)

        with open(args.object_path, "wb") as f:
            f.write(data_encrypted)

    @with_repository(manifest=False)
    def do_debug_put_obj(self, args, repository):
        """put file contents into the repository"""
        with open(args.path, "rb") as f:
            data = f.read()
        hex_id = args.id
        try:
            id = hex_to_bin(hex_id, length=32)
        except ValueError as err:
            raise CommandError(f"object id {hex_id} is invalid [{str(err)}].")

        repository.put(id, data)
        print("object %s put." % hex_id)

    @with_repository(manifest=False, exclusive=True)
    def do_debug_delete_obj(self, args, repository):
        """delete the objects with the given IDs from the repo"""
        for hex_id in args.ids:
            try:
                id = hex_to_bin(hex_id, length=32)
            except ValueError:
                print("object id %s is invalid." % hex_id)
            else:
                try:
                    repository.delete(id)
                    print("object %s deleted." % hex_id)
                except Repository.ObjectNotFound:
                    print("object %s not found." % hex_id)
        print("Done.")

    def do_debug_convert_profile(self, args):
        """convert Borg profile to Python profile"""
        import marshal

        with open(args.output, "wb") as wfd, open(args.input, "rb") as rfd:
            marshal.dump(msgpack.unpack(rfd, use_list=False, raw=False), wfd)

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
        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")

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
        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
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
            action=Highlander,
            help="term to search the repo for, either 0x1234abcd hex term or a string",
        )
        debug_id_hash_epilog = process_epilog(
            """
                This command computes the id-hash for some file content.
                """
        )
        subparser = debug_parsers.add_parser(
            "id-hash",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_id_hash.__doc__,
            epilog=debug_id_hash_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="compute id-hash for some file content (debug)",
        )
        subparser.set_defaults(func=self.do_debug_id_hash)
        subparser.add_argument(
            "path", metavar="PATH", type=str, help="content for which the id-hash shall get computed"
        )

        # parse_obj
        debug_parse_obj_epilog = process_epilog(
            """
                This command parses the object file into metadata (as json) and uncompressed data.
                """
        )
        subparser = debug_parsers.add_parser(
            "parse-obj",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_parse_obj.__doc__,
            epilog=debug_parse_obj_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="parse borg object file into meta dict and data",
        )
        subparser.set_defaults(func=self.do_debug_parse_obj)
        subparser.add_argument("id", metavar="ID", type=str, help="hex object ID to get from the repo")
        subparser.add_argument(
            "object_path", metavar="OBJECT_PATH", type=str, help="path of the object file to parse data from"
        )
        subparser.add_argument(
            "binary_path", metavar="BINARY_PATH", type=str, help="path of the file to write uncompressed data into"
        )
        subparser.add_argument(
            "json_path", metavar="JSON_PATH", type=str, help="path of the json file to write metadata into"
        )

        # format_obj
        debug_format_obj_epilog = process_epilog(
            """
                This command formats the file and metadata into objectfile.
                """
        )
        subparser = debug_parsers.add_parser(
            "format-obj",
            parents=[common_parser],
            add_help=False,
            description=self.do_debug_format_obj.__doc__,
            epilog=debug_format_obj_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="format file and metadata into borg objectfile",
        )
        subparser.set_defaults(func=self.do_debug_format_obj)
        subparser.add_argument("id", metavar="ID", type=str, help="hex object ID to get from the repo")
        subparser.add_argument(
            "binary_path", metavar="BINARY_PATH", type=str, help="path of the file to convert into objectfile"
        )
        subparser.add_argument(
            "json_path", metavar="JSON_PATH", type=str, help="path of the json file to read metadata from"
        )
        subparser.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            action=Highlander,
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )
        subparser.add_argument(
            "object_path",
            metavar="OBJECT_PATH",
            type=str,
            help="path of the objectfile to write compressed encrypted data into",
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
        This command puts an object into the repository.
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
        subparser.add_argument("id", metavar="ID", type=str, help="hex object ID to put into the repo")
        subparser.add_argument("path", metavar="PATH", type=str, help="file to read and create object from")

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
        subparser.add_argument("input", metavar="INPUT", type=str, help="Borg profile")
        subparser.add_argument("output", metavar="OUTPUT", type=str, help="Output file")
