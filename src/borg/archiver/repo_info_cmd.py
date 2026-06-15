import textwrap

from ._common import with_repository
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, json_print, basic_json_data
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class RepoInfoMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_repo_info(self, args, repository, manifest, cache):
        """Show repository information."""
        key = manifest.key
        info = basic_json_data(manifest, cache=cache, extra={"security_dir": cache.security_manager.dir})

        if args.json:
            json_print(info)
        else:
            encryption = "Encrypted: "
            # storage (keyfile/repokey) is a per-key property now; the crypto suite is described by
            # the two dimensions: cipher / AE algorithm (ENC_NAME) and id hash function (IDHASH_NAME).
            storage = getattr(key, "storage", None)
            mode = {KeyBlobStorage.KEYFILE: "keyfile", KeyBlobStorage.REPO: "repokey"}.get(storage)
            suite = "%s, %s" % (key.ENC_NAME, key.IDHASH_NAME)
            if key.ENC_NAME in ("none", "authenticated"):
                # the "none" and "authenticated" encryptions do not encrypt data; "authenticated"
                # (unlike "none"/plaintext) still has a key stored as a keyfile or repokey, so show
                # that location when there is one.
                encryption += "No (%s, %s)" % (mode, suite) if mode else "No"
            else:
                encryption += "Yes (%s, %s)" % (mode, suite) if mode else "Yes (%s)" % suite
            if storage == KeyBlobStorage.KEYFILE:
                encryption += "\nKey file: %s" % key.find_key()
            info["encryption"] = encryption

            output = (
                textwrap.dedent(
                    """
            Repository ID: {id}
            Location: {location}
            Repository version: {version}
            {encryption}
            Security directory: {security_dir}
            """
                )
                .strip()
                .format(
                    id=bin_to_hex(repository.id),
                    location=repository._location.canonical_path(),
                    version=repository.version,
                    encryption=info["encryption"],
                    security_dir=info["security_dir"],
                )
            )

            if hasattr(info["cache"], "path"):
                output += "\nCache: {cache.path}\n".format(**info)

            print(output)

    def build_parser_repo_info(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_info_epilog = process_epilog(
            """
        This command displays detailed information about the repository.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_repo_info.__doc__, epilog=repo_info_epilog
        )
        subparsers.add_subcommand("repo-info", subparser, help="show repository information")
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
