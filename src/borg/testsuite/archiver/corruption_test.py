import json


from ...constants import *  # NOQA
from . import cmd, create_test_files, RK_ENCRYPTION


def corrupt_archiver(archiver):
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    archiver.cache_path = json.loads(cmd(archiver, "repo-info", "--json"))["cache"].get("path")
