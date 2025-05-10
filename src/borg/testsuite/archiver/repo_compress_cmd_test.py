import os

from ...constants import *  # NOQA
from ...repository import Repository, repo_lister
from ...manifest import Manifest
from ...compress import ZSTD, ZLIB, LZ4, CNONE
from ...helpers import bin_to_hex

from . import create_regular_file, cmd, RK_ENCRYPTION


def test_repo_compress(archiver):
    def check_compression(ctype, clevel, olevel):
        """check if all the chunks in the repo are compressed/obfuscated like expected"""
        repository = Repository(archiver.repository_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            for id, _ in repo_lister(repository, limit=LIST_SCAN_LIMIT):
                chunk = repository.get(id, read_data=True)
                meta, data = manifest.repo_objs.parse(
                    id, chunk, ro_type=ROBJ_DONTCARE
                )  # will also decompress according to metadata
                m_olevel = meta.get("olevel", -1)
                m_psize = meta.get("psize", -1)
                print(bin_to_hex(id), meta["ctype"], meta["clevel"], meta["csize"], meta["size"], m_olevel, m_psize)
                # this is not as easy as one thinks due to the DecidingCompressor choosing the smallest of
                # (desired compressed, lz4 compressed, not compressed).
                assert meta["ctype"] in (ctype, LZ4.ID, CNONE.ID)
                assert meta["clevel"] in (clevel, 255)  # LZ4 and CNONE has level 255
                if olevel != -1:  # we expect obfuscation
                    assert "psize" in meta
                    assert m_olevel == olevel
                else:
                    assert "psize" not in meta
                    assert "olevel" not in meta

    create_regular_file(archiver.input_path, "file1", size=1024 * 10)
    create_regular_file(archiver.input_path, "file2", contents=os.urandom(1024 * 10))
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 3, -1
    cmd(archiver, "create", "test", "input", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 1, -1  # change compressor (and level)
    cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, -1  # only change level
    cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, 110  # only change to obfuscated
    cmd(archiver, "repo-compress", "-C", f"obfuscate,{olevel},{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, 112  # only change obfuscation level
    cmd(archiver, "repo-compress", "-C", f"obfuscate,{olevel},{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, -1  # change to not obfuscated
    cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 1, -1
    cmd(archiver, "repo-compress", "-C", f"auto,{cname},{clevel}")
    check_compression(ctype, clevel, olevel)

    cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 2, 111
    cmd(archiver, "repo-compress", "-C", f"obfuscate,{olevel},auto,{cname},{clevel}")
    check_compression(ctype, clevel, olevel)


def test_repo_compress_stats(archiver):
    create_regular_file(archiver.input_path, "file1", size=1024 * 10)
    create_regular_file(archiver.input_path, "file2", contents=os.urandom(1024 * 10))
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    cname, clevel = ZLIB.name, 3
    cmd(archiver, "create", "test", "input", "-C", f"{cname},{clevel}")

    cname, clevel = ZSTD.name, 1  # change compressor (and level)
    output = cmd(archiver, "repo-compress", "-C", f"{cname},{clevel}", "--stats")
    assert "Recompression stats:" in output
