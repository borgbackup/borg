import os
from binascii import hexlify

from ...constants import *  # NOQA
from ...repository import Repository
from ...manifest import Manifest
from ...compress import ZSTD, ZLIB, LZ4, CNONE

from . import ArchiverTestCaseBase, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_rcompress(self):
        def check_compression(ctype, clevel, olevel):
            """check if all the chunks in the repo are compressed/obfuscated like expected"""
            repository = Repository(self.repository_path, exclusive=True)
            with repository:
                manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
                state = None
                while True:
                    ids, state = repository.scan(limit=LIST_SCAN_LIMIT, state=state)
                    if not ids:
                        break
                    for id in ids:
                        chunk = repository.get(id, read_data=True)
                        meta, data = manifest.repo_objs.parse(id, chunk)  # will also decompress according to metadata
                        m_olevel = meta.get("olevel", -1)
                        m_psize = meta.get("psize", -1)
                        print(
                            hexlify(id).decode(),
                            meta["ctype"],
                            meta["clevel"],
                            meta["csize"],
                            meta["size"],
                            m_olevel,
                            m_psize,
                        )
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

        self.create_regular_file("file1", size=1024 * 10)
        self.create_regular_file("file2", contents=os.urandom(1024 * 10))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

        cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 3, -1
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "-C", f"{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 1, -1  # change compressor (and level)
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, -1  # only change level
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, 110  # only change to obfuscated
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"obfuscate,{olevel},{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, 112  # only change obfuscation level
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"obfuscate,{olevel},{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZSTD.name, ZSTD.ID, 3, -1  # change to not obfuscated
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 1, -1
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"auto,{cname},{clevel}")
        check_compression(ctype, clevel, olevel)

        cname, ctype, clevel, olevel = ZLIB.name, ZLIB.ID, 2, 111
        self.cmd(f"--repo={self.repository_location}", "rcompress", "-C", f"obfuscate,{olevel},auto,{cname},{clevel}")
        check_compression(ctype, clevel, olevel)
