import os
import unittest
from binascii import unhexlify, b2a_base64, a2b_base64

import pytest

from ...constants import *  # NOQA
from ...crypto.key import AESOCBRepoKey, AESOCBKeyfileKey, CHPOKeyfileKey, Passphrase
from ...crypto.keymanager import RepoIdMismatch, NotABorgKeyFile
from ...helpers import EXIT_ERROR
from ...helpers import bin_to_hex
from ...helpers import msgpack
from ...repository import Repository
from .. import environment_variable
from .. import key
from . import (
    ArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    RemoteArchiverTestCaseBase,
    RK_ENCRYPTION,
    KF_ENCRYPTION,
    BORG_EXES,
)


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_change_passphrase(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"
        # here we have both BORG_PASSPHRASE and BORG_NEW_PASSPHRASE set:
        self.cmd(f"--repo={self.repository_location}", "key", "change-passphrase")
        os.environ["BORG_PASSPHRASE"] = "newpassphrase"
        self.cmd(f"--repo={self.repository_location}", "rlist")

    def test_change_location_to_keyfile(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(repokey" in log
        self.cmd(f"--repo={self.repository_location}", "key", "change-location", "keyfile")
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(key file" in log

    def test_change_location_to_b2keyfile(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=repokey-blake2-aes-ocb")
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(repokey BLAKE2b" in log
        self.cmd(f"--repo={self.repository_location}", "key", "change-location", "keyfile")
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(key file BLAKE2b" in log

    def test_change_location_to_repokey(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(key file" in log
        self.cmd(f"--repo={self.repository_location}", "key", "change-location", "repokey")
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(repokey" in log

    def test_change_location_to_b2repokey(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=keyfile-blake2-aes-ocb")
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(key file BLAKE2b" in log
        self.cmd(f"--repo={self.repository_location}", "key", "change-location", "repokey")
        log = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "(repokey BLAKE2b" in log

    def test_key_export_keyfile(self):
        export_file = self.output_path + "/exported"
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)
        repo_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "key", "export", export_file)

        with open(export_file) as fd:
            export_contents = fd.read()

        assert export_contents.startswith("BORG_KEY " + bin_to_hex(repo_id) + "\n")

        key_file = self.keys_path + "/" + os.listdir(self.keys_path)[0]

        with open(key_file) as fd:
            key_contents = fd.read()

        assert key_contents == export_contents

        os.unlink(key_file)

        self.cmd(f"--repo={self.repository_location}", "key", "import", export_file)

        with open(key_file) as fd:
            key_contents2 = fd.read()

        assert key_contents2 == key_contents

    def test_key_import_keyfile_with_borg_key_file(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)

        exported_key_file = os.path.join(self.output_path, "exported")
        self.cmd(f"--repo={self.repository_location}", "key", "export", exported_key_file)

        key_file = os.path.join(self.keys_path, os.listdir(self.keys_path)[0])
        with open(key_file) as fd:
            key_contents = fd.read()
        os.unlink(key_file)

        imported_key_file = os.path.join(self.output_path, "imported")
        with environment_variable(BORG_KEY_FILE=imported_key_file):
            self.cmd(f"--repo={self.repository_location}", "key", "import", exported_key_file)
        assert not os.path.isfile(key_file), '"borg key import" should respect BORG_KEY_FILE'

        with open(imported_key_file) as fd:
            imported_key_contents = fd.read()
        assert imported_key_contents == key_contents

    def test_key_export_repokey(self):
        export_file = self.output_path + "/exported"
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repo_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "key", "export", export_file)

        with open(export_file) as fd:
            export_contents = fd.read()

        assert export_contents.startswith("BORG_KEY " + bin_to_hex(repo_id) + "\n")

        with Repository(self.repository_path) as repository:
            repo_key = AESOCBRepoKey(repository)
            repo_key.load(None, Passphrase.env_passphrase())

        backup_key = AESOCBKeyfileKey(key.TestKey.MockRepository())
        backup_key.load(export_file, Passphrase.env_passphrase())

        assert repo_key.crypt_key == backup_key.crypt_key

        with Repository(self.repository_path) as repository:
            repository.save_key(b"")

        self.cmd(f"--repo={self.repository_location}", "key", "import", export_file)

        with Repository(self.repository_path) as repository:
            repo_key2 = AESOCBRepoKey(repository)
            repo_key2.load(None, Passphrase.env_passphrase())

        assert repo_key2.crypt_key == repo_key2.crypt_key

    def test_key_export_qr(self):
        export_file = self.output_path + "/exported.html"
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repo_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "key", "export", "--qr-html", export_file)

        with open(export_file, encoding="utf-8") as fd:
            export_contents = fd.read()

        assert bin_to_hex(repo_id) in export_contents
        assert export_contents.startswith("<!doctype html>")
        assert export_contents.endswith("</html>\n")

    def test_key_export_directory(self):
        export_directory = self.output_path + "/exported"
        os.mkdir(export_directory)

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

        self.cmd(f"--repo={self.repository_location}", "key", "export", export_directory, exit_code=EXIT_ERROR)

    def test_key_import_errors(self):
        export_file = self.output_path + "/exported"
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)

        self.cmd(f"--repo={self.repository_location}", "key", "import", export_file, exit_code=EXIT_ERROR)

        with open(export_file, "w") as fd:
            fd.write("something not a key\n")

        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "key", "import", export_file, exit_code=2)
        else:
            with pytest.raises(NotABorgKeyFile):
                self.cmd(f"--repo={self.repository_location}", "key", "import", export_file)

        with open(export_file, "w") as fd:
            fd.write("BORG_KEY a0a0a0\n")

        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "key", "import", export_file, exit_code=2)
        else:
            with pytest.raises(RepoIdMismatch):
                self.cmd(f"--repo={self.repository_location}", "key", "import", export_file)

    def test_key_export_paperkey(self):
        repo_id = "e294423506da4e1ea76e8dcdf1a3919624ae3ae496fddf905610c351d3f09239"

        export_file = self.output_path + "/exported"
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)
        self._set_repository_id(self.repository_path, unhexlify(repo_id))

        key_file = self.keys_path + "/" + os.listdir(self.keys_path)[0]

        with open(key_file, "w") as fd:
            fd.write(CHPOKeyfileKey.FILE_ID + " " + repo_id + "\n")
            fd.write(b2a_base64(b"abcdefghijklmnopqrstu").decode())

        self.cmd(f"--repo={self.repository_location}", "key", "export", "--paper", export_file)

        with open(export_file) as fd:
            export_contents = fd.read()

        assert (
            export_contents
            == """To restore key use borg key import --paper /path/to/repo

BORG PAPER KEY v1
id: 2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02
 1: 616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d
 2: 737475 - 88
"""
        )

    def test_key_import_paperkey(self):
        repo_id = "e294423506da4e1ea76e8dcdf1a3919624ae3ae496fddf905610c351d3f09239"
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)
        self._set_repository_id(self.repository_path, unhexlify(repo_id))

        key_file = self.keys_path + "/" + os.listdir(self.keys_path)[0]
        with open(key_file, "w") as fd:
            fd.write(AESOCBKeyfileKey.FILE_ID + " " + repo_id + "\n")
            fd.write(b2a_base64(b"abcdefghijklmnopqrstu").decode())

        typed_input = (
            b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41  02\n"  # Forgot to type "-"
            b"2 / e29442 3506da 4e1ea7  25f62a 5a3d41 - 02\n"  # Forgot to type second "/"
            b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d42 - 02\n"  # Typo (..42 not ..41)
            b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n"  # Correct! Congratulations
            b"616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d\n"
            b"\n\n"  # Abort [yN] => N
            b"737475 88\n"  # missing "-"
            b"73747i - 88\n"  # typo
            b"73747 - 88\n"  # missing nibble
            b"73 74 75  -  89\n"  # line checksum mismatch
            b"00a1 - 88\n"  # line hash collision - overall hash mismatch, have to start over
            b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n"
            b"616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d\n"
            b"73 74 75  -  88\n"
        )

        # In case that this has to change, here is a quick way to find a colliding line hash:
        #
        # from hashlib import sha256
        # hash_fn = lambda x: sha256(b'\x00\x02' + x).hexdigest()[:2]
        # for i in range(1000):
        #     if hash_fn(i.to_bytes(2, byteorder='big')) == '88':  # 88 = line hash
        #         print(i.to_bytes(2, 'big'))
        #         break

        self.cmd(f"--repo={self.repository_location}", "key", "import", "--paper", input=typed_input)

        # Test abort paths
        typed_input = b"\ny\n"
        self.cmd(f"--repo={self.repository_location}", "key", "import", "--paper", input=typed_input)
        typed_input = b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n\ny\n"
        self.cmd(f"--repo={self.repository_location}", "key", "import", "--paper", input=typed_input)

    def test_init_defaults_to_argon2(self):
        """https://github.com/borgbackup/borg/issues/747#issuecomment-1076160401"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        with Repository(self.repository_path) as repository:
            key = msgpack.unpackb(a2b_base64(repository.load_key()))
        assert key["algorithm"] == "argon2 chacha20-poly1305"

    def test_change_passphrase_does_not_change_algorithm_argon2(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"

        self.cmd(f"--repo={self.repository_location}", "key", "change-passphrase")

        with Repository(self.repository_path) as repository:
            key = msgpack.unpackb(a2b_base64(repository.load_key()))
            assert key["algorithm"] == "argon2 chacha20-poly1305"

    def test_change_location_does_not_change_algorithm_argon2(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", KF_ENCRYPTION)

        self.cmd(f"--repo={self.repository_location}", "key", "change-location", "repokey")

        with Repository(self.repository_path) as repository:
            key = msgpack.unpackb(a2b_base64(repository.load_key()))
            assert key["algorithm"] == "argon2 chacha20-poly1305"


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
