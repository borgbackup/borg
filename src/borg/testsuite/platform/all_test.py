import io
import os
import tempfile

from ...platform import swidth, SyncFile, SaveFile
from ...crypto.file_integrity import IntegrityCheckedFile


def test_swidth_ascii():
    assert swidth("borg") == 4


def test_swidth_cjk():
    assert swidth("バックアップ") == 6 * 2


def test_swidth_mixed():
    assert swidth("borgバックアップ") == 4 + 6 * 2


def test_syncfile_seek_tell():
    """SyncFile exposes seek() and tell() from the underlying file object."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        with SyncFile(path, binary=True) as sf:
            sf.write(b"hello world")
            assert sf.tell() == 11
            sf.seek(0, io.SEEK_SET)
            assert sf.tell() == 0
            sf.seek(0, io.SEEK_END)
            assert sf.tell() == 11
            sf.seek(5, io.SEEK_SET)
            assert sf.tell() == 5


def test_syncfile_close_idempotent():
    """Calling SyncFile.close() twice does not raise."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        sf = SyncFile(path, binary=True)
        sf.write(b"data")
        sf.close()
        sf.close()  # must not raise


def test_savefile_with_integrity_checked_file():
    """SaveFile + IntegrityCheckedFile provides atomic writes with integrity verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        with SaveFile(path, binary=True) as sync_file:
            with IntegrityCheckedFile(path=path, write=True, override_fd=sync_file) as fd:
                fd.write(b"atomic integrity data")
            integrity_data = fd.integrity_data

        assert os.path.exists(path)
        assert integrity_data is not None

        # verify the written data can be read back with integrity check
        with IntegrityCheckedFile(path=path, write=False, integrity_data=integrity_data) as fd:
            assert fd.read() == b"atomic integrity data"
