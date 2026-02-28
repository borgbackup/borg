import io

from ...platform import swidth, SyncFile


def test_swidth_ascii():
    assert swidth("borg") == 4


def test_swidth_cjk():
    assert swidth("バックアップ") == 6 * 2


def test_swidth_mixed():
    assert swidth("borgバックアップ") == 4 + 6 * 2


def test_syncfile_seek_tell(tmp_path):
    """SyncFile exposes seek() and tell() from the underlying file object."""
    path = tmp_path / "testfile"
    with SyncFile(path, binary=True) as sf:
        sf.write(b"hello world")
        assert sf.tell() == 11
        sf.seek(0, io.SEEK_SET)
        assert sf.tell() == 0
        sf.seek(0, io.SEEK_END)
        assert sf.tell() == 11
        sf.seek(5, io.SEEK_SET)
        assert sf.tell() == 5
        assert sf.read() == b" world"
    assert path.read_bytes() == b"hello world"


def test_syncfile_close_idempotent(tmp_path):
    """Calling SyncFile.close() twice does not raise."""
    path = tmp_path / "testfile"
    sf = SyncFile(path, binary=True)
    sf.write(b"data")
    sf.close()
    sf.close()  # must not raise
