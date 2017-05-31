
import pytest

from ..crypto.file_integrity import IntegrityCheckedFile, DetachedIntegrityCheckedFile, FileIntegrityError


class TestReadIntegrityFile:
    def test_no_integrity(self, tmpdir):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        assert DetachedIntegrityCheckedFile.read_integrity_file(str(protected_file)) is None

    def test_truncated_integrity(self, tmpdir):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.integrity').write('')
        with pytest.raises(FileIntegrityError):
            DetachedIntegrityCheckedFile.read_integrity_file(str(protected_file))

    def test_unknown_algorithm(self, tmpdir):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.integrity').write('{"algorithm": "HMAC_SERIOUSHASH", "digests": "1234"}')
        assert DetachedIntegrityCheckedFile.read_integrity_file(str(protected_file)) is None

    @pytest.mark.parametrize('json', (
        '{"ALGORITHM": "HMAC_SERIOUSHASH", "digests": "1234"}',
        '[]',
        '1234.5',
        '"A string"',
        'Invalid JSON',
    ))
    def test_malformed(self, tmpdir, json):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.integrity').write(json)
        with pytest.raises(FileIntegrityError):
            DetachedIntegrityCheckedFile.read_integrity_file(str(protected_file))


class TestDetachedIntegrityCheckedFile:
    @pytest.fixture
    def integrity_protected_file(self, tmpdir):
        path = str(tmpdir.join('file'))
        with DetachedIntegrityCheckedFile(path, write=True) as fd:
            fd.write(b'foo and bar')
        return path

    def test_simple(self, tmpdir, integrity_protected_file):
        assert tmpdir.join('file').check(file=True)
        assert tmpdir.join('file.integrity').check(file=True)
        with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
            assert fd.read() == b'foo and bar'

    def test_corrupted_file(self, integrity_protected_file):
        with open(integrity_protected_file, 'ab') as fd:
            fd.write(b' extra data')
        with pytest.raises(FileIntegrityError):
            with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
                assert fd.read() == b'foo and bar extra data'

    def test_corrupted_file_partial_read(self, integrity_protected_file):
        with open(integrity_protected_file, 'ab') as fd:
            fd.write(b' extra data')
        with pytest.raises(FileIntegrityError):
            with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
                data = b'foo and bar'
                assert fd.read(len(data)) == data

    @pytest.mark.parametrize('new_name', (
        'different_file',
        'different_file.different_ext',
    ))
    def test_renamed_file(self, tmpdir, integrity_protected_file, new_name):
        new_path = tmpdir.join(new_name)
        tmpdir.join('file').move(new_path)
        tmpdir.join('file.integrity').move(new_path + '.integrity')
        with pytest.raises(FileIntegrityError):
            with DetachedIntegrityCheckedFile(str(new_path), write=False) as fd:
                assert fd.read() == b'foo and bar'

    def test_moved_file(self, tmpdir, integrity_protected_file):
        new_dir = tmpdir.mkdir('another_directory')
        tmpdir.join('file').move(new_dir.join('file'))
        tmpdir.join('file.integrity').move(new_dir.join('file.integrity'))
        new_path = str(new_dir.join('file'))
        with DetachedIntegrityCheckedFile(new_path, write=False) as fd:
            assert fd.read() == b'foo and bar'

    def test_no_integrity(self, tmpdir, integrity_protected_file):
        tmpdir.join('file.integrity').remove()
        with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
            assert fd.read() == b'foo and bar'


class TestDetachedIntegrityCheckedFileParts:
    @pytest.fixture
    def integrity_protected_file(self, tmpdir):
        path = str(tmpdir.join('file'))
        with DetachedIntegrityCheckedFile(path, write=True) as fd:
            fd.write(b'foo and bar')
            fd.hash_part('foopart')
            fd.write(b' other data')
        return path

    def test_simple(self, integrity_protected_file):
        with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
            data1 = b'foo and bar'
            assert fd.read(len(data1)) == data1
            fd.hash_part('foopart')
            assert fd.read() == b' other data'

    def test_wrong_part_name(self, integrity_protected_file):
        with pytest.raises(FileIntegrityError):
            # Because some hash_part failed, the final digest will fail as well - again - even if we catch
            # the failing hash_part. This is intentional: (1) it makes the code simpler (2) it's a good fail-safe
            # against overly broad exception handling.
            with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
                data1 = b'foo and bar'
                assert fd.read(len(data1)) == data1
                with pytest.raises(FileIntegrityError):
                    # This specific bit raises it directly
                    fd.hash_part('barpart')
                # Still explodes in the end.

    @pytest.mark.parametrize('partial_read', (False, True))
    def test_part_independence(self, integrity_protected_file, partial_read):
        with open(integrity_protected_file, 'ab') as fd:
            fd.write(b'some extra stuff that does not belong')
        with pytest.raises(FileIntegrityError):
            with DetachedIntegrityCheckedFile(integrity_protected_file, write=False) as fd:
                data1 = b'foo and bar'
                try:
                    assert fd.read(len(data1)) == data1
                    fd.hash_part('foopart')
                except FileIntegrityError:
                    assert False, 'This part must not raise, since this part is still valid.'
                if not partial_read:
                    fd.read()
                # But overall it explodes with the final digest. Neat, eh?
