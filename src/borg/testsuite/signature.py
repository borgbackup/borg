
import pytest

from ..signature import SignedFile, SignatureError


class TestReadSignatures:
    def test_no_signature(self, tmpdir):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        assert not SignedFile.read_signatures(str(protected_file), None)

    def test_truncated_signature(self, tmpdir):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.signature').write('')
        with pytest.raises(SignatureError):
            SignedFile.read_signatures(str(protected_file), None)

    def test_unknown_algorithm(self, tmpdir):
        class SomeSigner:
            NAME = 'HMAC_FOOHASH9000'
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.signature').write('{"algorithm": "HMAC_SERIOUSHASH", "signature": "1234"}')
        assert not SignedFile.read_signatures(str(protected_file), SomeSigner())

    @pytest.mark.parametrize('json', (
        '{"ALGORITHM": "HMAC_SERIOUSHASH", "signature": "1234"}',
        '[]',
        '1234.5',
        '"A string"',
        'Invalid JSON',
    ))
    def test_malformed(self, tmpdir, json):
        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.signature').write(json)
        with pytest.raises(SignatureError):
            SignedFile.read_signatures(str(protected_file), None)

    def test_valid(self, tmpdir):
        class SomeSigner:
            NAME = 'HMAC_FOO1'

        protected_file = tmpdir.join('file')
        protected_file.write('1234')
        tmpdir.join('file.signature').write('{"algorithm": "HMAC_FOO1", "signatures": {"final": "1234"}}')
        assert SignedFile.read_signatures(str(protected_file), SomeSigner()) == {'final': '1234'}


class TestSignedFile:
    @pytest.fixture
    def key(self):
        return bytes(64)

    @pytest.fixture
    def signed_path(self, tmpdir, key):
        path = str(tmpdir.join('file'))
        with SignedFile(key, path, write=True) as fd:
            fd.write(b'foo and bar')
        return path

    def test_simple(self, tmpdir, signed_path, key):
        assert tmpdir.join('file').check(file=True)
        assert tmpdir.join('file.signature').check(file=True)
        with SignedFile(key, signed_path, write=False) as fd:
            assert fd.read() == b'foo and bar'

    def test_corrupted_file(self, signed_path, key):
        with open(signed_path, 'ab') as fd:
            fd.write(b' extra data')
        with pytest.raises(SignatureError):
            with SignedFile(key, signed_path, write=False) as fd:
                assert fd.read() == b'foo and bar extra data'

    def test_corrupted_file_partial_read(self, signed_path, key):
        with open(signed_path, 'ab') as fd:
            fd.write(b' extra data')
        with pytest.raises(SignatureError):
            with SignedFile(key, signed_path, write=False) as fd:
                data = b'foo and bar'
                assert fd.read(len(data)) == data

    @pytest.mark.parametrize('new_name', (
        'different_file',
        'different_file.different_ext',
    ))
    def test_renamed_file(self, tmpdir, signed_path, key, new_name):
        new_path = tmpdir.join(new_name)
        tmpdir.join('file').move(new_path)
        tmpdir.join('file.signature').move(new_path + '.signature')
        with pytest.raises(SignatureError):
            with SignedFile(key, str(new_path), write=False) as fd:
                assert fd.read() == b'foo and bar'

    def test_moved_file(self, tmpdir, signed_path, key):
        new_dir = tmpdir.mkdir('another_directory')
        tmpdir.join('file').move(new_dir.join('file'))
        tmpdir.join('file.signature').move(new_dir.join('file.signature'))
        new_path = str(new_dir.join('file'))
        with SignedFile(key, new_path, write=False) as fd:
            assert fd.read() == b'foo and bar'

    def test_wrong_key(self, signed_path, key):
        with pytest.raises(SignatureError):
            with SignedFile(key + b'abba', signed_path, write=False) as fd:
                assert fd.read() == b'foo and bar'

    def test_no_signature(self, tmpdir, signed_path, key):
        tmpdir.join('file.signature').remove()
        with SignedFile(key + b'abba', signed_path, write=False) as fd:
            assert fd.read() == b'foo and bar'


class TestSignedFileParts:
    @pytest.fixture
    def key(self):
        return bytes(64)

    @pytest.fixture
    def signed_path(self, tmpdir, key):
        path = str(tmpdir.join('file'))
        with SignedFile(key, path, write=True) as fd:
            fd.write(b'foo and bar')
            fd.sign_part('foopart')
            fd.write(b' other data')
        return path

    def test_simple(self, tmpdir, signed_path, key):
        with SignedFile(key, signed_path, write=False) as fd:
            data1 = b'foo and bar'
            assert fd.read(len(data1)) == data1
            fd.sign_part('foopart')
            assert fd.read() == b' other data'

    def test_wrong_part_name(self, signed_path, key):
        with pytest.raises(SignatureError):
            # Because some sign_part failed, the final signing will fail as well - again - even if we catch
            # the failing sign_part. This is intentional: (1) it makes the code simpler (2) it's a good fail-safe
            # against overly broad exception handling.
            with SignedFile(key, signed_path, write=False) as fd:
                data1 = b'foo and bar'
                assert fd.read(len(data1)) == data1
                with pytest.raises(SignatureError):
                    # This specific bit raises it directly
                    fd.sign_part('barpart')

    @pytest.mark.parametrize('partial_read', (False, True))
    def test_part_independence(self, signed_path, key, partial_read):
        with open(signed_path, 'ab') as fd:
            fd.write(b'some extra stuff that does not belong')
        with pytest.raises(SignatureError):
            with SignedFile(key, signed_path, write=False) as fd:
                data1 = b'foo and bar'
                try:
                    assert fd.read(len(data1)) == data1
                    fd.sign_part('foopart')
                except:
                    assert False, 'This part must not raise, since this part is still valid.'
                if not partial_read:
                    fd.read()
                # But overall it explodes with the final signature. Neat, eh?
