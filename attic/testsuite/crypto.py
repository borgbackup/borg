from binascii import hexlify
from attic.testsuite import AtticTestCase
from attic.crypto import pbkdf2_sha256, get_random_bytes, AES, AES_GCM_MODE, AES_CTR_MODE, \
    bytes_to_int, bytes16_to_int, int_to_bytes16, increment_iv


class CryptoTestCase(AtticTestCase):

    def test_bytes_to_int(self):
        self.assert_equal(bytes_to_int(b'\0\0\0\1'), 1)

    def test_bytes16_to_int(self):
        i, b = 1, b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1'
        self.assert_equal(bytes16_to_int(b), i)
        self.assert_equal(int_to_bytes16(i), b)
        i, b = (1 << 64) + 2, b'\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\2'
        self.assert_equal(bytes16_to_int(b), i)
        self.assert_equal(int_to_bytes16(i), b)

    def test_increment_iv(self):
        tests = [
            # iv, amount, iv_expected
            (0, 0, 0),
            (0, 15, 1),
            (0, 16, 1),
            (0, 17, 2),
            (0xffffffffffffffff, 32, 0x10000000000000001),
        ]
        for iv, amount, iv_expected in tests:
            iv = int_to_bytes16(iv)
            iv_expected = int_to_bytes16(iv_expected)
            self.assert_equal(increment_iv(iv, amount), iv_expected)

    def test_pbkdf2_sha256(self):
        self.assert_equal(hexlify(pbkdf2_sha256(b'password', b'salt', 1, 32)),
                          b'120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
        self.assert_equal(hexlify(pbkdf2_sha256(b'password', b'salt', 2, 32)),
                          b'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43')
        self.assert_equal(hexlify(pbkdf2_sha256(b'password', b'salt', 4096, 32)),
                          b'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a')

    def test_get_random_bytes(self):
        bytes = get_random_bytes(10)
        bytes2 = get_random_bytes(10)
        self.assert_equal(len(bytes), 10)
        self.assert_equal(len(bytes2), 10)
        self.assert_not_equal(bytes, bytes2)

    def test_aes_ctr(self):
        key = b'X' * 32
        iv = b'\0' * 16
        data = b'foo' * 10
        # encrypt
        aes = AES(mode=AES_CTR_MODE, is_encrypt=True, key=key, iv=iv)
        _, cdata = aes.compute_mac_and_encrypt(data)
        self.assert_equal(hexlify(cdata), b'c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466')
        # decrypt (correct mac/cdata)
        aes = AES(mode=AES_CTR_MODE, is_encrypt=False, key=key, iv=iv)
        pdata = aes.check_mac_and_decrypt(None, cdata)
        self.assert_equal(data, pdata)

    def test_aes_gcm(self):
        key = b'X' * 32
        iv = b'A' * 16
        data = b'foo' * 10
        # encrypt
        aes = AES(mode=AES_GCM_MODE, is_encrypt=True, key=key, iv=iv)
        mac, cdata = aes.compute_mac_and_encrypt(data)
        self.assert_equal(hexlify(mac), b'c98aa10eb6b7031bcc2160878d9438fb')
        self.assert_equal(hexlify(cdata), b'841bcce405df769d22ee9f7f012edf5dc7fb2594d924c7400ffd050f2741')
        # decrypt (correct mac/cdata)
        aes = AES(mode=AES_GCM_MODE, is_encrypt=False, key=key, iv=iv)
        pdata = aes.check_mac_and_decrypt(mac, cdata)
        self.assert_equal(data, pdata)
        # decrypt (incorrect mac/cdata)
        aes = AES(mode=AES_GCM_MODE, is_encrypt=False, key=key, iv=iv)
        cdata = b'x' + cdata[1:]  # corrupt cdata
        self.assertRaises(Exception, aes.check_mac_and_decrypt, mac, cdata)
