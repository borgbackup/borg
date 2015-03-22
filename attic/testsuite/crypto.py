from binascii import hexlify
from attic.testsuite import AtticTestCase
from attic.crypto import pbkdf2_sha256, get_random_bytes, AES, AES_GCM_MODE, AES_CTR_MODE, \
    bytes_to_long, bytes_to_int, long_to_bytes


class CryptoTestCase(AtticTestCase):

    def test_bytes_to_int(self):
        self.assert_equal(bytes_to_int(b'\0\0\0\1'), 1)

    def test_bytes_to_long(self):
        self.assert_equal(bytes_to_long(b'\0\0\0\0\0\0\0\1'), 1)
        self.assert_equal(long_to_bytes(1), b'\0\0\0\0\0\0\0\1')

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
        self.assert_equal(hexlify(mac), b'c98aa10eb6b7031bcc2160878d9438fb00000000000000000000000000000000')
        self.assert_equal(hexlify(cdata), b'841bcce405df769d22ee9f7f012edf5dc7fb2594d924c7400ffd050f2741')
        # decrypt (correct mac/cdata)
        aes = AES(mode=AES_GCM_MODE, is_encrypt=False, key=key, iv=iv)
        pdata = aes.check_mac_and_decrypt(mac, cdata)
        self.assert_equal(data, pdata)
        # decrypt (incorrect mac/cdata)
        aes = AES(mode=AES_GCM_MODE, is_encrypt=False, key=key, iv=iv)
        cdata = b'x' + cdata[1:]  # corrupt cdata
        self.assertRaises(Exception, aes.check_mac_and_decrypt, mac, cdata)
