import os.path

import pytest

from ..crypto import nonces
from ..crypto.nonces import NonceManager
from ..crypto.key import bin_to_hex
from ..helpers import get_security_dir
from ..remote import InvalidRPCMethod


class TestNonceManager:

    class MockRepository:
        class _Location:
            orig = '/some/place'

        _location = _Location()
        id = bytes(32)
        id_str = bin_to_hex(id)

        def get_free_nonce(self):
            return self.next_free

        def commit_nonce_reservation(self, next_unreserved, start_nonce):
            assert start_nonce == self.next_free
            self.next_free = next_unreserved

    class MockOldRepository(MockRepository):
        def get_free_nonce(self):
            raise InvalidRPCMethod("")

        def commit_nonce_reservation(self, next_unreserved, start_nonce):
            pytest.fail("commit_nonce_reservation should never be called on an old repository")

    class MockEncCipher:
        def __init__(self, iv):
            self.iv_set = False  # placeholder, this is never a valid iv
            self.iv = iv

        def reset(self, key, iv):
            assert key is None
            assert iv is not False
            self.iv_set = iv
            self.iv = iv

        def expect_iv_and_advance(self, expected_iv, advance):
            expected_iv = expected_iv.to_bytes(16, byteorder='big')
            iv_set = self.iv_set
            assert iv_set == expected_iv
            self.iv_set = False
            self.iv = advance.to_bytes(16, byteorder='big')

        def expect_no_reset_and_advance(self, advance):
            iv_set = self.iv_set
            assert iv_set is False
            self.iv = advance.to_bytes(16, byteorder='big')

    def setUp(self):
        self.repository = None

    def cache_nonce(self):
        with open(os.path.join(get_security_dir(self.repository.id_str), 'nonce'), "r") as fd:
            return fd.read()

    def set_cache_nonce(self, nonce):
        with open(os.path.join(get_security_dir(self.repository.id_str), 'nonce'), "w") as fd:
            assert fd.write(nonce)

    def test_empty_cache_and_old_server(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x2000)
        self.repository = self.MockOldRepository()
        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2013)

        assert self.cache_nonce() == "0000000000002033"

    def test_empty_cache(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x2000)
        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2013)

        assert self.cache_nonce() == "0000000000002033"

    def test_empty_nonce(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x2000)
        self.repository = self.MockRepository()
        self.repository.next_free = None
        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # enough space in reservation
        manager.ensure_reservation(13)
        enc_cipher.expect_no_reset_and_advance(0x2000 + 19 + 13)
        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # just barely enough space in reservation
        manager.ensure_reservation(19)
        enc_cipher.expect_no_reset_and_advance(0x2000 + 19 + 13 + 19)
        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # no space in reservation
        manager.ensure_reservation(16)
        enc_cipher.expect_no_reset_and_advance(0x2000 + 19 + 13 + 19 + 16)
        assert self.cache_nonce() == "0000000000002063"
        assert self.repository.next_free == 0x2063

        # spans reservation boundary
        manager.ensure_reservation(64)
        enc_cipher.expect_no_reset_and_advance(0x2000 + 19 + 13 + 19 + 16 + 64)
        assert self.cache_nonce() == "00000000000020c3"
        assert self.repository.next_free == 0x20c3

    def test_sync_nonce(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x2000)
        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_server_just_upgraded(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x2000)
        self.repository = self.MockRepository()
        self.repository.next_free = None
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_transaction_abort_no_cache(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x1000)
        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000

        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_transaction_abort_old_server(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x1000)
        self.repository = self.MockOldRepository()
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"

    def test_transaction_abort_on_other_client(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x1000)
        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        self.set_cache_nonce("0000000000001000")

        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_interleaved(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        enc_cipher = self.MockEncCipher(0x2000)
        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, enc_cipher, 0x2000)
        manager.ensure_reservation(19)
        enc_cipher.expect_iv_and_advance(0x2000, 0x2000 + 19)

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # somehow the clients unlocks, another client reserves and this client relocks
        self.repository.next_free = 0x4000

        # enough space in reservation
        manager.ensure_reservation(12)
        enc_cipher.expect_no_reset_and_advance(0x2000 + 19 + 12)
        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x4000

        # spans reservation boundary
        manager.ensure_reservation(21)
        enc_cipher.expect_iv_and_advance(0x4000, 0x4000 + 21)
        assert self.cache_nonce() == "0000000000004035"
        assert self.repository.next_free == 0x4035
